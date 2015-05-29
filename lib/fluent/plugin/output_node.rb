# require 'msgpack'
# require 'socket'
# require 'openssl'
# require 'digest'
# require 'resolve/hostname'

require_relative 'openssl_util'

class Fluent::SecureForwardOutput::Node
  attr_accessor :host, :port, :hostlabel, :shared_key, :username, :password, :standby

  attr_accessor :authentication, :keepalive
  attr_accessor :socket, :sslsession, :unpacker, :shared_key_salt, :state

  attr_accessor :first_session, :detach

  attr_reader :expire

  def initialize(sender, conf)
    @sender = sender
    @shared_key = conf.shared_key || sender.shared_key

    @host = conf.host
    @port = conf.port
    @hostlabel = conf.hostlabel || conf.host
    @username = conf.username
    @password = conf.password
    @standby = conf.standby

    @keepalive = sender.keepalive

    @authentication = nil

    @writing = false

    @expire = nil
    @first_session = false
    @detach = false

    @socket = nil
    @sslsession = nil
    @unpacker = MessagePack::Unpacker.new

    @shared_key_salt = generate_salt
    @state = :helo
    @thread = nil
  end

  def log
    @sender.log
  end

  def dup
    renewed = self.class.new(
      @sender,
      Fluent::Config::Section.new({host: @host, port: @port, hostlabel: @hostlabel, username: @username, password: @password, shared_key: @shared_key, standby: @standby})
    )
    renewed
  end

  def start
    @thread = Thread.new(&method(:connect))
  end

  def detach!
    @detach = true
  end

  def detached?
    @detach
  end

  def tain!
    raise RuntimeError, "BUG: taining detached node" if @detach
    @writing = true
  end

  def tained?
    @writing
  end

  def release!
    @writing = false
  end

  def shutdown
    log.debug "shutting down node #{@host}"
    @state = :closed

    if @thread == Thread.current
      @sslsession.close if @sslsession
      @socket.close if @socket
      @thread.kill
    else
      if @thread
        @thread.kill
        @thread.join
      end
      @sslsession.close if @sslsession
      @socket.close if @socket
    end
  rescue => e
    log.debug "error on node shutdown #{e.class}:#{e.message}"
  end

  def join
    @thread && @thread.join
  end

  def established?
    @state == :established
  end

  def expired?
    if @keepalive.nil? || @keepalive == 0
      false
    else
      @expire && @expire < Time.now
    end
  end

  def generate_salt
    OpenSSL::Random.random_bytes(16)
  end

  def check_helo(message)
    log.debug "checking helo"
    # ['HELO', options(hash)]
    unless message.size == 2 && message[0] == 'HELO'
      return false
    end
    opts = message[1]
    @authentication = opts['auth']
    @allow_keepalive = opts['keepalive']
    true
  end

  def generate_ping
    log.debug "generating ping"
    # ['PING', self_hostname, sharedkey\_salt, sha512\_hex(sharedkey\_salt + self_hostname + shared_key),
    #  username || '', sha512\_hex(auth\_salt + username + password) || '']
    shared_key_hexdigest = Digest::SHA512.new.update(@shared_key_salt).update(@sender.self_hostname).update(@shared_key).hexdigest
    ping = ['PING', @sender.self_hostname, @shared_key_salt, shared_key_hexdigest]
    if @authentication != ''
      password_hexdigest = Digest::SHA512.new.update(@authentication).update(@username).update(@password).hexdigest
      ping.push(@username, password_hexdigest)
    else
      ping.push('','')
    end
    ping
  end

  def check_pong(message)
    log.debug "checking pong"
    # ['PONG', bool(authentication result), 'reason if authentication failed',
    #  self_hostname, sha512\_hex(salt + self_hostname + sharedkey)]
    unless message.size == 5 && message[0] == 'PONG'
      return false, 'invalid format for PONG message'
    end
    pong, auth_result, reason, hostname, shared_key_hexdigest = message

    unless auth_result
      return false, 'authentication failed: ' + reason
    end

    if hostname == @sender.self_hostname
      return false, 'same hostname between input and output: invalid configuration'
    end

    clientside = Digest::SHA512.new.update(@shared_key_salt).update(hostname).update(@shared_key).hexdigest
    unless shared_key_hexdigest == clientside
      return false, 'shared key mismatch'
    end

    return true, nil
  end

  def send_data(data)
    @sslsession.write data.to_msgpack
  end

  def on_read(data)
    log.debug "on_read"
    if self.established?
      #TODO: ACK
      log.warn "unknown packets arrived..."
      return
    end

    case @state
    when :helo
      unless check_helo(data)
        log.warn "received invalid helo message from #{@host}"
        self.shutdown
        return
      end
      send_data generate_ping()
      @state = :pingpong
    when :pingpong
      success, reason = check_pong(data)
      unless success
        log.warn "connection refused to #{@host}:" + reason
        self.shutdown
        return
      end
      log.info "connection established to #{@host}" if @first_session
      @state = :established
      @expire = Time.now + @keepalive if @keepalive && @keepalive > 0
      log.debug "connection established", host: @host, port: @port, expire: @expire
    end
  end

  def connect
    Thread.current.abort_on_exception = true
    log.debug "starting client"

    addr = @sender.hostname_resolver.getaddress(@host)
    log.debug "create tcp socket to node", host: @host, address: addr, port: @port
    begin
      sock = TCPSocket.new(addr, @port)
    rescue => e
      log.warn "failed to connect for secure-forward", error_class: e.class, error: e, host: @host, address: addr, port: @port
      @state = :failed
      return
    end

    log.trace "changing socket options"
    opt = [1, @sender.send_timeout.to_i].pack('I!I!')  # { int l_onoff; int l_linger; }
    sock.setsockopt(Socket::SOL_SOCKET, Socket::SO_LINGER, opt)

    opt = [@sender.send_timeout.to_i, 0].pack('L!L!')  # struct timeval
    sock.setsockopt(Socket::SOL_SOCKET, Socket::SO_SNDTIMEO, opt)

    log.trace "initializing SSL contexts"

    context = OpenSSL::SSL::SSLContext.new(@sender.ssl_version)

    log.trace "setting SSL verification options"

    if @sender.secure
      # inject OpenSSL::SSL::SSLContext::DEFAULT_PARAMS
      # https://bugs.ruby-lang.org/issues/9424
      context.set_params({})

      if @sender.ssl_ciphers
        context.ciphers = @sender.ssl_ciphers
      else
        ### follow httpclient configuration by nahi
        # OpenSSL 0.9.8 default: "ALL:!ADH:!LOW:!EXP:!MD5:+SSLv2:@STRENGTH"
        context.ciphers = "ALL:!aNULL:!eNULL:!SSLv2" # OpenSSL >1.0.0 default
      end

      log.trace "set verify_mode VERIFY_PEER"
      context.verify_mode = OpenSSL::SSL::VERIFY_PEER
      if @sender.enable_strict_verification
        context.ca_store = OpenSSL::X509::Store.new
        begin
          context.ca_store.set_default_paths
        rescue OpenSSL::X509::StoreError => e
          log.warn "faild to load system default certificates", error: e
        end
      end
      if @sender.ca_cert_path
        log.trace "set to use private CA", path: @sender.ca_cert_path
        context.ca_file = @sender.ca_cert_path
      end
    end

    log.debug "trying to connect ssl session", host: @host, address: addr, port: @port
    begin
      sslsession = OpenSSL::SSL::SSLSocket.new(sock, context)
      log.trace "connecting...", host: @host, address: addr, port: @port
      sslsession.connect
    rescue => e
      log.warn "failed to establish SSL connection", error_class: e.class, error: e, host: @host, address: addr, port: @port
      @state = :failed
      return
    end

    log.debug "ssl session connected", host: @host, port: @port

    begin
      if @sender.enable_strict_verification
        log.debug "checking peer's certificate", subject: sslsession.peer_cert.subject
        sslsession.post_connection_check(@hostlabel)
        verify = sslsession.verify_result
        if verify != OpenSSL::X509::V_OK
          err_name = Fluent::SecureForwardOutput::OpenSSLUtil.verify_result_name(verify)
          log.warn "BUG: failed to verify certification while connecting host #{@host} as #{@hostlabel} (but not raised, why?)"
          log.warn "BUG: verify_result: #{err_name}"
          raise RuntimeError, "BUG: failed to verify certification and to handle it correctly while connecting host #{@host} as #{@hostlabel}"
        end
      end
    rescue OpenSSL::SSL::SSLError => e
      log.warn "failed to verify certification while connecting ssl session", host: @host, hostlabel: @hostlabel
      self.shutdown
      raise
    end

    log.debug "ssl session connected", host: @host, port: @port
    @socket = sock
    @sslsession = sslsession

    buf = ''
    read_length = @sender.read_length
    read_interval = @sender.read_interval
    socket_interval = @sender.socket_interval

    loop do
      break if @detach

      begin
        while @sslsession.read_nonblock(read_length, buf)
          if buf == ''
            sleep read_interval
            next
          end
          @unpacker.feed_each(buf, &method(:on_read))
          buf = ''
        end
      rescue OpenSSL::SSL::SSLError
        # to wait i/o restart
        sleep socket_interval
      rescue EOFError
        log.warn "disconnected from #{@host}"
        break
      end
    end
    while @writing
      break if @detach

      sleep read_interval
    end
    self.shutdown
  end
end
