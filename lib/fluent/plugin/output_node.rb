# require 'msgpack'
# require 'socket'
# require 'openssl'
# require 'digest'
# require 'resolve/hostname'

require_relative 'openssl_util'

class Fluent::SecureForwardOutput::Node
  attr_accessor :host, :port, :hostlabel, :shared_key, :username, :password
  attr_accessor :authentication, :keepalive
  attr_accessor :socket, :sslsession, :unpacker, :shared_key_salt, :state

  attr_accessor :first_session, :detach

  attr_reader :expire

  def initialize(sender, shared_key, conf)
    @sender = sender
    @shared_key = shared_key

    @host = conf['host']
    @port = (conf['port'] || Fluent::SecureForwardOutput::DEFAULT_SECURE_CONNECT_PORT).to_i
    @hostlabel = conf['hostlabel'] || conf['host']
    @username = conf['username'] || ''
    @password = conf['password'] || ''

    @authentication = nil

    @keepalive = nil
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

  def dup
    self.class.new(
      @sender,
      @shared_key,
      {'host' => @host, 'port' => @port, 'hostlabel' => @hostlabel, 'username' => @username, 'password' => @password}
    )
  end

  def start
    @thread = Thread.new(&method(:connect))
  end

  def shutdown
    $log.debug "shutting down node #{@host}"
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
    $log.debug "error on node shutdown #{e.class}:#{e.message}"
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
    $log.debug "checking helo"
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
    $log.debug "generating ping"
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
    $log.debug "checking pong"
    # ['PONG', bool(authentication result), 'reason if authentication failed',
    #  self_hostname, sha512\_hex(salt + self_hostname + sharedkey)]
    unless message.size == 5 && message[0] == 'PONG'
      return false, 'invalid format for PONG message'
    end
    pong, auth_result, reason, hostname, shared_key_hexdigest = message

    unless auth_result
      return false, 'authentication failed: ' + reason
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
    $log.debug "on_read"
    if self.established?
      #TODO: ACK
      $log.warn "unknown packets arrived..."
      return
    end

    case @state
    when :helo
      unless check_helo(data)
        $log.warn "received invalid helo message from #{@host}"
        self.shutdown
        return
      end
      send_data generate_ping()
      @state = :pingpong
    when :pingpong
      success, reason = check_pong(data)
      unless success
        $log.warn "connection refused to #{@host}:" + reason
        self.shutdown
        return
      end
      $log.info "connection established to #{@host}" if @first_session
      @state = :established
      @expire = Time.now + @keepalive if @keepalive && @keepalive > 0
      $log.debug "connection established", :host => @host, :port => @port, :expire => @expire
    end
  end

  def connect
    $log.debug "starting client"

    addr = @sender.hostname_resolver.getaddress(@host)
    $log.debug "create tcp socket to node", :host => @host, :address => addr, :port => @port
    sock = TCPSocket.new(addr, @port)

    $log.trace "changing socket options"
    opt = [1, @sender.send_timeout.to_i].pack('I!I!')  # { int l_onoff; int l_linger; }
    sock.setsockopt(Socket::SOL_SOCKET, Socket::SO_LINGER, opt)

    opt = [@sender.send_timeout.to_i, 0].pack('L!L!')  # struct timeval
    sock.setsockopt(Socket::SOL_SOCKET, Socket::SO_SNDTIMEO, opt)

    # TODO: SSLContext constructer parameter (SSL/TLS protocol version)
    $log.trace "initializing SSL contexts"
    context = OpenSSL::SSL::SSLContext.new
    # TODO: context.ca_file = (ca_file_path)
    # TODO: context.ciphers = (SSL Shared key chiper protocols)

    $log.debug "trying to connect ssl session", :host => @host, :ipaddr => addr, :port => @port
    sslsession = OpenSSL::SSL::SSLSocket.new(sock, context)
    # TODO: check connection failure
    sslsession.connect
    $log.debug "ssl session connected", :host => @host, :port => @port

    begin
      unless @sender.allow_self_signed_certificate
        $log.debug "checking peer's certificate", :subject => sslsession.peer_cert.subject
        sslsession.post_connection_check(@hostlabel)
        verify = sslsession.verify_result
        if verify != OpenSSL::X509::V_OK
          err_name = Fluent::SecureForwardOutput::OpenSSLUtil.verify_result_name(verify)
          $log.warn "failed to verify certification while connecting host #{@host} as #{@hostlabel} (but not raised, why?)"
          $log.warn "verify_result: #{err_name}"
          raise RuntimeError, "failed to verify certification while connecting host #{@host} as #{@hostlabel}"
        end
      end
    rescue OpenSSL::SSL::SSLError => e
      $log.warn "failed to verify certification while connecting ssl session", :host => @host, :hostlabel => @hostlabel
      self.shutdown
      raise
    end

    $log.debug "ssl sessison connected", :host => @host, :port => @port
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
        $log.warn "disconnected from #{@host}"
        break
      end
    end
    self.shutdown
  end
end
