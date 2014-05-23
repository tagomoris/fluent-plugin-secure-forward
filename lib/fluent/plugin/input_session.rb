require 'msgpack'
require 'socket'
require 'openssl'
require 'digest'
# require 'resolv'

class Fluent::SecureForwardInput::Session
  attr_accessor :receiver
  attr_accessor :state, :thread, :node, :socket, :unpacker, :auth_salt

  def initialize(receiver, socket)
    @receiver = receiver

    @state = :helo

    @socket = socket
    @socket.sync = true

    @ipaddress = nil
    @node = nil
    @unpacker = MessagePack::Unpacker.new
    @thread = Thread.new(&method(:start))
  end

  def log
    @receiver.log
  end

  def established?
    @state == :established
  end

  def generate_salt
    OpenSSL::Random.random_bytes(16)
  end

  def check_node(ipaddress)
    node = nil
    @receiver.nodes.each do |n|
      if n[:address].include?(ipaddress)
        node = n
        break
      end
    end
    node
  end

  ## not implemented yet
  # def check_hostname_reverse_lookup(ipaddress)
  #   rev_name = Resolv.getname(ipaddress)
  #   proto, port, host, ipaddr, family_num, socktype_num, proto_num = Socket.getaddrinfo(rev_name, DUMMY_PORT)
  #   unless ipaddr == ipaddress
  #     return false
  #   end
  #   true
  # end

  def generate_helo
    log.debug "generating helo"
    # ['HELO', options(hash)]
    [ 'HELO', {'auth' => (@receiver.authentication ? @auth_key_salt : ''), 'keepalive' => @receiver.allow_keepalive } ]
  end

  def check_ping(message)
    log.debug "checking ping"
    # ['PING', self_hostname, shared_key\_salt, sha512\_hex(shared_key\_salt + self_hostname + shared_key),
    #  username || '', sha512\_hex(auth\_salt + username + password) || '']
    unless message.size == 6 && message[0] == 'PING'
      return false, 'invalid ping message'
    end
    ping, hostname, shared_key_salt, shared_key_hexdigest, username, password_digest = message

    shared_key = if @node && @node[:shared_key]
                   @node[:shared_key]
                 else
                   @receiver.shared_key
                 end
    serverside = Digest::SHA512.new.update(shared_key_salt).update(hostname).update(shared_key).hexdigest
    if shared_key_hexdigest != serverside
      log.warn "Shared key mismatch from '#{hostname}'"
      return false, 'shared_key mismatch'
    end

    if @receiver.authentication
      users = @receiver.select_authenticate_users(@node, username)
      success = false
      users.each do |user|
        passhash = Digest::SHA512.new.update(@auth_key_salt).update(username).update(user[:password]).hexdigest
        success ||= (passhash == password_digest)
      end
      unless success
        log.warn "Authentication failed from client '#{hostname}', username '#{username}'"
        return false, 'username/password mismatch'
      end
    end

    return true, shared_key_salt
  end

  def generate_pong(auth_result, reason_or_salt)
    log.debug "generating pong"
    # ['PONG', bool(authentication result), 'reason if authentication failed',
    #  self_hostname, sha512\_hex(salt + self_hostname + sharedkey)]
    if not auth_result
      return ['PONG', false, reason_or_salt, '', '']
    end

    shared_key = if @node && @node[:shared_key]
                   @node[:shared_key]
                 else
                   @receiver.shared_key
                 end
    shared_key_hex = Digest::SHA512.new.update(reason_or_salt).update(@receiver.self_hostname).update(shared_key).hexdigest
    [ 'PONG', true, '', @receiver.self_hostname, shared_key_hex ]
  end

  def on_read(data)
    log.debug "on_read"
    if self.established?
      @receiver.on_message(data)
    end

    case @state
    when :pingpong
      success, reason_or_salt = self.check_ping(data)
      if not success
        send_data generate_pong(false, reason_or_salt)
        self.shutdown
        return
      end
      send_data generate_pong(true, reason_or_salt)

      log.debug "connection established"
      @state = :established
    end
  end

  def send_data(data)
    # not nonblock because write data (response) needs sequence
    @socket.write data.to_msgpack
  end

  def start
    log.debug "starting server"

    log.trace "accepting ssl session"
    begin
      @socket.accept
    rescue OpenSSL::SSL::SSLError => e
      log.debug "failed to establish ssl session"
      self.shutdown
      return
    end

    proto, port, host, ipaddr = @socket.io.peeraddr
    @node = check_node(ipaddr)
    if @node.nil? && (! @receiver.allow_anonymous_source)
      log.warn "Connection required from unknown host '#{host}' (#{ipaddr}), disconnecting..."
      self.shutdown
      return
    end

    @auth_key_salt = generate_salt

    buf = ''
    read_length = @receiver.read_length
    read_interval = @receiver.read_interval
    socket_interval = @receiver.socket_interval

    send_data generate_helo()
    @state = :pingpong

    loop do
      begin
        while @socket.read_nonblock(read_length, buf)
          if buf == ''
            sleep read_interval
            next
          end
          @unpacker.feed_each(buf, &method(:on_read))
          buf = ''
        end
      rescue OpenSSL::SSL::SSLError => e
        # to wait i/o restart
        sleep socket_interval
      rescue EOFError => e
        log.debug "Connection closed from '#{host}'(#{ipaddr})"
        break
      end
    end
  rescue Errno::ECONNRESET => e
    # disconnected from client
  rescue => e
    log.warn "unexpected error in in_secure_forward", :error_class => e.class, :error => e
  ensure
    self.shutdown
  end

  def shutdown
    @state = :closed
    if @thread == Thread.current
      @socket.close
      @thread.kill
    else
      if @thread
        @thread.kill
        @thread.join
      end
      @socket.close
    end
  rescue => e
    log.debug "#{e.class}:#{e.message}"
  end
end
