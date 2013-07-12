# -*- coding: utf-8 -*-

require 'fluent/mixin/config_placeholders'

module Fluent
  class SecureForwardInput < Input
    DEFAULT_SECURE_LISTEN_PORT = 24284

    Fluent::Plugin.register_input('secure_forward', self)

    config_param :self_hostname, :string
    include Fluent::Mixin::ConfigPlaceholders

    config_param :shared_key, :string

    config_param :bind, :string, :default => '0.0.0.0'
    config_param :port, :integer, :default => DEFAULT_SECURE_LISTEN_PORT
    config_param :allow_keepalive, :bool, :default => true #TODO: implement

    config_param :allow_anonymous_source, :bool, :default => true
    config_param :authentication, :bool, :default => false

    ## meaningless for security...? not implemented yet
    # config_param :dns_reverse_lookup_check, :bool, :default => false

    config_param :cert_auto_generate, :bool, :default => false
    config_param :generate_private_key_length, :integer, :default => 2048

    config_param :generate_cert_country, :string, :default => 'US'
    config_param :generate_cert_state, :string, :default => 'CA'
    config_param :generate_cert_locality, :string, :default => 'Mountain View'
    config_param :generate_cert_common_name, :string, :default => nil

    config_param :cert_file_path, :string, :default => nil
    config_param :private_key_file, :string, :default => nil
    config_param :private_key_passphrase, :string, :default => nil

    config_param :read_length, :size, :default => 8*1024*1024 # 8MB
    config_param :read_interval_msec, :integer, :default => 50 # 50ms
    config_param :socket_interval_msec, :integer, :default => 200 # 200ms

    attr_reader :read_interval, :socket_interval

    attr_reader :users # list of (username, password) by <user> tag
    # <user>
    #   username ....
    #   password ....
    # </user>
    attr_reader :nodes # list of hosts, allowed to connect <server> tag (it includes source ip, shared_key(optional))
    # <client>
    #   host ipaddr/hostname
    #   shared_key .... # optional shared key
    #   users username,list,of,allowed
    # </client>

    attr_reader :sessions # node/socket/thread list which has sslsocket instance keepaliving to client

    def initialize
      super
      require 'resolv'
      require 'socket'
      require 'openssl'
      require 'digest'
    end

    def configure(conf)
      super

      unless @cert_auto_generate || @cert_file_path
        raise Fluent::ConfigError, "One of 'cert_auto_generate' or 'cert_file_path' must be specified"
      end

      @read_interval = @read_interval_msec / 1000.0
      @socket_interval = @socket_interval_msec / 1000.0

      @users = []
      @nodes = []
      conf.elements.each do |element|
        case element.name
        when 'user'
          unless element['username'] && element['password']
            raise Fluent::ConfigError, "username/password pair missing in <user>"
          end
          @users.push({
              username: element['username'],
              password: element['password']
            })
        when 'client'
          unless element['host']
            raise Fluent::ConfigError, "host missing in <client>"
          end
          @nodes.push({
              host: element['host'],
              shared_key: (element['shared_key'] || @shared_key),
              users: (element['users'] ? element['users'].split(',') : nil),
            })
        else
          raise Fluent::ConfigError, "unknown config tag name"
        end
      end

      @generate_cert_common_name ||= @self_hostname
      self.certificate
      true
    end

    def start
      super
      OpenSSL::Random.seed(File.read("/dev/random", 16))
      @sessions = []
      @sock = nil
      @listener = Thread.new(&method(:run))
    end

    def shutdown
      @listener.kill
      @listener.join
      @sessions.each{ |s| s.shutdown }
      @sock.close
    end

    def select_authenticate_users(node, username)
      if node.nil? || node[:users].nil?
        @users.select{|u| u[:username] == username}
      else
        @users.select{|u| node[:users].include?(u[:username]) && u[:username] == username}
      end
    end

    def certificate
      return @cert, @key if @cert && @key

      if @cert_auto_generate
        key = OpenSSL::PKey::RSA.generate(@generate_private_key_length)

        digest = OpenSSL::Digest::SHA1.new
        issuer = subject = OpenSSL::X509::Name.new
        subject.add_entry('C', @generate_cert_country)
        subject.add_entry('ST', @generate_cert_state)
        subject.add_entry('L', @generate_cert_locality)
        subject.add_entry('CN', @generate_cert_common_name)

        cer = OpenSSL::X509::Certificate.new
        cer.not_before = Time.at(0)
        cer.not_after = Time.at(0)
        cer.public_key = key
        cer.serial = 1
        cer.issuer = issuer
        cer.subject  = subject
        cer.sign(key, digest)

        @cert = cer
        @key = key
        return @cert, @key
      end

      @cert = OpenSSL::X509::Certificate.new(File.read(@cert_file_path))
      @key = OpenSSL::PKey::RSA.new(File.read(@private_key_file), @private_key_passphrase)
    end

    def run # sslsocket server thread
      cert, key = self.certificate
      ctx = OpenSSL::SSL::SSLContext.new
      ctx.cert = cert
      ctx.key = key

      server = TCPServer.new(@bind, @port)
      @sock = OpenSSL::SSL::SSLServer.new(server, ctx)
      begin
        loop do
          while socket = @sock.accept
            @sessions.push Session.new(self, socket)
          end
        end
      rescue OpenSSL::SSL::SSLError => e
        raise unless e.message.start_with?('SSL_accept SYSCALL')
      end
    end

    def on_message(msg)
      # NOTE: copy&paste from Fluent::ForwardInput#on_message(msg)

      # TODO: format error
      tag = msg[0].to_s
      entries = msg[1]

      if entries.class == String
        # PackedForward
        es = MessagePackEventStream.new(entries, @cached_unpacker)
        Fluent::Engine.emit_stream(tag, es)

      elsif entries.class == Array
        # Forward
        es = Fluent::MultiEventStream.new
        entries.each {|e|
          time = e[0].to_i
          time = (now ||= Fluent::Engine.now) if time == 0
          record = e[1]
          es.add(time, record)
        }
        Fluent::Engine.emit_stream(tag, es)
  
      else
        # Message
        time = msg[1]
        time = Fluent::Engine.now if time == 0
        record = msg[2]
        Fluent::Engine.emit(tag, time, record)
      end
    end

    class Session # Fluent::SecureForwardInput::Session
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

      def established?
        @state == :established
      end

      def generate_salt
        OpenSSL::Random.random_bytes(16)
      end

      def check_node(hostname, ipaddress, port, proto)
        node = nil
        family = Socket.const_get(proto)
        @receiver.nodes.each do |n|
          proto, port, host, ipaddr, family_num, socktype_num, proto_num = Socket.getaddrinfo(n[:host], port, family).first
          if ipaddr == ipaddress
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
        $log.debug "generating helo"
        # ['HELO', options(hash)]
        [ 'HELO', {'auth' => (@receiver.authentication ? @auth_key_salt : ''), 'keepalive' => @receiver.allow_keepalive } ]
      end

      def check_ping(message)
        $log.debug "checking ping"
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
          $log.warn "Shared key mismatch from '#{hostname}'"
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
            $log.warn "Authentication failed from client '#{hostname}', username '#{username}'"
            return false, 'username/password mismatch'
          end
        end

        return true, shared_key_salt
      end

      def generate_pong(auth_result, reason_or_salt)
        $log.debug "generating pong"
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
        $log.debug "on_read"
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
          
          $log.debug "connection established"
          @state = :established
        end
      end

      def send_data(data)
        # not nonblock because write data (response) needs sequence
        @socket.write data.to_msgpack
      end

      def start
        $log.debug "starting server"

        proto, port, host, ipaddr = @socket.io.addr
        @node = check_node(host, ipaddr, port, proto)
        if @node.nil? && (! @receiver.allow_anonymous_source)
          $log.warn "Connection required from unknown host '#{host}' (#{ipaddr}), disconnecting..."
          self.shutdown
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
            $log.debug "Connection closed from '#{host}'(#{ipaddr})"
            break
          end
        end
        self.shutdown
      rescue => e
        $log.warn e
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
        $log.debug "#{e.class}:#{e.message}"
      end
    end
  end
end
