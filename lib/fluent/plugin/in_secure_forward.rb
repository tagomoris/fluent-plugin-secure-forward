# -*- coding: utf-8 -*-

require 'fluent/mixin/config_placeholders'

module Fluent
  class SecureForwardInput < Input
    DEFAULT_SECURE_LISTEN_PORT = 24284

    Fluent::Plugin.register_input('secure_forward', self)

    config_param :self_hostname, :string, :default => nil
    include Fluent::Mixin::ConfigPlaceholders

    config_param :shared_key, :string

    config_param :bind, :string, :default => '0.0.0.0'
    config_param :port, :integer, :default => DEFAULT_SECURE_LISTEN_PORT
    config_param :allow_keepalive, :bool, :default => true

    config_param :allow_anonymous_source, :bool, :default => true
    config_param :authentication, :bool, :default => false
    config_param :dns_reverse_lookup_check, :bool, :default => false

    config_param :cert_auto_generate, :string, :default => false
    config_param :generate_private_key_length, :integer, :default => 2048

    config_param :generate_cert_country, :string, :default => 'US'
    config_param :generate_cert_state, :string, :default => 'CA'
    config_param :generate_cert_locality, :string, :default => 'Mountain View'
    config_param :generate_cert_common_name, :string, :default => 'fluentd secure forward'

    config_param :cert_file_path, :string, :default => nil
    config_param :private_key_file, :string
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
    attr_reader :nodes # list of hosts, allowed to connect <node> tag (it includes source ip, shared_key(optional))
    # <node>
    #   host ipaddr/hostname
    #   shared_key .... # optional shared key
    #   users username,list,of,allowed
    # </node>

    attr_reader :sessions # node/socket/thread list which has sslsocket instance keepaliving to client

    def initialize
      super
      require 'socket'
      require 'openssl'
      require 'digest'
    end

    def configure(conf)
      super
      
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
        when 'node'
          unless element['host']
            raise Fluent::ConfigError, "host missing in <node>"
          end
          @nodes.push({
              host: element['host'],
              shared_key: (element['shared_key'] || @shared_key),
              users: (element['users'] || '').split(',')
            })
        else
          raise Fluent::ConfigError, "unknown config tag name"
        end
      end

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
      @sock.close
      @sessions.each{ |s| s.close }
      @listener.join
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

      raise NotImplementedError, "wait a minute!"

      @cert = OpenSSL::X509::Certificate.new(File.read(@cert_file_path))
      @key = OpenSSL::PKey::RSA.new(File.read(@private_key_file), @private_key_passphrase)
    end

    def run # sslsocket server thread
      cert, key = self.certificate
      ctx = OpenSSL::SSL::SSLContext.new
      ctx.cert = cert
      ctx.key = key

      server = TCPServer.new(2013)
      @sock = OpenSSL::SSL::SSLServer.new(server, ctx)
      loop do
        while socket = @sock.accept
          @sessions.push Session.new(socket, method(:check_ping), method(:generate_pong), method(:on_message))
        end
      end
    end

    def check_node(hostname, ipaddress)
      # @nodes.push({
      #     host: element['host'],
      #     shared_key: (element['shared_key'] || @shared_key),
      #     users: (element['users'] || '').split(',')
      #   })
      #TODO: check from nodes and select one (or nil)
    end

    def generate_salt
      OpenSSL::Random.random_bytes(16)
    end

    def generate_helo(auth_salt)
      # ['HELO', options(hash)]
      [ 'HELO', {'auth' => (@authentication ? auth_salt : ''), 'keepalive' => @allow_keepalive } ].to_msgpack
    end

    def check_ping(auth_salt, message)
      # ['PING', selfhostname, sharedkey\_salt, sha512\_hex(sharedkey\_salt + selfhostname + sharedkey),
      #  username || '', sha512\_hex(auth\_salt + username + password) || '']
      unless message.size == 6 && message[0] == 'PING'
        return false, 'invalid ping message'
      end
      ping, hostname, shared_key_salt, shared_key_hexdigest, username, password_digest = message

      serverside = Digest::SHA512.new(shared_key_salt).update(hostname).update(@shared_key).hexdigest
      if shared_key_hexdigest != serverside
        return false, 'shared_key mismatch'
      end

      if @authentication
        if @node and @node[:users].size > 0
          #TODO: check username matches or mismatch
        end
        #TODO: check password matches for username
      end

      return true, shared_key_salt
    end

    def generate_pong(salt, auth_result, reason_or_salt)
      # ['PONG', bool(authentication result), 'reason if authentication failed', selfhostname, sha512\_hex(salt + selfhostname + sharedkey)]
      if not auth_result
        return ['PONG', auth_result, reason_or_salt, '', '']
      end

      shared_key_hex = Digest::SHA512.new(reason_or_salt).update(@selfhostname).update(@shared_key).hexdigest
      [ 'PONG', true, '', @selfhostname, shared_key_hex ]
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

    class Session # Fluent::SecureForwardOutput::Session
      attr_accessor :state, :thread, :node, :socket, :unpacker, :auth_salt, :shared_key_salt

      def initialize(socket, receiver)
        @handshake = false

        @state = :helo

        @socket = socket
        @socket.sync = true
        proto, port, host, ipaddr = @socket.io.addr

        @node = receiver.check_node(host)
        if @node.nil? && (! receiver.allow_anonymous_source)
          raise NotImplementedError, "wait a minute."
          # TODO: implement to disconnect socket
        end

        # check reverse lookup if needed
        if receiver.dns_reverse_lookup_check
          raise NotImplementedError, "wait a minute."
          # TODO: implement to disconnect socket
        end

        @auth_key_salt = receiver.generate_salt
        @unpacker = MessagePack::Unpacker.new
        @thread = Thread.new(:start)
      end

      def on_read(data)
        if @state == :established
          receiver.on_message(data)
        end

        case @state
        when :helo
          # TODO: log debug
          send_data(receiver.generate_helo(@shared_key_salt))
          @state = :pingpong
        when :pingpong
          result, reason_or_salt = receiver.check_ping(@salt, data)
          # TODO: log info? debug?
          if not result
            send_data(receiver.generate_pong(@salt, result, reason_or_salt))
            # connection refused
            # disconnect and close
            # kill thread
          end
          
          @state = :established
          @socket.sync = false
        end
      end

      def send_data(data)
        # not nonblock because write data (response) needs sequence
        @socket.write(data)
      end

      def start
        buf = ''
        loop do 
          begin
            while @socket.read_nonblock(receiver.read_length, buf)
              if buf == ''
                sleep receiver.read_interval
                next
              end
              @unpacker.feed_each(buf, method(:on_read))
            end
          rescue OpenSSL::SSL::SSLError
            # to wait i/o restart
            sleep receiver.socket_interval
          end
        end
      end

      def close
        @socket.close
        @thread.join
      end
    end
  end
end
