# -*- coding: utf-8 -*-

require 'fluent/mixin/config_placeholders'

module Fluent
  class SecureForwardOutput < ObjectBufferedOutput
    DEFAULT_SECURE_CONNECT_PORT = 24284

    Fluent::Plugin.register_output('secure_forward', self)

    config_param :self_hostname, :string
    include Fluent::Mixin::ConfigPlaceholders

    config_param :shared_key, :string

    # config_param :keepalive, :time, :default => 3600 # 0 means disable keepalive

    config_param :send_timeout, :time, :default => 60
    # config_param :hard_timeout, :time, :default => 60
    # config_param :expire_dns_cache, :time, :default => 0 # 0 means disable cache

    config_param :allow_self_signed_certificate, :bool, :default => true
    config_param :cert_file_path, :string, :default => nil

    config_param :read_length, :size, :default => 512 # 512bytes
    config_param :read_interval_msec, :integer, :default => 50 # 50ms
    config_param :socket_interval_msec, :integer, :default => 200 # 200ms

    attr_reader :read_interval, :socket_interval

    attr_reader :nodes
    # <server>
    #   host ipaddr/hostname
    #   port 24284
    #   shared_key .... # optional shared key
    #   username name # if required
    #   password pass # if required
    # </server>

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

      # TODO: read cert_file
      self.certificates

      # read <server> tags and set to nodes
      @nodes = []
      conf.elements.each do |element|
        case element.name
        when 'server'
          unless element['host']
            raise Fluent::ConfigError, "host missing in <server>"
          end
          node_shared_key = element['shared_key'] || @shared_key
          @nodes.push Node.new(self, node_shared_key, element)
        else
          raise Fluent::ConfigError, "unknown config tag name #{element.name}"
        end
      end

      true
    end

    def select_node
      @nodes.select(&:established?).first
    end

    def start
      super

      OpenSSL::Random.seed(File.read("/dev/random", 16))
      # in thread
      @nodes.each do |node|
        node.start
      end
    end

    def shutdown
      @nodes.each do |node|
        node.shutdown
      end
    end

    def certificates
      #TODO implement here!
      @certs = []
      return @certs
    end

    def write_objects(tag, es)
      #TODO: select one of nodes or connected sockets
      #TODO: check errors
      node = select_node
      unless node
        raise "no one nodes with valid ssl session"
      end

      send_data(node, tag, es)
    end

    # MessagePack FixArray length = 2
    FORWARD_HEADER = [0x92].pack('C')

    # to forward messages
    def send_data(node, tag, es)
      ssl = node.sslsession
      # beginArray(2)
      ssl.write FORWARD_HEADER

      # writeRaw(tag)
      ssl.write tag.to_msgpack

      # beginRaw(size)
      sz = es.size
      #  # FixRaw
      #  ssl.write [0xa0 | sz].pack('C')
      #elsif sz < 65536
      #  # raw 16
      #  ssl.write [0xda, sz].pack('Cn')
      #else
      # raw 32
      ssl.write [0xdb, sz].pack('CN')
      #end

      # writeRawBody(packed_es)
      es.write_to(ssl)
    end

    class Node # Fluent::SecureForwardOutput::Node
      attr_accessor :host, :port, :hostlabel, :shared_key, :username, :password
      attr_accessor :authentication, :keepalive
      attr_accessor :socket, :sslsession, :unpacker, :shared_key_salt, :state

      def initialize(sender, shared_key, conf)
        @sender = sender
        @shared_key = shared_key

        @host = conf['host']
        @port = (conf['port'] || DEFAULT_SECURE_CONNECT_PORT).to_i
        @hostlabel = conf['hostlabel'] || conf['host']
        @username = conf['username'] || ''
        @password = conf['password'] || ''

        @authentication = nil
        @keepalive = nil

        @socket = nil
        @sslsession = nil
        @unpacker = MessagePack::Unpacker.new

        @shared_key_salt = generate_salt
        @state = :helo
      end

      def start
        @thread = Thread.new(&method(:connect))
      end

      def shutdown
        @state = :closed
        if @thread
          @thread.kill
          @thread.join
        end
        @sslsession.close if @sslsession
        @socket.close if @socket
      end

      def established?
        @state == :established
      end

      def generate_salt
        OpenSSL::Random.random_bytes(16)
      end

      def check_helo(message)
        $log.info "checking helo"
        # ['HELO', options(hash)]
        unless message.size == 2 && message[0] == 'HELO'
          return false
        end
        opts = message[1]
        @authentication = opts['auth']
        @keepalive = opts['keepalive']
        true
      end

      def generate_ping
        $log.info "generating ping"
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
        $log.info "checking pong"
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
        $log.info "on_read"
        if self.established?
          #TODO: ACK
          $log.warn "unknown packets arrived..."
          return
        end

        case @state
        when :helo
          # TODO: log debug
          unless check_helo(data)
            # invalid helo message
            # disconnect
            # kill thread
            return
          end
          send_data generate_ping()
          @state = :pingpong
        when :pingpong
          success, reason = check_pong(data)
          unless success
            # connection refused
            # log warn reason
            # disconnect and close
            # kill thread
            return
          end
          $log.info "connection established"
          @state = :established
        end
      end

      def connect
        $log.info "starting client"
        sock = TCPSocket.new(@host, @port)

        opt = [1, @sender.send_timeout.to_i].pack('I!I!')  # { int l_onoff; int l_linger; }
        sock.setsockopt(Socket::SOL_SOCKET, Socket::SO_LINGER, opt)

        opt = [@sender.send_timeout.to_i, 0].pack('L!L!')  # struct timeval
        sock.setsockopt(Socket::SOL_SOCKET, Socket::SO_SNDTIMEO, opt)

        context = OpenSSL::SSL::SSLContext.new
        # TODO get @sender.certs and set into context
        sslsession = OpenSSL::SSL::SSLSocket.new(sock, context)

        sslsession.connect
      
        unless @sender.allow_self_signed_certificate
          sslsession.post_connection_check(@hostlabel)
          if sslsession.verify_result != OpenSSL::X509::V_OK
            raise RuntimeError, "failed to verify certification while connecting host #{@host} as #{@hostlabel}"
          end
        end

        $log.info "ssl sessison connected"
        @socket = sock
        @sslsession = sslsession

        buf = ''
        read_length = @sender.read_length
        read_interval = @sender.read_interval
        socket_interval = @sender.socket_interval

        loop do
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
          end
        end
      end
    end
  end
end
