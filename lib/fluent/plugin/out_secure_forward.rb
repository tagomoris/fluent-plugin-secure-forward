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
    config_param :ca_file_path, :string, :default => nil

    config_param :read_length, :size, :default => 512 # 512bytes
    config_param :read_interval_msec, :integer, :default => 50 # 50ms
    config_param :socket_interval_msec, :integer, :default => 200 # 200ms

    config_param :reconnect_interval, :time, :default => 15

    attr_reader :read_interval, :socket_interval

    attr_reader :nodes
    # <server>
    #   host ipaddr/hostname
    #   hostlabel labelname # certification common name
    #   port 24284
    #   shared_key .... # optional shared key
    #   username name # if required
    #   password pass # if required
    # </server>

    attr_reader :hostname_resolver

    def initialize
      super
      require 'socket'
      require 'openssl'
      require 'digest'
      require 'resolve/hostname'
    end

    def configure(conf)
      super

      unless @allow_self_signed_certificate
        raise Fluent::ConfigError, "not tested yet!"
      end

      @read_interval = @read_interval_msec / 1000.0
      @socket_interval = @socket_interval_msec / 1000.0

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
      if @nodes.size > 1
        raise Fluent::ConfigError, "Two or more servers are not supported yet."
      end

      @hostname_resolver = Resolve::Hostname.new(:system_resolver => true)

      true
    end

    def select_node
      #TODO: roundrobin? random?
      @nodes.select(&:established?).first
    end

    def start
      super

      OpenSSL::Random.seed(File.read("/dev/random", 16))
      @nodes.each do |node|
        node.start
      end
      @nodewatcher = Thread.new(&method(:node_watcher))
    end

    def node_watcher
      loop do
        sleep @reconnect_interval
        $log.debug "in node health watcher"
        (0...(@nodes.size)).each do |i|
          $log.debug "node health watcher for #{@nodes[i].host}"
          if @nodes[i].state != :established
            $log.info "dead connection found: #{@nodes[i].host}, reconnecting..."
            node = @nodes[i]
            @nodes[i] = node.dup
            @nodes[i].start
            node.shutdown
          end
        end
      end
    end

    def shutdown
      @nodewatcher.kill
      @nodewatcher.join
      @nodes.each do |node|
        node.shutdown
      end
    end

    def write_objects(tag, es)
      #TODO: check errors
      node = select_node
      unless node
        raise "no one nodes with valid ssl session"
      end

      begin
        send_data(node, tag, es)
      rescue IOError => e
        $log.warn "Failed to send messages to #{node.host}, parging."
        node.shutdown
      end
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
        @thread = nil
      end

      def dup
        Node.new(
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

      def verify_result_name(code)
        case code
        when OpenSSL::X509::V_OK then 'V_OK'
        when OpenSSL::X509::V_ERR_AKID_SKID_MISMATCH then 'V_ERR_AKID_SKID_MISMATCH'
        when OpenSSL::X509::V_ERR_APPLICATION_VERIFICATION then 'V_ERR_APPLICATION_VERIFICATION'
        when OpenSSL::X509::V_ERR_CERT_CHAIN_TOO_LONG then 'V_ERR_CERT_CHAIN_TOO_LONG'
        when OpenSSL::X509::V_ERR_CERT_HAS_EXPIRED then 'V_ERR_CERT_HAS_EXPIRED'
        when OpenSSL::X509::V_ERR_CERT_NOT_YET_VALID then 'V_ERR_CERT_NOT_YET_VALID'
        when OpenSSL::X509::V_ERR_CERT_REJECTED then 'V_ERR_CERT_REJECTED'
        when OpenSSL::X509::V_ERR_CERT_REVOKED then 'V_ERR_CERT_REVOKED'
        when OpenSSL::X509::V_ERR_CERT_SIGNATURE_FAILURE then 'V_ERR_CERT_SIGNATURE_FAILURE'
        when OpenSSL::X509::V_ERR_CERT_UNTRUSTED then 'V_ERR_CERT_UNTRUSTED'
        when OpenSSL::X509::V_ERR_CRL_HAS_EXPIRED then 'V_ERR_CRL_HAS_EXPIRED'
        when OpenSSL::X509::V_ERR_CRL_NOT_YET_VALID then 'V_ERR_CRL_NOT_YET_VALID'
        when OpenSSL::X509::V_ERR_CRL_SIGNATURE_FAILURE then 'V_ERR_CRL_SIGNATURE_FAILURE'
        when OpenSSL::X509::V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT then 'V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT'
        when OpenSSL::X509::V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD then 'V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD'
        when OpenSSL::X509::V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD then 'V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD'
        when OpenSSL::X509::V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD then 'V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD'
        when OpenSSL::X509::V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD then 'V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD'
        when OpenSSL::X509::V_ERR_INVALID_CA then 'V_ERR_INVALID_CA'
        when OpenSSL::X509::V_ERR_INVALID_PURPOSE then 'V_ERR_INVALID_PURPOSE'
        when OpenSSL::X509::V_ERR_KEYUSAGE_NO_CERTSIGN then 'V_ERR_KEYUSAGE_NO_CERTSIGN'
        when OpenSSL::X509::V_ERR_OUT_OF_MEM then 'V_ERR_OUT_OF_MEM'
        when OpenSSL::X509::V_ERR_PATH_LENGTH_EXCEEDED then 'V_ERR_PATH_LENGTH_EXCEEDED'
        when OpenSSL::X509::V_ERR_SELF_SIGNED_CERT_IN_CHAIN then 'V_ERR_SELF_SIGNED_CERT_IN_CHAIN'
        when OpenSSL::X509::V_ERR_SUBJECT_ISSUER_MISMATCH then 'V_ERR_SUBJECT_ISSUER_MISMATCH'
        when OpenSSL::X509::V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY then 'V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY'
        when OpenSSL::X509::V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE then 'V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY'
        when OpenSSL::X509::V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE then 'V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE'
        when OpenSSL::X509::V_ERR_UNABLE_TO_GET_CRL then 'V_ERR_UNABLE_TO_GET_CRL'
        when OpenSSL::X509::V_ERR_UNABLE_TO_GET_ISSUER_CERT then 'V_ERR_UNABLE_TO_GET_ISSUER_CERT'
        when OpenSSL::X509::V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY then 'V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY'
        when OpenSSL::X509::V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE then 'V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE'
        end
      end

      def established?
        @state == :established
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
        @keepalive = opts['keepalive']
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
          # TODO: log debug
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
          $log.info "connection established to #{@host}"
          @state = :established
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
        context.ca_file = @cert_file_path
        # TODO: context.ciphers= (SSL Shared key chiper protocols)

        $log.debug "trying to connect ssl session", :host => @host, :port => @port
        sslsession = OpenSSL::SSL::SSLSocket.new(sock, context)
        sslsession.connect
        $log.debug "ssl session connected", :host => @host, :port => @port

        begin
          unless @sender.allow_self_signed_certificate
            $log.debug "checking peer's certificate", :subject => sslsession.peer_cert.subject
            sslsession.post_connection_check(@hostlabel)
            verify = sslsession.verify_result
            if verify != OpenSSL::X509::V_OK
              err_name = verify_result_name(verify)
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
  end
end
