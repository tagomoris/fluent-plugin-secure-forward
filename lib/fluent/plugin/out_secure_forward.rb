# -*- coding: utf-8 -*-

require 'fluent/output'
require 'fluent/mixin/config_placeholders'

module Fluent
  class SecureForwardOutput < ObjectBufferedOutput
  end
end

require_relative 'output_node'

module Fluent
  class SecureForwardOutput < ObjectBufferedOutput
    DEFAULT_SECURE_CONNECT_PORT = 24284

    Fluent::Plugin.register_output('secure_forward', self)

    config_param :secure, :bool

    config_param :self_hostname, :string
    include Fluent::Mixin::ConfigPlaceholders

    config_param :shared_key, :string, secret: true

    config_param :keepalive, :time, default: nil # nil/0 means disable keepalive expiration
    config_param :connection_hard_timeout, :time, default: nil # specifying 0 explicitly means not to disconnect stuck connection forever

    config_param :send_timeout, :time, default: 60
    # config_param :hard_timeout, :time, :default => 60

    config_param :expire_dns_cache, :time, default: 60 # 0 means disable DNS cache

    config_param :ca_cert_path, :string, default: nil

    config_param :enable_strict_verification, :bool, default: nil # FQDN check with hostlabel
    config_param :ssl_version, :string, default: 'TLSv1_2'
    config_param :ssl_ciphers, :string, default: nil

    config_param :read_length, :size, default: 512 # 512bytes
    config_param :read_interval_msec, :integer, default: 50 # 50ms
    config_param :socket_interval_msec, :integer, default: 200 # 200ms

    config_param :reconnect_interval, :time, default: 5
    config_param :established_timeout, :time, default: 10

    config_param :proxy_uri, :string, default: nil

    attr_reader :read_interval, :socket_interval

    config_section :server, param_name: :servers do
      config_param :host, :string
      config_param :hostlabel, :string, default: nil
      config_param :port, :integer, default: DEFAULT_SECURE_CONNECT_PORT
      config_param :shared_key, :string, default: nil, secret: true
      config_param :username, :string, default: ''
      config_param :password, :string, default: '', secret: true
      config_param :standby, :bool, default: false
      config_param :proxy_uri, :string, default: nil
    end
    attr_reader :nodes

    attr_reader :hostname_resolver

    def initialize
      super
      require 'socket'
      require 'openssl'
      require 'digest'
      require 'resolve/hostname'
      require 'securerandom'
    end

    # Define `log` method for v0.10.42 or earlier
    unless method_defined?(:log)
      define_method("log") { $log }
    end

    def configure(conf)
      super

      if @secure
        if @ca_cert_path
          raise Fluent::ConfigError, "CA cert file not found nor readable at '#{@ca_cert_path}'" unless File.readable?(@ca_cert_path)
          begin
            OpenSSL::X509::Certificate.new File.read(@ca_cert_path)
          rescue OpenSSL::X509::CertificateError => e
            raise Fluent::ConfigError, "failed to load CA cert file"
          end
        else
          raise Fluent::ConfigError, "FQDN verification required for certificates issued from public CA" unless @enable_strict_verification
          log.info "secure connection with valid certificates issued from public CA"
        end
      else
        log.warn "'insecure' mode has vulnerability for man-in-the-middle attacks."
      end

      if @keepalive && !@connection_hard_timeout
        @connection_hard_timeout = @keepalive * 1.2
      end

      @read_interval = @read_interval_msec / 1000.0
      @socket_interval = @socket_interval_msec / 1000.0

      @nodes = []
      @servers.each do |server|
        node = Node.new(self, server)
        node.first_session = true
        @nodes.push node
      end

      if @num_threads > @nodes.select{|n| not n.standby}.size
        log.warn "Too many num_threads for secure-forward: threads should be smaller or equal to non standby servers"
      end

      @next_node = 0
      @mutex = Mutex.new

      @hostname_resolver = Resolve::Hostname.new(system_resolver: true, ttl: @expire_dns_cache)

      true
    end

    def select_node(permit_standby=false)
      tries = 0
      nodes = @nodes.size
      @mutex.synchronize {
        n = nil
        while tries <= nodes
          n = @nodes[@next_node]
          @next_node += 1
          @next_node = 0 if @next_node >= nodes

          if n && n.established? && (! n.tained?) && (! n.detached?) && (!n.standby || permit_standby)
            n.tain!
            return n
          end

          tries += 1
        end
        nil
      }
    end

    def start
      super

      log.debug "starting secure-forward"
      OpenSSL::Random.seed(SecureRandom.random_bytes(16))
      log.debug "start to connect target nodes"
      @nodes.each do |node|
        log.debug "connecting node", host: node.host, port: node.port
        node.start
      end
      @nodewatcher = Thread.new(&method(:node_watcher))
      @nodewatcher.abort_on_exception = true
    end

    def node_watcher
      reconnectings = Array.new(@nodes.size)
      nodes_size = @nodes.size

      loop do
        sleep @reconnect_interval

        log.trace "in node health watcher"

        (0...nodes_size).each do |i|
          log.trace "node health watcher for #{@nodes[i].host}"

          next if @nodes[i].established? && ! @nodes[i].expired? && ! @nodes[i].detached?

          next if reconnectings[i]

          reason = :expired

          unless @nodes[i].established?
            log.warn "dead connection found: #{@nodes[i].host}, reconnecting..."
            reason = :dead
          end

          node = @nodes[i]
          log.debug "reconnecting to node", host: node.host, port: node.port, state: node.state, expire: node.expire, expired: node.expired?, detached: node.detached?

          renewed = node.dup
          renewed.start

          Thread.pass # to connection thread
          reconnectings[i] = { conn: renewed, at: Time.now, reason: reason }
        end

        (0...nodes_size).each do |i|
          next unless reconnectings[i]

          log.trace "checking reconnecting node #{reconnectings[i][:conn].host}"

          if reconnectings[i][:conn].established?
            log.debug "connection established for reconnecting node"

            oldconn = @nodes[i]
            @nodes[i] = reconnectings[i][:conn]

            if reconnectings[i][:reason] == :dead
              log.warn "recovered connection to dead node: #{nodes[i].host}"
            end

            log.trace "old connection shutting down"
            oldconn.detach! if oldconn # connection object doesn't raise any exceptions
            log.trace "old connection shutted down"

            reconnectings[i] = nil
            next
          end

          # not connected yet

          next if reconnectings[i][:at] + @established_timeout > Time.now

          # not connected yet, and timeout
          timeout_conn = reconnectings[i][:conn]
          log.debug "SSL connection is not established until timemout", host: timeout_conn.host, port: timeout_conn.port, timeout: @established_timeout
          reconnectings[i] = nil
          timeout_conn.detach! if timeout_conn # connection object doesn't raise any exceptions
        end
      end
    end

    def shutdown
      super

      @nodewatcher.kill
      @nodewatcher.join

      @nodes.each do |node|
        node.detach!
        node.join
      end
    end

    def write_objects(tag, es)
      node = select_node || select_node(true)
      unless node
        raise "no one nodes with valid ssl session"
      end
      log.trace "selected node", host: node.host, port: node.port, standby: node.standby

      begin
        send_data(node, tag, es)
        node.release!
      rescue Errno::EPIPE, IOError, OpenSSL::SSL::SSLError => e
        log.warn "Failed to send messages to #{node.host}, parging.", error_class: e.class, error: e
        node.release!
        node.detach!

        raise # to retry #write_objects
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
  end
end
