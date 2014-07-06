# -*- coding: utf-8 -*-

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

    config_param :self_hostname, :string
    include Fluent::Mixin::ConfigPlaceholders

    config_param :shared_key, :string

    config_param :keepalive, :time, :default => nil # nil/0 means disable keepalive expiration

    config_param :send_timeout, :time, :default => 60
    # config_param :hard_timeout, :time, :default => 60
    # config_param :expire_dns_cache, :time, :default => 0 # 0 means disable cache

    config_param :allow_self_signed_certificate, :bool, :default => true
    config_param :ca_file_path, :string, :default => nil

    config_param :read_length, :size, :default => 512 # 512bytes
    config_param :read_interval_msec, :integer, :default => 50 # 50ms
    config_param :socket_interval_msec, :integer, :default => 200 # 200ms

    config_param :reconnect_interval, :time, :default => 5
    config_param :established_timeout, :time, :default => 10

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

    # Define `log` method for v0.10.42 or earlier
    unless method_defined?(:log)
      define_method("log") { $log }
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
          node = Node.new(self, node_shared_key, element)
          node.first_session = true
          node.keepalive = @keepalive
          @nodes.push node
        else
          raise Fluent::ConfigError, "unknown config tag name #{element.name}"
        end
      end
      @next_node = 0
      @mutex = Mutex.new

      @hostname_resolver = Resolve::Hostname.new(:system_resolver => true)

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

          return n if n && n.established? && (!n.standby || permit_standby)

          tries += 1
        end
        nil
      }
    end

    def start
      super

      log.debug "starting secure-forward"
      OpenSSL::Random.seed(File.read("/dev/urandom", 16))
      log.debug "start to connect target nodes"
      @nodes.each do |node|
        log.debug "connecting node", :host => node.host, :port => node.port
        node.start
      end
      @nodewatcher = Thread.new(&method(:node_watcher))
    end

    def node_watcher
      reconnectings = Array.new(@nodes.size)

      loop do
        sleep @reconnect_interval

        log.trace "in node health watcher"

        (0...(@nodes.size)).each do |i|
          log.trace "node health watcher for #{@nodes[i].host}"

          next if @nodes[i].established? && ! @nodes[i].expired?

          next if reconnectings[i]

          log.info "dead connection found: #{@nodes[i].host}, reconnecting..." unless @nodes[i].established?

          node = @nodes[i]
          log.debug "reconnecting to node", :host => node.host, :port => node.port, :expire => node.expire, :expired => node.expired?

          renewed = node.dup
          begin
            renewed.start
            Thread.pass # to connection thread
            reconnectings[i] = { :conn => renewed, :at => Time.now }
          rescue => e
            log.debug "Some error occured on start of renewed connection", :error_class => e2.class, :error => e2, :host => renewed.host, :port => renewed.port
          end
        end

        (0...(reconnectings.size)).each do |i|
          next unless reconnectings[i]

          if reconnectings[i][:conn].established?
            oldconn = @nodes[i]
            @nodes[i] = reconnectings[i][:conn]
            begin
              oldconn.shutdown
            rescue => e
              log.debug "Some error occured on shutdown of expired connection", :error_class => e.class, :error => e, :host => renewed.host, :port => renewed.port
            end

            reconnectings[i] = nil
            next
          end

          # not connected yet

          next if reconnectings[i][:at] < Time.now + @established_timeout

          # not connected yet, and timeout
          begin
            timeout_conn = reconnectings[i][:conn]
            log.debug "SSL connection is not established until timemout", :host => timeout_conn.host, :port => timeout_conn.port, :timeout => @established_timeout
            reconnectings[i] = nil
            timeout_conn.shutdown
          rescue => e
            log.debug "Some error occured on shutdown of timeout re-connection", :error_class => e.class, :error => e
          end
        end
      end
    end

    def shutdown
      super

      @nodewatcher.kill
      @nodewatcher.join

      @nodes.each do |node|
        node.detach = true
        node.join
      end
    end

    def write_objects(tag, es)
      node = select_node || select_node(true)
      unless node
        raise "no one nodes with valid ssl session"
      end
      log.trace "selected node", :host => node.host, :port => node.port, :standby => node.standby

      begin
        send_data(node, tag, es)
      rescue Errno::EPIPE, IOError, OpenSSL::SSL::SSLError => e
        log.warn "Failed to send messages to #{node.host}, parging.", :error_class => e.class, :error => e
        begin
          node.shutdown
        rescue => e2
          # ignore all errors
        end

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
