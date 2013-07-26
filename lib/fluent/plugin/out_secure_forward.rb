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

      $log.debug "starting secure-forward"
      OpenSSL::Random.seed(File.read("/dev/urandom", 16))
      $log.debug "start to connect target nodes"
      @nodes.each do |node|
        $log.debug "connecting node", :host => node.host, :port => node.port
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
  end
end
