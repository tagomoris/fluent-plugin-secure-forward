# -*- coding: utf-8 -*-

require 'fluent/mixin/config_placeholders'
require_relative './secure_forward/node'

module Fluent
  class SecureForwardOutput < ObjectBufferedOutput
    Fluent::Plugin.register_output('secure_forward', self)

    config_param :self_hostname, :string, :default => nil
    include Fluent::Mixin::ConfigPlaceholders

    config_param :keepalive, :time, :default => 3600 # 0 means disable keepalive

    config_param :send_timeout, :time, :default => 60
    config_param :hard_timeout, :time, :default => 60
    config_param :expire_dns_cache, :time, :default => 0 # 0 means disable cache

    config_param :cert_file_path, :string
    # in <server>
    # config_param :username, :string, :default => nil
    # config_param :password, :string, :default => nil

    attr_reader :servers

    def initialize
      super
      #
    end

    def configure(conf)
      super
      #
    end

    def start
      super
      # ...
    end

    def shutdown
      # ...
    end

    def emit(tag, es, chain)
      data = es.to_msgpack_stream
      if @buffer.emit(tag, data, chain)
        submit_flush
      end
    end

    def write_objects(tag, es)
      # send data ...
    end

    def send_data(...)
    end
  end
end
