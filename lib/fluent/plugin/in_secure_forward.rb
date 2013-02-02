# -*- coding: utf-8 -*-

require 'fluent/mixin/config_placeholders'
require_relative './secure_forward/node'

module Fluent
  class SecureForwardInput < Input
    DEFAULT_SECURE_LISTEN_PORT = 24284

    Fluent::Plugin.register_input('secure_forward', self)

    config_param :self_hostname, :string, :default => nil
    include Fluent::Mixin::ConfigPlaceholders

    config_param :bind, :string, :default => '0.0.0.0'
    config_param :port, :integer, :default => DEFAULT_SECURE_LISTEN_PORT

    config_param :password, :string

    config_param :require_authentication, :bool, :default => true
    config_param :allow_anonymous_source, :bool, :default => true
    config_param :allow_raw_password, :bool, :default => true
    config_param :allow_raw_messages, :bool, :default => true

    config_param :allow_keepalive, :bool, :default => true
    config_param :dns_reverse_lookup_check, :bool, :default => false

    # for handshake: RSA public key info
    config_param :known_key_file, :string, :default => nil

    attr_reader :nodes

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
    
  end
end
