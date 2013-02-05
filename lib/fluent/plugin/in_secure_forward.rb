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
    config_param :cert_file_path, :string, :default => nil
    config_param :private_key_file, :string
    config_param :private_key_passphrase, :string, :default => nil

    attr_reader :users # list of (username, password) by <user> tag
    attr_reader :nodes # list of hosts, allowed to connect <node> tag (it includes source ip, shared_key(optional))

    def initialize
      super
      require 'socket'
      require 'openssl'
    end

    def configure(conf)
      super
      #
    end

    def start
      super
      # ...
  end


    end

    def shutdown
      # ...
    end
    
    def run # sslsocket server thread
      # http://doc.ruby-lang.org/ja/1.9.3/class/OpenSSL=3a=3aSSL=3a=3aSSLContext.html
      # http://doc.ruby-lang.org/ja/1.9.3/class/OpenSSL=3a=3aSSL=3a=3aSSLServer.html
      ctx = OpenSSL::SSL::SSLContext.new(...)
      ctx.cert = OpenSSL::X509::Certificate.new(File.read('cert.pem'))
      ctx.key = OpenSSL::PKey::RSA.new(File.read('privkey.pem'))
      svr = TCPServer.new(2007)
      serv = OpenSSL::SSL::SSLServer.new(svr, ctx)
      loop do
      while soc = serv.accept
        puts soc.read
      end
    end

  end
end
