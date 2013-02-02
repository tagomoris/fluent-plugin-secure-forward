# -*- coding: utf-8 -*-

require 'fluent/mixin/config_placeholders'
require_relative './secure_forward/node'

def example
  require 'socket'
  require 'openssl'
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

  # http://doc.ruby-lang.org/ja/1.9.3/class/OpenSSL=3a=3aSSL=3a=3aSSLSocket.html
  soc = TCPSocket.new('www.example.com', 443)
  context = OpenSSL::SSL::SSLContext.new(...) # to read ca cert file
  ssl = OpenSSL::SSL::SSLSocket.new(soc, context)
  ssl.connect
  ssl.post_connection_check('www.example.com')
  raise "verification error" if ssl.verify_result != OpenSSL::X509::V_OK
  ssl.write('hoge')
  print ssl.peer_cert.to_text
  ssl.close
  soc.close
end

module Fluent
  class SecureForwardInput < Input
    DEFAULT_SECURE_LISTEN_PORT = 24284

    Fluent::Plugin.register_input('secure_forward', self)

    config_param :self_hostname, :string, :default => nil
    include Fluent::Mixin::ConfigPlaceholders

    config_param :bind, :string, :default => '0.0.0.0'
    config_param :port, :integer, :default => DEFAULT_SECURE_LISTEN_PORT
    config_param :allow_keepalive, :bool, :default => true

    config_param :allow_anonymous_source, :bool, :default => true
    config_param :check_password, :bool, :default => false
    config_param :dns_reverse_lookup_check, :bool, :default => false

    config_param :cert_file_path, :string
    config_param :private_key_file, :string
    config_param :private_key_passphrase, :string, :default => nil

    attr_reader :users # list of (username, password) by <user> tag
    attr_reader :nodes # list of hosts, allowed to connect <node> tag

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
