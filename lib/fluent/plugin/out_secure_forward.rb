# -*- coding: utf-8 -*-

require 'fluent/mixin/config_placeholders'

module Fluent
  class SecureForwardOutput < ObjectBufferedOutput
    Fluent::Plugin.register_output('secure_forward', self)

    config_param :self_hostname, :string, :default => nil
    include Fluent::Mixin::ConfigPlaceholders

    config_param :shared_key, :string

    config_param :keepalive, :time, :default => 3600 # 0 means disable keepalive

    config_param :send_timeout, :time, :default => 60
    config_param :hard_timeout, :time, :default => 60
    config_param :expire_dns_cache, :time, :default => 0 # 0 means disable cache

    config_param :allow_self_signed_certificate, :bool, :default => false
    config_param :cert_file_path, :string, :default => nil # comma delimited
    # in <server>
    # config_param :username, :string, :default => nil
    # config_param :password, :string, :default => nil

    attr_reader :servers

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
      # http://doc.ruby-lang.org/ja/1.9.3/class/OpenSSL=3a=3aSSL=3a=3aSSLContext.html
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
  end
end
