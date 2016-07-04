# -*- coding: utf-8 -*-

require 'fluent/input'
require 'fluent/mixin/config_placeholders'

module Fluent
  class SecureForwardInput < Input
  end
end

require_relative 'input_session'
require_relative './secure_forward/cert_util'

module Fluent
  class SecureForwardInput < Input
    DEFAULT_SECURE_LISTEN_PORT = 24284

    Fluent::Plugin.register_input('secure_forward', self)

    config_param :secure, :bool # if secure, cert_path or ca_cert_path required

    config_param :self_hostname, :string
    include Fluent::Mixin::ConfigPlaceholders

    config_param :shared_key, :string, secret: true

    config_param :bind, :string, default: '0.0.0.0'
    config_param :port, :integer, default: DEFAULT_SECURE_LISTEN_PORT
    config_param :allow_keepalive, :bool, default: true #TODO: implement

    config_param :allow_anonymous_source, :bool, default: true
    config_param :authentication, :bool, default: false

    config_param :ssl_version, :string, default: 'TLSv1_2'
    config_param :ssl_ciphers, :string, default: nil

    # Cert signed by public CA
    config_param :cert_path, :string, default: nil
    config_param :private_key_path, :string, default: nil
    config_param :private_key_passphrase, :string, default: nil, secret: true

    # Cert automatically generated and signed by private CA
    config_param :ca_cert_path, :string, default: nil
    config_param :ca_private_key_path, :string, default: nil
    config_param :ca_private_key_passphrase, :string, default: nil, secret: true

    # Otherwise: Cert automatically generated and signed by itself (for without any verification)

    config_param :generate_private_key_length, :integer, default: 2048
    config_param :generate_cert_country, :string, default: 'US'
    config_param :generate_cert_state, :string, default: 'CA'
    config_param :generate_cert_locality, :string, default: 'Mountain View'
    config_param :generate_cert_common_name, :string, default: nil

    config_param :read_length, :size, default: 8*1024*1024 # 8MB
    config_param :read_interval_msec, :integer, default: 50 # 50ms
    config_param :socket_interval_msec, :integer, default: 200 # 200ms

    attr_reader :read_interval, :socket_interval

    config_section :user, param_name: :users do
      config_param :username, :string
      config_param :password, :string, secret: true
    end

    config_section :client, param_name: :clients do
      config_param :host, :string, default: nil
      config_param :network, :string, default: nil
      config_param :shared_key, :string, default: nil, secret: true
      config_param :users, :string, default: nil # comma separated username list
    end
    attr_reader :nodes

    attr_reader :sessions # node/socket/thread list which has sslsocket instance keepaliving to client

    def initialize
      super
      require 'ipaddr'
      require 'socket'
      require 'openssl'
      require 'digest'
      require 'securerandom'
    end

    # Define `log` method for v0.10.42 or earlier
    unless method_defined?(:log)
      define_method("log") { $log }
    end

    # Define `router` method of v0.12 to support v0.10
    unless method_defined?(:router)
      define_method("router") { Fluent::Engine }
    end

    def configure(conf)
      super

      if @secure
        unless @cert_path || @ca_cert_path
          raise Fluent::ConfigError, "cert_path or ca_cert_path required for secure communication"
        end
        if @cert_path
          raise Fluent::ConfigError, "private_key_path required" unless @private_key_path
          raise Fluent::ConfigError, "private_key_passphrase required" unless @private_key_passphrase
          certs = Fluent::SecureForward::CertUtil.certificates_from_file(@cert_path)
          if certs.size < 1
            raise Fluent::ConfigError, "no valid certificates in cert_path: #{@cert_path}"
          end
        else # @ca_cert_path
          raise Fluent::ConfigError, "ca_private_key_path required" unless @ca_private_key_path
          raise Fluent::ConfigError, "ca_private_key_passphrase required" unless @ca_private_key_passphrase
        end
      else
        log.warn "'insecure' mode has vulnerability for man-in-the-middle attacks for clients (output plugins)."
      end

      @read_interval = @read_interval_msec / 1000.0
      @socket_interval = @socket_interval_msec / 1000.0

      @nodes = []

      @clients.each do |client|
        if client.host && client.network
          raise Fluent::ConfigError, "both of 'host' and 'network' are specified for client"
        end
        if !client.host && !client.network
          raise Fluent::ConfigError, "Either of 'host' and 'network' must be specified for client"
        end
        source = nil
        if client.host
          begin
            source = IPSocket.getaddress(client.host)
          rescue SocketError => e
            raise Fluent::ConfigError, "host '#{client.host}' cannot be resolved"
          end
        end
        source_addr = begin
                        IPAddr.new(source || client.network)
                      rescue ArgumentError => e
                        raise Fluent::ConfigError, "network '#{client.network}' address format is invalid"
                      end
        @nodes.push({
            address: source_addr,
            shared_key: (client.shared_key || @shared_key),
            users: (client.users ? client.users.split(',') : nil)
          })
      end

      @generate_cert_common_name ||= @self_hostname

      # To check whether certificates are successfully generated/loaded at startup time
      self.certificate

      true
    end

    def start
      super
      OpenSSL::Random.seed(SecureRandom.random_bytes(16))
      @sessions = []
      @sock = nil
      @listener = Thread.new(&method(:run))
      @listener.abort_on_exception
    end

    def shutdown
      @listener.kill
      @listener.join
      @sessions.each{ |s| s.shutdown }
      @sock.close
    end

    def select_authenticate_users(node, username)
      if node.nil? || node[:users].nil?
        @users.select{|u| u.username == username}
      else
        @users.select{|u| node[:users].include?(u.username) && u.username == username}
      end
    end

    def certificate
      return @cert, @key if @cert && @key

      @client_ca = nil
      if @cert_path
        @key = OpenSSL::PKey::RSA.new(File.read(@private_key_path), @private_key_passphrase)
        certs = Fluent::SecureForward::CertUtil.certificates_from_file(@cert_path)
        @cert = certs.shift
        @client_ca = certs
      elsif @ca_cert_path
        opts = {
          ca_cert_path: @ca_cert_path,
          ca_key_path: @ca_private_key_path,
          ca_key_passphrase: @ca_private_key_passphrase,
          private_key_length: @generate_private_key_length,
          country: @generate_cert_country,
          state: @generate_cert_state,
          locality: @generate_cert_locality,
          common_name: @generate_cert_common_name,
        }
        @cert, @key = Fluent::SecureForward::CertUtil.generate_server_pair(opts)
      else
        opts = {
          private_key_length: @generate_private_key_length,
          country: @generate_cert_country,
          state: @generate_cert_state,
          locality: @generate_cert_locality,
          common_name: @generate_cert_common_name,
        }
        @cert, @key = Fluent::SecureForward::CertUtil.generate_self_signed_server_pair(opts)
      end
      return @cert, @key
    end

    def run # sslsocket server thread
      log.trace "setup for ssl sessions"
      cert, key = self.certificate

      ctx = OpenSSL::SSL::SSLContext.new(@ssl_version)
      if @secure
        # inject OpenSSL::SSL::SSLContext::DEFAULT_PARAMS
        # https://bugs.ruby-lang.org/issues/9424
        ctx.set_params({})

        if @ssl_ciphers
          ctx.ciphers = @ssl_ciphers
        else
          ### follow httpclient configuration by nahi
          # OpenSSL 0.9.8 default: "ALL:!ADH:!LOW:!EXP:!MD5:+SSLv2:@STRENGTH"
          ctx.ciphers = "ALL:!aNULL:!eNULL:!SSLv2" # OpenSSL >1.0.0 default
        end
      end

      ctx.cert = cert
      ctx.key = key
      if @client_ca
        ctx.extra_chain_cert = @client_ca
      end

      log.trace "start to listen", bind: @bind, port: @port
      server = TCPServer.new(@bind, @port)
      log.trace "starting SSL server", bind: @bind, port: @port
      @sock = OpenSSL::SSL::SSLServer.new(server, ctx)
      @sock.start_immediately = false
      begin
        log.trace "accepting sessions"
        loop do
          while socket = @sock.accept
            log.trace "accept tcp connection (ssl session not established yet)"
            @sessions.push Session.new(self, socket)

            # cleanup closed session instance
            @sessions.delete_if(&:closed?)
            log.trace "session instances:", all: @sessions.size, closed: @sessions.select(&:closed?).size
          end
        end
      rescue OpenSSL::SSL::SSLError => e
        raise unless e.message.start_with?('SSL_accept SYSCALL') # signal trap on accept
      end
    end

    def on_message(msg)
      # NOTE: copy&paste from Fluent::ForwardInput#on_message(msg)

      # TODO: format error
      tag = msg[0].to_s
      entries = msg[1]

      if entries.class == String
        # PackedForward
        es = MessagePackEventStream.new(entries, @cached_unpacker)
        router.emit_stream(tag, es)

      elsif entries.class == Array
        # Forward
        es = Fluent::MultiEventStream.new
        entries.each {|e|
          time = e[0].to_i
          time = (now ||= Fluent::Engine.now) if time == 0
          record = e[1]
          es.add(time, record)
        }
        router.emit_stream(tag, es)

      else
        # Message
        time = msg[1]
        time = Fluent::Engine.now if time == 0
        record = msg[2]
        router.emit(tag, time, record)
      end
    end
  end
end
