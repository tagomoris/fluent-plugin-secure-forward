# -*- coding: utf-8 -*-

require 'fluent/mixin/config_placeholders'

module Fluent
  class SecureForwardInput < Input
  end
end

require_relative 'input_session'

module Fluent
  class SecureForwardInput < Input
    DEFAULT_SECURE_LISTEN_PORT = 24284

    Fluent::Plugin.register_input('secure_forward', self)

    config_param :self_hostname, :string
    include Fluent::Mixin::ConfigPlaceholders

    config_param :shared_key, :string

    config_param :bind, :string, :default => '0.0.0.0'
    config_param :port, :integer, :default => DEFAULT_SECURE_LISTEN_PORT
    config_param :allow_keepalive, :bool, :default => true #TODO: implement

    config_param :allow_anonymous_source, :bool, :default => true
    config_param :authentication, :bool, :default => false

    ## meaningless for security...? not implemented yet
    # config_param :dns_reverse_lookup_check, :bool, :default => false

    config_param :cert_auto_generate, :bool, :default => false
    config_param :generate_private_key_length, :integer, :default => 2048

    config_param :generate_cert_country, :string, :default => 'US'
    config_param :generate_cert_state, :string, :default => 'CA'
    config_param :generate_cert_locality, :string, :default => 'Mountain View'
    config_param :generate_cert_common_name, :string, :default => nil

    config_param :cert_file_path, :string, :default => nil
    config_param :private_key_file, :string, :default => nil
    config_param :private_key_passphrase, :string, :default => nil

    config_param :read_length, :size, :default => 8*1024*1024 # 8MB
    config_param :read_interval_msec, :integer, :default => 50 # 50ms
    config_param :socket_interval_msec, :integer, :default => 200 # 200ms

    attr_reader :read_interval, :socket_interval

    attr_reader :users # list of (username, password) by <user> tag
    # <user>
    #   username ....
    #   password ....
    # </user>
    attr_reader :nodes # list of hosts, allowed to connect <server> tag (it includes source ip, shared_key(optional))
    # <client>
    #   host ipaddr/hostname
    #   shared_key .... # optional shared key
    #   users username,list,of,allowed
    # </client>

    attr_reader :sessions # node/socket/thread list which has sslsocket instance keepaliving to client

    def initialize
      super
      require 'socket'
      require 'openssl'
      require 'digest'
    end

    # Define `log` method for v0.10.42 or earlier
    unless method_defined?(:log)
      define_method("log") { $log }
    end

    def configure(conf)
      super

      unless @cert_auto_generate || @cert_file_path
        raise Fluent::ConfigError, "One of 'cert_auto_generate' or 'cert_file_path' must be specified"
      end

      @read_interval = @read_interval_msec / 1000.0
      @socket_interval = @socket_interval_msec / 1000.0

      @users = []
      @nodes = []
      conf.elements.each do |element|
        case element.name
        when 'user'
          unless element['username'] && element['password']
            raise Fluent::ConfigError, "username/password pair missing in <user>"
          end
          @users.push({
              username: element['username'],
              password: element['password']
            })
        when 'client'
          unless element['host']
            raise Fluent::ConfigError, "host missing in <client>"
          end
          @nodes.push({
              host: element['host'],
              shared_key: (element['shared_key'] || @shared_key),
              users: (element['users'] ? element['users'].split(',') : nil),
            })
        else
          raise Fluent::ConfigError, "unknown config tag name"
        end
      end

      @generate_cert_common_name ||= @self_hostname
      self.certificate
      true
    end

    def start
      super
      OpenSSL::Random.seed(File.read("/dev/urandom", 16))
      @sessions = []
      @sock = nil
      @listener = Thread.new(&method(:run))
    end

    def shutdown
      @listener.kill
      @listener.join
      @sessions.each{ |s| s.shutdown }
      @sock.close
    end

    def select_authenticate_users(node, username)
      if node.nil? || node[:users].nil?
        @users.select{|u| u[:username] == username}
      else
        @users.select{|u| node[:users].include?(u[:username]) && u[:username] == username}
      end
    end

    def certificate
      return @cert, @key if @cert && @key

      if @cert_auto_generate
        key = OpenSSL::PKey::RSA.generate(@generate_private_key_length)

        digest = OpenSSL::Digest::SHA1.new
        issuer = subject = OpenSSL::X509::Name.new
        subject.add_entry('C', @generate_cert_country)
        subject.add_entry('ST', @generate_cert_state)
        subject.add_entry('L', @generate_cert_locality)
        subject.add_entry('CN', @generate_cert_common_name)

        cer = OpenSSL::X509::Certificate.new
        cer.not_before = Time.at(0)
        cer.not_after = Time.at(0)
        cer.public_key = key
        cer.serial = 1
        cer.issuer = issuer
        cer.subject  = subject
        cer.sign(key, digest)

        @cert = cer
        @key = key
        return @cert, @key
      end

      @cert = OpenSSL::X509::Certificate.new(File.read(@cert_file_path))
      @key = OpenSSL::PKey::RSA.new(File.read(@private_key_file), @private_key_passphrase)
    end

    def run # sslsocket server thread
      log.trace "setup for ssl sessions"
      cert, key = self.certificate
      ctx = OpenSSL::SSL::SSLContext.new
      ctx.cert = cert
      ctx.key = key

      log.trace "start to listen", :bind => @bind, :port => @port
      server = TCPServer.new(@bind, @port)
      log.trace "starting SSL server", :bind => @bind, :port => @port
      @sock = OpenSSL::SSL::SSLServer.new(server, ctx)
      @sock.start_immediately = false
      begin
        log.trace "accepting sessions"
        loop do
          while socket = @sock.accept
            log.trace "accept tcp connection (ssl session not established yet)"
            @sessions.push Session.new(self, socket)
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
        Fluent::Engine.emit_stream(tag, es)

      elsif entries.class == Array
        # Forward
        es = Fluent::MultiEventStream.new
        entries.each {|e|
          time = e[0].to_i
          time = (now ||= Fluent::Engine.now) if time == 0
          record = e[1]
          es.add(time, record)
        }
        Fluent::Engine.emit_stream(tag, es)

      else
        # Message
        time = msg[1]
        time = Fluent::Engine.now if time == 0
        record = msg[2]
        Fluent::Engine.emit(tag, time, record)
      end
    end
  end
end
