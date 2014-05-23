require 'rubygems'
require 'bundler'
begin
  Bundler.setup(:default, :development)
rescue Bundler::BundlerError => e
  $stderr.puts e.message
  $stderr.puts "Run `bundle install` to install missing gems"
  exit e.status_code
end
require 'test/unit'

$LOAD_PATH.unshift(File.join(File.dirname(__FILE__), '..', 'lib'))
$LOAD_PATH.unshift(File.dirname(__FILE__))
require 'fluent/test'

$log = Fluent::Log.new(Fluent::Test::DummyLogDevice.new, Fluent::Log::LEVEL_INFO)

require 'fluent/plugin/in_secure_forward'
require 'fluent/plugin/out_secure_forward'

class DummySocket
  attr_accessor :sync
end

class DummyInputPlugin
  attr_reader :log, :users, :nodes, :authentication, :allow_anonymous_source, :allow_keepalive
  attr_reader :shared_key, :self_hostname
  attr_reader :read_length, :read_interval, :socket_interval

  attr_reader :data

  def initialize(opts={})
    @log = $log
    @users = opts.fetch(:users, [])
    @nodes = opts.fetch(:nodes, [])
    @authentication = opts.fetch(:authentication, false)
    @allow_anonymous_source = opts.fetch(:allow_anonymous_source, true)
    @allow_keepalive = opts.fetch(:allow_keepalive, true)
    @shared_key = opts.fetch(:shared_key, 'shared key')
    @self_hostname = opts.fetch(:self_hostname, 'hostname.local')
    @read_length = opts.fetch(:read_length, 8*1024*1024)
    @read_interval = opts.fetch(:read_interval, 0.05)
    @socket_interval = opts.fetch(:socket_interval, 0.2)

    @data = []
  end

  def select_authenticate_users(node, username)
    if node.nil? || node[:users].nil?
      self.users.select{|u| u[:username] == username}
    else
      self.users.select{|u| node[:users].include?(u[:username]) && u[:username] == username}
    end
  end

  def on_message(data)
    raise NotImplementedError
  end
end

class DummyOutputPlugin
end


class Test::Unit::TestCase
end
