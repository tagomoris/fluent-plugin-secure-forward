require 'helper'

class SecureForwardOutputTest < Test::Unit::TestCase
  CONFIG = %[
]

  def setup
    Fluent::Test.setup
  end

  def create_driver(conf=CONFIG,tag='test')
    Fluent::Test::OutputTestDriver.new(Fluent::SecureForwardOutput, tag).configure(conf)
  end

  def test_configure_secondary
    p1 = nil
    assert_nothing_raised { p1 = create_driver(<<CONFIG).instance }
  type secure_forward
  shared_key secret_string
  self_hostname client.fqdn.local
  <server>
    host server.fqdn.local  # or IP
    # port 24284
  </server>
  <secondary>
    type forward
    <server>
      host localhost
    </server>
  </secondary>
CONFIG
  end

  def test_configure_standby_server
    p1 = nil
    assert_nothing_raised { p1 = create_driver(<<CONFIG).instance }
  type secure_forward
  shared_key secret_string
  self_hostname client.fqdn.local
  keepalive 1m
  <server>
    host server1.fqdn.local
  </server>
  <server>
    host server2.fqdn.local
    hostlabel server2
  </server>
  <server>
    host server1.fqdn.local
    hostlabel server1
    port 24285
    shared_key secret_string_more
    standby
  </server>
CONFIG
    assert_equal 3, p1.servers.size
    assert_equal 3, p1.nodes.size

    assert_equal 'server1.fqdn.local', p1.nodes[0].host
    assert_equal 'server1.fqdn.local', p1.nodes[0].hostlabel
    assert_equal 24284, p1.nodes[0].port
    assert_equal false, p1.nodes[0].standby
    assert_equal 'secret_string', p1.nodes[0].shared_key
    assert_equal 60, p1.nodes[0].keepalive

    assert_equal 'server2.fqdn.local', p1.nodes[1].host
    assert_equal 'server2', p1.nodes[1].hostlabel
    assert_equal 24284, p1.nodes[1].port
    assert_equal false, p1.nodes[1].standby
    assert_equal 'secret_string', p1.nodes[1].shared_key
    assert_equal 60, p1.nodes[1].keepalive

    assert_equal 'server1.fqdn.local', p1.nodes[2].host
    assert_equal 'server1', p1.nodes[2].hostlabel
    assert_equal 24285, p1.nodes[2].port
    assert_equal true, p1.nodes[2].standby
    assert_equal 'secret_string_more', p1.nodes[2].shared_key
    assert_equal 60, p1.nodes[2].keepalive
  end

  def test_configure_standby_server2
    p1 = nil
    assert_nothing_raised { p1 = create_driver(<<CONFIG).instance }
  type secure_forward
  shared_key secret_string
  self_hostname client.fqdn.local
  num_threads 3
  <server>
    host server1.fqdn.local
  </server>
  <server>
    host server2.fqdn.local
  </server>
  <server>
    host server3.fqdn.local
    standby
  </server>
CONFIG
    assert_equal 3, p1.num_threads
    assert_equal 1, p1.log.logs.select{|line| line =~ /\[warn\]: Too many num_threads for secure-forward:/}.size
  end
end
