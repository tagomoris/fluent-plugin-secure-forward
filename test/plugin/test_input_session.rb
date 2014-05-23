require 'helper'

require 'fluent/plugin/input_session'

require 'ipaddr'

class InputSessionTest < Test::Unit::TestCase

  def test_check_node
    # def check_node(hostname, ipaddress, port, proto)
    nodes = [
      { address: IPAddr.new('127.0.0.1'), shared_key: 'shared_key', users: ['tagomoris', 'repeatedly'] },
      { address: IPAddr.new('2001:DB8::9'), shared_key: 'shared_key2', users: nil },
      { address: IPAddr.new('127.0.0.0/24'), shared_key: 'shared_key3', users: ['tagomoris', 'repeatedly'] },
    ]
    p1 = DummyInputPlugin.new(nodes: nodes)
    s1 = Fluent::SecureForwardInput::Session.new(p1, DummySocket.new)

    assert s1.check_node('127.0.0.1')
    assert_equal 'shared_key', s1.check_node('127.0.0.1')[:shared_key]

    assert s1.check_node('127.0.0.127')
    assert_equal 'shared_key3', s1.check_node('127.0.0.127')[:shared_key]

    assert_nil s1.check_node('192.0.2.8')
    assert_nil s1.check_node('2001:DB8::8')

    assert s1.check_node('2001:DB8::9')
    assert_equal 'shared_key2', s1.check_node('2001:DB8::9')[:shared_key]
  end

  def test_generate_helo
  end

  def test_check_ping
  end

  def test_generate_pong
  end

  def test_on_read
  end
end
