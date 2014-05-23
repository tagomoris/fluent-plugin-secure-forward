require 'helper'

class SecureForwardInputTest < Test::Unit::TestCase
  CONFIG = %[

]

  def create_driver(conf=CONFIG,tag='test')
    Fluent::Test::InputTestDriver.new(Fluent::SecureForwardInput).configure(conf)
  end

  def test_configure
    p1 = nil
    assert_nothing_raised { p1 = create_driver(<<CONFIG).instance }
  type secure_forward
  shared_key         secret_string
  self_hostname      server.fqdn.local  # This fqdn is used as CN (Common Name) of certificates
  cert_auto_generate yes                # This parameter MUST be specified
CONFIG
    assert_equal 'secret_string', p1.shared_key
    assert_equal 'server.fqdn.local', p1.self_hostname
    assert p1.cert_auto_generate

    assert_raise(Fluent::ConfigError){ create_driver(<<CONFIG) }
  type secure_forward
  shared_key         secret_string
  self_hostname      server.fqdn.local
  cert_auto_generate yes
  authentication     yes # Deny clients without valid username/password
  <user>
    username tagomoris
    password foobar012
  </user>
  <user>
    password yakiniku
  </user>
CONFIG
    assert_raise(Fluent::ConfigError){ create_driver(<<CONFIG) }
  type secure_forward
  shared_key         secret_string
  self_hostname      server.fqdn.local
  cert_auto_generate yes
  authentication     yes # Deny clients without valid username/password
  <user>
    username tagomoris
    password foobar012
  </user>
  <user>
    username frsyuki
  </user>
CONFIG

    p2 = nil
    assert_nothing_raised { p2 = create_driver(<<CONFIG).instance }
  type secure_forward
  shared_key         secret_string
  self_hostname      server.fqdn.local
  cert_auto_generate yes
  authentication     yes # Deny clients without valid username/password
  <user>
    username tagomoris
    password foobar012
  </user>
  <user>
    username frsyuki
    password yakiniku
  </user>
CONFIG
    assert_equal 2, p2.users.size
    assert_equal 'tagomoris', p2.users[0].username
    assert_equal 'foobar012', p2.users[0].password

    assert_raise(Fluent::ConfigError){ create_driver(<<CONFIG) }
  type secure_forward
  shared_key         secret_string
  self_hostname      server.fqdn.local
  cert_auto_generate     yes
  allow_anonymous_source no  # Allow to accept from nodes of <client>
  <client>
    host 192.168.10.30
    # network address (ex: 192.168.10.0/24) NOT Supported now
  </client>
  <client>
    host localhost
    network 192.168.1.1/32
  </client>
  <client>
    network 192.168.16.0/24
  </client>
CONFIG
    assert_raise(Fluent::ConfigError){ create_driver(<<CONFIG) }
  type secure_forward
  shared_key         secret_string
  self_hostname      server.fqdn.local
  cert_auto_generate     yes
  allow_anonymous_source no  # Allow to accept from nodes of <client>
  <client>
    host 192.168.10.30
    # network address (ex: 192.168.10.0/24) NOT Supported now
  </client>
  <client>
  </client>
  <client>
    network 192.168.16.0/24
  </client>
CONFIG

    p3 = nil
    assert_nothing_raised { p3 = create_driver(<<CONFIG).instance }
  type secure_forward
  shared_key         secret_string
  self_hostname      server.fqdn.local
  cert_auto_generate     yes
  allow_anonymous_source no  # Allow to accept from nodes of <client>
  <client>
    host 192.168.10.30
    # network address (ex: 192.168.10.0/24) NOT Supported now
  </client>
  <client>
    host localhost
    # wildcard (ex: *.host.fqdn.local) NOT Supported now
  </client>
  <client>
    network 192.168.16.0/24
  </client>
CONFIG
    assert (not p3.allow_anonymous_source)
    assert_equal 3, p3.clients.size
    assert_equal '192.168.16.0/24', p3.clients[2].network
    assert_equal 3, p3.nodes.size
    assert_equal IPAddr.new('192.168.10.30'), p3.nodes[0][:address]
    assert_equal IPAddr.new('192.168.16.0/24'), p3.nodes[2][:address]

    p4 = nil
    assert_nothing_raised { p4 = create_driver(<<CONFIG).instance }
  shared_key         secret_string
  self_hostname      server.fqdn.local
  cert_auto_generate     yes
  allow_anonymous_source no  # Allow to accept from nodes of <client>
  authentication         yes # Deny clients without valid username/password
  <user>
    username tagomoris
    password foobar012
  </user>
  <user>
    username frsyuki
    password sukiyaki
  </user>
  <user>
    username repeatedly
    password sushi
  </user>
  <client>
    host 192.168.10.30      # allow all users to connect from 192.168.10.30
  </client>
  <client>
    host  192.168.10.31
    users tagomoris,frsyuki # deny repeatedly from 192.168.10.31
  </client>
  <client>
    host 192.168.10.32
    shared_key less_secret_string # limited shared_key for 192.168.10.32
    users      repeatedly         # and repatedly only
  </client>
CONFIG
    assert_equal ['tagomoris','frsyuki'], p4.nodes[1][:users]
  end
end
