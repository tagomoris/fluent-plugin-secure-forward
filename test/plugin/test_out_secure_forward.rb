require 'helper'

class SecureForwardOutputTest < Test::Unit::TestCase
  CONFIG = %[
]

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

end
