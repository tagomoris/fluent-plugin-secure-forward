require 'helper'

class SecureForwardInputTest < Test::Unit::TestCase
  CONFIG = %[
]

  def create_driver(conf=CONFIG,tag='test')
    Fluent::Test::InputTestDriver.new(Fluent::SecureForwardInput, tag).configure(conf)
  end
end
