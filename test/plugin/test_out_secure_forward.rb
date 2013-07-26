require 'helper'

class SecureForwardOutputTest < Test::Unit::TestCase
  CONFIG = %[
]

  def create_driver(conf=CONFIG,tag='test')
    Fluent::Test::OutputTestDriver.new(Fluent::SecureForwardOutput, tag).configure(conf)
  end
end
