# Copyright (c) 2010 ThoughtWorks Inc. (http://thoughtworks.com)
# Licenced under the MIT License (http://www.opensource.org/licenses/mit-license.php)
require File.join(File.dirname(__FILE__), '../test_helper')

module Oauth2
  module Provider
    class ClockTest < Test::Unit::TestCase

      def test_can_fake_now
        Clock.fake_now = Time.utc(2007, 2, 10, 15, 30, 45)
        now = Clock.now
        assert_equal Time.utc(2007, 2, 10, 15, 30, 45), now
      end
  
      def test_can_restore_real_now
        Clock.fake_now = Time.utc(2007, 2, 10, 15, 30, 45)
        Clock.reset
        assert (Clock.now - Time.now) < 1.minute
      end
  
    end
  end
end