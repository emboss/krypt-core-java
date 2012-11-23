
unless defined? JRUBY_VERSION
  warn 'Loading krypt-core-jruby in a non-JRuby interpreter'
end

require 'kryptcore.jar'
require 'krypt-provider-jce'

