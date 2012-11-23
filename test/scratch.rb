require 'krypt'
require 'openssl'
require 'stringio'
require 'pp'
require 'base64'

d = Krypt::Digest.new("SHA1")
p d

result = d.hexdigest("test")
p result
