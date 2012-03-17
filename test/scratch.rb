require 'krypt'
require 'openssl'
require 'stringio'
require 'pp'
require 'base64'

A = Class.new do
  include Krypt::ASN1::Template::Sequence
  asn1_integer :a
end

B = Class.new do
  include Krypt::ASN1::Template::Sequence
  asn1_boolean :a
end

C = Class.new do
  include Krypt::ASN1::Template::Choice
  asn1_template B, tag: 1, tagging: :EXPLICIT
end

D = Class.new do
  include Krypt::ASN1::Template::Sequence
  asn1_template :b, C, tag: 2, tagging: :EXPLICIT
end

asn1 = D.parse_der "\x30\x09\xA2\x07\xA1\x05\x30\x03\x01\x01\xFF"

p asn1.b.value.a


