require 'krypt'
require 'openssl'
require 'stringio'
require 'pp'
require 'base64'

class Tester
  include Krypt::ASN1::Template::Sequence

  asn1_integer :version
  asn1_printable_string :text

  def dump
    puts "Version: #{version}"
    puts "Text: #{text}"
  end
end

t = Tester.parse_der("\x30\x06\x02\x01\x01\x13\x01a")
pp t
puts t.version
puts t.text
t.dump
pp t
