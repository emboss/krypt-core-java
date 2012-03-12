require 'krypt'
require 'openssl'
require 'stringio'
require 'pp'
require 'base64'

class A
  include Krypt::ASN1::Template::Sequence

  asn1_boolean :truth
  asn1_integer :number
end

class Tester
  include Krypt::ASN1::Template::Sequence

  asn1_integer :version
  asn1_template :member, A
  asn1_printable_string :text

  def dump
    puts "Version: #{version}"
    puts "Text: #{text}"
    puts "Member: #{member}"
    puts "Member#truth: #{member.truth}"
    puts "Member#number: #{member.number}"
  end
end


t = Tester.parse_der("\x30\x0E\x02\x01\x01\x30\x06\x01\x01\xFF\x02\x01\x03\x13\x01a")
pp t
puts t.version
puts t.text
m = t.member
p m
puts m.truth
t.dump
pp t
