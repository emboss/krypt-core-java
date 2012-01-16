require 'java'
require 'openssl'
$CLASSPATH << File.expand_path('../../lib/kryptcore.jar', File.dirname(__FILE__))
java_import 'java.io.ByteArrayInputStream'
java_import 'impl.krypt.asn1.ParserFactory'
java_import 'impl.krypt.asn1.ParsedHeader'
java_import 'impl.krypt.asn1.parser.PullHeaderParser'

describe "PullHeaderParser" do 
  subject {
    ParserFactory.new.new_header_parser
  }

  it "returns parsed header" do 
    test = %w{04 03 01 02 03}
    raw = [test.join('')].pack('H*')
    header = subject.next(ByteArrayInputStream.new(raw.to_java_bytes))
    expected = OpenSSL::ASN1.decode(raw)
    String.from_java_bytes(header.value).should == expected.value
    header.parsed_tag.tag.should == expected.tag
  end
end
