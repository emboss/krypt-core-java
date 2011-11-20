require 'krypt-core'
require 'stringio'
require_relative 'resources'

describe Krypt::Asn1::Parser do 
  it "can be instantiated with default constructor" do 
    Krypt::Asn1::Parser.new.should be_an_instance_of Krypt::Asn1::Parser
  end

  it "takes no arguments in its constructor" do
    lambda { Krypt::Asn::Parser.new(Object.new) }.should raise_error
  end

  it "should be reusable for several IOs" do
    parser = Krypt::Asn1::Parser.new
    parser.next(Resources.certificate_io).should_not be_nil
    parser.next(Resources.certificate_io).should_not be_nil
  end

end

describe Krypt::Asn1::Parser, "#next" do

  subject { Krypt::Asn1::Parser.new }

  it "returns a Header when called on an IO representing an ASN.1" do
    parse_next Resources.certificate_io
    parse_next(StringIO.new(Resources.certificate))
  end

  def parse_next(io)
    subject.next(io).should be_an_instance_of Krypt::Asn1::Header
  end

  it "reads nested Headers when called subsequently for constructed values" do
    num_headers = 0
    io = Resources.certificate_io
    parser = Krypt::Asn1::Parser.new
    while header = parser.next(io)
      num_headers += 1
      next if header.constructed?
      header.skip_value #need to consume the values
    end
    num_headers.should > 1
  end 

  it "yields the original contents for the header and the value of the
      initial sequence" do
    cert = Resources.certificate
    io = StringIO.new cert
    parser = Krypt::Asn1::Parser.new
    header = parser.next io
    value = header.value
    (header.header_size + value.size).should == cert.size
    ("" << header.bytes << value).should == cert
  end

  it "yields the original contents for the headers and the values of all
      values" do
    cert = Resources.certificate
    io = StringIO.new cert
    parser = Krypt::Asn1::Parser.new
    out = ""
    while header = parser.next(io)
      out << header.bytes
      next if header.constructed?
      val = header.value
      out << val unless val == nil
    end
    out.should == cert
  end

end

describe Krypt::Asn1::Header do
  
  it "cannot be instantiated" do
    lambda { Krypt::Asn1::Header.new }.should raise_error
  end
  
end

describe Krypt::Asn1::Header, "#skip_value" do

  it "skips to the end of the file when asked to skip the value of a
      starting constructed value" do
    skip_value(StringIO.new(Resources.certificate))
    skip_value Resources.certificate_io
  end

  def skip_value(io)
    parser = Krypt::Asn1::Parser.new
    header = parser.next(io)
    header.skip_value
    parser.next(io).should be_nil
  end

end

describe Krypt::Asn1::Header, "#value" do

  subject { Krypt::Asn1::Parser.new }

  it "caches the value of a header once it was read" do
    header = subject.next Resources.certificate_io
    header.value.should == header.value
  end

  it "raises an error if an IO is requested for a header more than once" do
    io = Resources.certificate_io
    header = subject.next io
    header.value_io
    lambda { header.value_io }.should raise_error
  end

  it "raises an error if the value of a header is requested after requesting
    an IO" do
    io = Resources.certificate_io
    header = subject.next io
    header.value_io
    lambda { header.value }.should raise_error
  end

end

