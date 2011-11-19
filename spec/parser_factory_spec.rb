require 'java'
$CLASSPATH << File.expand_path('../dist/asn1pull-java.jar', File.dirname(__FILE__))
java_import 'org.jruby.ext.krypt.asn1.ParserFactory'
java_import 'org.jruby.ext.krypt.asn1.parser.PullHeaderParser'

describe "ParserFactory" do 
  it "can be instanciated" do 
    ParserFactory.new.should be_an_instance_of ParserFactory
  end

  describe "instance" do
    subject {
      ParserFactory.new
    }

    it "creates PullHeaderParser" do 
      subject.newHeaderParser.should be_an_instance_of  PullHeaderParser
    end
  end
end
