require 'rake'
require 'rake/testtask'

MANIFEST = FileList["Rakefile", "Manifest.txt", "CHANGELOG.txt", "README.txt", "License.txt", "lib/jkrypt.jar", "lib/**/*", "test/**/*"]

task :default => [:java_compile, :test]

def java_classpath_arg # myriad of ways to discover JRuby classpath
  begin
    cpath = Java::java.lang.System.getProperty('java.class.path').split(File::PATH_SEPARATOR)
    cpath += Java::java.lang.System.getProperty('sun.boot.class.path').split(File::PATH_SEPARATOR)
    jruby_cpath = cpath.compact.join(File::PATH_SEPARATOR)
  rescue => e
  end
  unless jruby_cpath
    jruby_cpath = ENV['JRUBY_PARENT_CLASSPATH'] || ENV['JRUBY_HOME'] &&
      FileList["#{ENV['JRUBY_HOME']}/lib/*.jar"].join(File::PATH_SEPARATOR)
  end
  jruby_cpath ? "-cp \"#{jruby_cpath.gsub('\\', '/')}" : ""
end

desc "Compile the native Java code."
task :java_compile do
  mkdir_p "pkg/classes"

  File.open("pkg/compile_options", "w") do |f|
    f << "-g -target 1.5 -source 1.5 -Xlint:unchecked -Xlint:deprecation -d pkg/classes"
  end

  File.open("pkg/compile_classpath", "w") do |f|
    f << java_classpath_arg
  end

  File.open("pkg/compile_sourcefiles", "w") do |f|
    f << FileList['src/java/**/*.java'].join(' ')
  end

  sh "#{ENV['JAVA_HOME']}/bin/javac @pkg/compile_options @pkg/compile_classpath @pkg/compile_sourcefiles"
  sh "#{ENV['JAVA_HOME']}/bin/jar cf lib/jkrypt.jar -C pkg/classes/ ."
end

file "lib/jkrypt.jar" => :java_compile

task :clean do
  rm_f FileList['lib/jkrypt.jar']
end

File.open("Manifest.txt", "w") {|f| MANIFEST.each {|n| f.puts n } }

begin
  require 'hoe'
  Hoe.plugin :gemcutter
  hoe = Hoe.spec("krypt-core-jruby") do |p|
    load File.dirname(__FILE__) + "/lib/jkrypt/version.rb"
    p.version = Jkrypt::Version::VERSION
    p.url = "https://github.com/emboss/krypt-core-jruby"
    p.author = "Hiroshi Nakamura, Martin Bosslet"
    p.email = "Martin.Bosslet@googlemail.com"
    p.summary = "krypt-core API implementation in JRuby"
    p.changes = p.paragraphs_of('CHANGELOG.txt', 0..1).join("\n\n")
    p.description = p.paragraphs_of('README.txt', 3...4).join("\n\n")
    p.test_globs = ENV["TEST"] || ["test/test_all.rb"]
  end
  hoe.spec.dependencies.delete_if { |dep| dep.name == "hoe" }

  task :gemspec do
    File.open("#{hoe.name}.gemspec", "w") {|f| f << hoe.spec.to_ruby }
  end
  task :package => :gemspec
rescue LoadError
  puts "You need Hoe installed to be able to package this gem"
rescue => e
  puts "ignoring error while loading hoe: #{e.to_s}"
end

