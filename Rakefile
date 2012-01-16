require 'rake'
require 'rake/testtask'
require 'rspec/core/rake_task'

# TODO: update
MANIFEST = FileList["Rakefile", "Manifest.txt", "CHANGELOG.rdoc", "README.rdoc", "License.txt", "lib/kryptcore.jar", "lib/**/*", "spec/**/*"]

task :default => [:java_compile, :spec]

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
    f << FileList['src/**/*.java'].join(' ')
  end

  sh "#{ENV['JAVA_HOME']}/bin/javac @pkg/compile_options @pkg/compile_classpath @pkg/compile_sourcefiles"
  sh "#{ENV['JAVA_HOME']}/bin/jar cf lib/kryptcore.jar -C pkg/classes/ ."
end

file "lib/kryptcore.jar" => :java_compile

task :clean do
  rm_f FileList['lib/kryptcore.jar']
end

File.open("Manifest.txt", "w") {|f| MANIFEST.each {|n| f.puts n } }

RSpec::Core::RakeTask.new(:spec) do |spec|
  spec.ruby_opts = [
    "--1.9", 
    "-J-Demma.coverage.out.file=coverage.ec",
    "-J-Demma.coverage.out.merge=true",
    "-J-Demma.verbosity.level=silent"
  ].join(' ')
end
