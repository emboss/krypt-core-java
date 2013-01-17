require 'rake'
require 'rake/testtask'
require 'rspec/core/rake_task'
require 'ant'

KRYPT_HOME = '../krypt'

# TODO: update
MANIFEST = FileList["Rakefile", "Manifest.txt", "README.rdoc", "LICENSE", "lib/**/*", "spec/**/*"]
File.open("Manifest.txt", "w") {|f| MANIFEST.each {|n| f.puts n } }

task :default => [:build, :spec]

file "lib/kryptcore.jar" => :build

desc "Delete artifact files"
task :clean do
  rm_f FileList['lib/kryptcore.jar']
  ant :clean
end

RSpec::Core::RakeTask.new(:spec) do |spec|
  spec.ruby_opts = ['--1.9']
  spec.pattern = File.join(KRYPT_HOME, 'spec/**/*_spec.rb')
  spec.fail_on_error = false
end

task :pre_coverage do
  ant 'coverage-jar'
end

task :post_coverage do
  ant 'coverage-report'
end

desc "Create coverage report of spec run"
task :coverage => [:clean, :pre_coverage, :spec, :post_coverage]

desc "Build a JAR file"
task :build do
  ant 'jar'
end

task :java_compile => :build
