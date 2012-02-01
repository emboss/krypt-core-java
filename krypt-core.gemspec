Gem::Specification.new do |s|
  s.name = 'krypt-core-jruby'
  s.version = '0.0.1'
  s.author = 'Hiroshi Nakamura, Martin Bosslet'
  s.email = 'Martin.Bosslet@googlemail.com'
  s.homepage = 'https://github.com/emboss/krypt-core-jruby'
  s.summary = 'Java implementation of the krypt-core API'
  s.extensions << 'ext/krypt/core/extconf.rb'
  s.files = ["Rakefile", "License.txt", "README.rdoc", "Manifest.txt"] + Dir.glob('{bin,lib,spec,test}/**/*')
  s.test_files = Dir.glob('test/**/test_*.rb')
  s.require_path = "lib"
end
