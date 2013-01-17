Gem::Specification.new do |s|
  s.name = 'krypt-core-java'
  s.version = '0.0.1'
  s.author = 'Hiroshi Nakamura, Martin Bosslet'
  s.email = 'Martin.Bosslet@gmail.com'
  s.homepage = 'https://github.com/krypt/krypt-core-java'
  s.summary = 'Java implementation of the krypt-core API'
  s.files = ["Rakefile", "License.txt", "README.rdoc", "Manifest.txt", "lib/kryptcore.jar"] + Dir.glob('{bin,lib,spec,test}/**/*')
  s.test_files = Dir.glob('test/**/test_*.rb')
  s.require_path = "lib"
end
