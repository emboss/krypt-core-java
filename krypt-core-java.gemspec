version = '0.0.1'

Gem::Specification.new do |s|

  s.name = 'krypt-core'
  s.version = version
  
  s.author = 'Hiroshi Nakamura, Martin Bosslet'
  s.email = 'Martin.Bosslet@gmail.com'
  s.homepage = 'https://github.com/krypt/krypt-core-java'
  s.summary = 'krypt-core API for JRuby'
  s.description = 'Java implementation of the krypt-core API'
  s.required_ruby_version     = '>= 1.9.3'

  s.files = ["Rakefile", "LICENSE", "README.rdoc", "Manifest.txt", "lib/kryptcore.jar"] + Dir.glob('{bin,lib,spec,test}/**/*')
  s.test_files = Dir.glob('test/**/test_*.rb')
  s.require_path = "lib"
  s.license = 'MIT'

  s.platform = 'universal-java'
  s.add_dependency 'krypt-provider-jdk', version

end
