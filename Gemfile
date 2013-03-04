source 'https://rubygems.org'

group :development do
  gem 'rake'
  gem 'rake-compiler'
end

group :test do
  gem 'jruby-openssl'
  gem 'rspec'
  gem 'krypt',              :path => File.expand_path('../krypt', File.dirname(__FILE__))
  gem 'krypt-provider-jdk', :path => File.expand_path('../krypt-provider-jdk', File.dirname(__FILE__))
end

gemspec
