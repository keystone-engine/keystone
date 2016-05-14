# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'keystone/version'

Gem::Specification.new do |spec|
  spec.name          = "keystone"
  spec.version       = Keystone::VERSION
  spec.authors       = ["Sascha Schirra"]
  spec.email         = ["sashs@scoding.de"]
  spec.license       = 'GPL-2.0'
  spec.summary       = %q{Ruby binding for Keystone}
  spec.description   = %q{Ruby binding for Keystone <Keystone-engine.org>}
  spec.homepage      = "https://keystone-engine.org"

  spec.files         = Dir["lib/keystone/*.rb"] + Dir["ext/keystone.c"] + Dir["ext/keystone.h"] + Dir["ext/extconf.rb"]
  spec.require_paths = ["lib","ext"]
  spec.extensions    = ["ext/extconf.rb"]
  spec.add_development_dependency "bundler", "~> 1.11"
  spec.add_development_dependency "rake", "~> 10.0"
end
