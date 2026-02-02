# frozen_string_literal: true

Gem::Specification.new do |spec|
  spec.name          = 'licensecm'
  spec.version       = '1.0.0'
  spec.authors       = ['LicenseCM']
  spec.email         = ['support@licensecm.com']

  spec.summary       = 'Ruby SDK for LicenseCM License Management System'
  spec.description   = 'A comprehensive Ruby SDK for integrating LicenseCM license validation and management into your applications.'
  spec.homepage      = 'https://github.com/licensecm/sdk-ruby'
  spec.license       = 'MIT'
  spec.required_ruby_version = '>= 2.7.0'

  spec.files = Dir['lib/**/*.rb', 'README.md', 'LICENSE']
  spec.require_paths = ['lib']

  spec.add_dependency 'openssl', '~> 3.0'
end
