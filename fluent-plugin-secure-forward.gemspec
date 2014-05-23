# -*- encoding: utf-8 -*-
Gem::Specification.new do |gem|
  gem.name          = "fluent-plugin-secure-forward"
  gem.version       = "0.1.8"
  gem.authors       = ["TAGOMORI Satoshi"]
  gem.email         = ["tagomoris@gmail.com"]
  gem.summary       = %q{Fluentd input/output plugin to forward over SSL with authentications}
  gem.description   = %q{Message forwarding over SSL with authentication}
  gem.homepage      = "https://github.com/tagomoris/fluent-plugin-secure-forward"
  gem.license       = "APLv2"

  gem.files         = `git ls-files`.split($\)
  gem.executables   = gem.files.grep(%r{^bin/}).map{ |f| File.basename(f) }
  gem.test_files    = gem.files.grep(%r{^(test|spec|features)/})
  gem.require_paths = ["lib"]

  gem.add_runtime_dependency "fluentd", ">= 0.10.46"
  gem.add_runtime_dependency "fluent-mixin-config-placeholders"
  gem.add_runtime_dependency "resolve-hostname"
  gem.add_development_dependency "rake"
end
