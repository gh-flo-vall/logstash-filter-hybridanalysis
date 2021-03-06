Gem::Specification.new do |s|
  s.name          = 'logstash-filter-hybridanalysis'
  s.version       = '0.1.0'
  s.licenses      = ['Apache License (2.0)']
  s.summary       = 'Logstash filter to query Payload Security Hybrid Analysis'
  s.description   = 'Logstash filter plugin to query Hybrid Analysis. This gem is not a stand-alone program'
  s.homepage      = 'https://github.com/gh-flo-vall/logstash-filter-hybridanalysis/'
  s.authors       = ['gh-flo-vall']
  s.email         = ''
  s.require_paths = ['lib']

  # Files
  s.files = Dir['lib/**/*','spec/**/*','vendor/**/*','*.gemspec','*.md','CONTRIBUTORS','Gemfile','LICENSE','NOTICE.TXT']
   # Tests
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = { "logstash_plugin" => "true", "logstash_group" => "filter" }

  # Gem dependencies
  s.add_runtime_dependency "logstash-core-plugin-api", "~> 2.0"
  s.add_development_dependency 'logstash-devutils'
end
