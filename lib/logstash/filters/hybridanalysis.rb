# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require "json"

# This  filter will replace the contents of the default 
# message field with whatever you specify in the configuration.
#
# It is only intended to be used as an .
class LogStash::Filters::Passivetotal < LogStash::Filters::Base

  config_name "hybridanalysis"
  
  #For apikey and username, report to the page: https://www.passivetotal.org/account_settings 
  config :apikey, :validate => :string, :required => true
  config :secret, :validate => :string, :required => true
  config :field, :validate => :string, :required => true
  #Lookup queries: scan (hash value only), search (host:ip, port:int, domain:string, vxfamily:string, filetype:string, url:string)
  config :lookup, :validate => :string, :default => "scan"
  config :target, :validate => :string, :default => "hybridanalysis"

  public
  def register
    require "faraday"
  end # def register

  public
  def filter(event)
  
    unless apikey =~ /^[a-zA-Z0-9]{25}$/
      @logger.error("API key must be a 25 character alphanumeric string, check: https://www.hybrid-analysis.com/my-account?tab=%23api-key-tab")
      return
    end

    #Full API documentation: https://www.hybrid-analysis.com/apikeys/info
    baseurl = "https://www.hybrid-analysis.com/api/"

    if @lookup == "scan"
      url = "scan/" + event.get(@field)
    elsif @lookup == "search"
      url = "search"
    end
    
    conn = Faraday.new baseurl
    conn.basic_auth(@apikey,@secret) 
    conn.headers[:user_agent] = "VxStream"
    begin
      resp = conn.get url do |req|
	if @lookup == "search"
	  req.params[:query] = event.get(@field)
        end
      end
      if resp.body.length > 2
        result = JSON.parse(resp.body)
        event.set(@target, result)
        filter_matched(event)
      end
    
    rescue Faraday::TimeoutError
      @logger.error("Timeout trying to contact Hybrid-Analysis")

    end

  end # def filter
end # class LogStash::Filters::Passivetotal
