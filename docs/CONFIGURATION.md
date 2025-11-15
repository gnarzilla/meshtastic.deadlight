```ini

[core]
#Listen port for proxy connections
port=8080
#IP address to bind to
bind_address=0.0.0.0
#Maximum concurrent connections
max_connections=500
#Connection timeout in seconds
connection_timeout=30
#Buffer size for data transfer
buffer_size=65536
#Log level: error, warning, info, debug
log_level=info
#Log file path (empty for stdout)
log_file=
#Number of worker threads
worker_threads=4

[ssl]
#Enable SSL interception
enabled=true
#CA certificate file
ca_cert_file=/etc/deadlight/ca.crt
#CA private key file
ca_key_file=/etc/deadlight/ca.key
#Certificate cache directory
cert_cache_dir=/tmp/deadlight_certs
#Maximum cached certificates
cert_cache_size=1000
#Generated certificate validity period
cert_validity_days=30
#Allowed cipher suites
cipher_suites=HIGH:!aNULL:!MD5
#Allowed SSL/TLS protocols
protocols=TLSv1.2,TLSv1.3

[protocols]
#Enable HTTP support
http_enabled=true
#Enable HTTPS support
https_enabled=true
#Enable SOCKS4 support
socks4_enabled=true
#Enable SOCKS5 support
socks5_enabled=true
#Enable HTTP CONNECT support
connect_enabled=true
#Enable IMAP support
imap_enabled=true
#Enable IMAPS support
imaps_enabled=true
#Enable SMTP support
smtp_enabled=true
#Protocol detection timeout
protocol_detection_timeout=5

[network]
#Upstream connection timeout
upstream_timeout=30
#Keep-alive timeout
keepalive_timeout=300
#DNS resolution timeout
dns_timeout=5
#Custom DNS servers (comma-separated)
dns_servers=
#Enable IPv6 support
ipv6_enabled=true
#Enable TCP_NODELAY
tcp_nodelay=true
#Enable TCP keepalive
tcp_keepalive=true

[plugins]
#Enable plugin system
enabled=true
#Plugin directory
plugin_dir=/usr/lib/deadlight/plugins
#Auto-load plugins
autoload=adblocker,logger,stats
#Enable built-in plugins
builtin_enabled=true

[plugin.adblocker]
#Enable ad blocker
enabled=true
#Blocklist URL
blocklist_url=https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
#Local blocklist file
blocklist_file=/var/cache/deadlight/blocklist.txt
#Blocklist update interval (seconds)
update_interval=86400
#Custom blocking rules file
custom_rules=

[plugin.logger]
#Enable request logging
enabled=true
#Log HTTP requests
log_requests=true
#Log HTTP responses
log_responses=false
#Log format: combined, common, json
log_format=combined
#Access log file
log_file=/var/log/deadlight/access.log
#Maximum log file size
max_log_size=100MB
#Log rotation: daily, weekly, size
log_rotation=daily

[plugin.stats]
#Enable statistics collection
enabled=true
#Statistics update interval
stats_interval=60
#Statistics history size (minutes)
history_size=1440
#Enable web statistics interface
web_interface=true
#Web interface port
web_port=8081

[plugin.auth]
#Enable authentication
enabled=false
#Authentication type: basic, digest
auth_type=basic
#Authentication file
auth_file=/etc/deadlight/users.txt
#Authentication realm
auth_realm=Deadlight Proxy
#Require authentication for all requests
require_auth=false

[cache]
#Enable response caching
enabled=true
#Cache directory
cache_dir=/tmp/deadlight_cache
#Maximum cache size
max_cache_size=1GB
#Default cache TTL (seconds)
default_ttl=3600
#Cacheable HTTP methods
cache_methods=GET,HEAD
#Cacheable response codes
cache_responses=200,301,302,404

[security]
#Add security headers
enable_security_headers=true
#Block requests to private IPs
block_private_ips=false
#Allowed domains (whitelist)
allowed_domains=
#Blocked domains (blacklist)
blocked_domains=
#Maximum request size
max_request_size=10MB
```
#Maximum header size
max_header_size=8KB

