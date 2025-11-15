## Common Issues

### "Certificate verification failed"
**Cause**: Client doesn't trust the proxy's CA certificate
**Solution**: Install the CA cert: `sudo cp ~/.deadlight/ca/ca.crt /usr/local/share/ca-certificates/`

### "Connection refused" on IMAP/SMTP
**Cause**: Upstream server not configured
**Solution**: Set `upstream_host` and `upstream_port` in config

### High CPU usage
**Cause**: Too many worker threads or connections
**Solution**: Reduce `worker_threads` or `max_connections` in config
