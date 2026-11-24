# Server configuration (as deployed)

The services behind `by-ai-for-ai.com/api/opus-tplink-mcp/` (field reports) and `kd.by-ai-for-ai.com` (shared
device names), published so the privacy claims can be checked. The server address is replaced by `<server-ip>`.

- `nginx-kd.conf` - `kd.by-ai-for-ai.com`: DNS-only (no CDN), TLS ends on this server. No access log. A rate limit
  kept in memory (20 requests a minute per IP, burst 10); only a client over the limit is written to
  `/var/log/nginx-kd/limit.log`. Only the two endpoints exist; a wrong method gets a 405 that logs nothing.
- `fail2ban-*` - bans an IP that went over the limit 5 times in 10 minutes, for 15 minutes.
- `logrotate-nginx-kd` - the limit log is rotated daily and no old copy is kept.
- `nginx-report-path.conf` - the field-report path (behind the CDN): no access log; the service is given the
  visitor address that nginx's real-IP module verified (trusted only from the CDN's own ranges).
- The service itself is `server/report_server.py` + `server/known_devices_db.py`: it stores no IPs; see their
  docstrings for what is kept.
