# OPNsense Monitoring Bridge API Examples

This document provides example `curl` commands and expected responses for interacting with the OPNsense Monitoring Bridge API. The examples assume the bridge is running at `https://172.16.216.10:8443` and a valid JWT token is available for authenticated requests.

## Prerequisites
- **JWT Token**: Obtain a JWT token for authenticated endpoints. Example token: `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...`
- **SSL**: Use `-k` flag with `curl` to bypass SSL verification if using self-signed certificates (not recommended for production).
- **Environment**: Ensure `.env` is configured with `OPNSENSE_HOST`, `OPNSENSE_API_KEY`, `OPNSENSE_API_SECRET`, and other required settings.

## Health Check Examples

### Basic Health Check
```bash
curl -k https://172.16.216.10:8443/health
```
**Response**:
```json
{
  "status": "ok",
  "bridge_ip": "172.16.216.10",
  "timestamp": "2025-07-31T11:52:00.123456+00:00"
}
```

### Detailed Health Check
```bash
curl -k -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." https://172.16.216.10:8443/health/detailed
```
**Response**:
```json
{
  "status": "ok",
  "bridge_ip": "172.16.216.10",
  "opnsense_connected": true,
  "system_status": {
    "hostname": "opnsense.example.com",
    "version": "25.7",
    "uptime": "15 days, 3 hours"
  },
  "timestamp": "2025-07-31T11:52:00.123456+00:00"
}
```

## Monitoring Examples

### Get Comprehensive Monitoring Status
```bash
curl -k -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." https://172.16.216.10:8443/monitoring/status
```
**Response**:
```json
{
  "status": "ok",
  "system_stats": {
    "cpu": {"usage_percent": 45.5, "status": "ok"},
    "memory": {"usage_percent": 60.2, "status": "ok"},
    "uptime": {"raw": "15 days, 3 hours", "hours": 363.0},
    "version": "25.7",
    "hostname": "opnsense.example.com"
  },
  "firewall_stats": {
    "total_rules": 50,
    "by_action": {"pass": 30, "block": 20},
    "by_interface": {"wan": 40, "lan": 10},
    "by_protocol": {"tcp": 35, "udp": 15},
    "enabled_vs_disabled": {"enabled": 45, "disabled": 5}
  },
  "timestamp": "2025-07-31T11:52:00.123456+00:00"
}
```

### Get Firewall Rules (Active Only)
```bash
curl -k -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." https://172.16.216.10:8443/monitoring/firewall-rules?active_only=true
```
**Response**:
```json
{
  "status": "ok",
  "rules": [
    {
      "uuid": "123e4567-e89b-12d3-a456-426614174000",
      "enabled": "1",
      "action": "block",
      "interface": "wan",
      "protocol": "tcp",
      "description": "Block malicious IP"
    }
  ],
  "total_rules": 1,
  "timestamp": "2025-07-31T11:52:00.123456+00:00"
}
```

### Get System Statistics
```bash
curl -k -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." https://172.16.216.10:8443/monitoring/system-stats
```
**Response**:
```json
{
  "status": "ok",
  "cpu": {"usage_percent": 45.5, "status": "ok"},
  "memory": {"usage_percent": 60.2, "status": "ok"},
  "uptime": {"raw": "15 days, 3 hours", "hours": 363.0},
  "version": "25.7",
  "hostname": "opnsense.example.com",
  "timestamp": "2025-07-31T11:52:00.123456+00:00"
}
```

## Nagios Integration Examples

### Firewall Rules Check
```bash
curl -k https://172.16.216.10:8443/nagios/firewall-rules
```
**Response**:
```
OK: 50 firewall rules active | rules=50;5;2
```

### System Health Check
```bash
curl -k https://172.16.216.10:8443/nagios/system-health
```
**Response**:
```
OK: System healthy | cpu=45.5%;80;95 memory=60.2%;85;95
```

## PRTG Integration Example

### Firewall Statistics
```bash
curl -k https://172.16.216.10:8443/prtg/firewall-statistics
```
**Response**:
```xml
<prtg>
  <result>
    <channel>Total Rules</channel>
    <value>50</value>
    <unit>Count</unit>
  </result>
  <result>
    <channel>Active Rules</channel>
    <value>45</value>
    <unit>Count</unit>
  </result>
</prtg>
```

## Emergency Response Examples

### Block Single IP
```bash
curl -k -X POST -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -H "Content-Type: application/json" \
  -d '{"ip_address": "1.2.3.4", "reason": "Active attack"}' \
  https://172.16.216.10:8443/emergency/block-ip
```
**Response**:
```json
{
  "status": "success",
  "operation_id": "emergency_dmz_1698765432",
  "rule_uuid": "123e4567-e89b-12d3-a456-426614174000",
  "ip_blocked": "1.2.3.4",
  "applied": true,
  "timestamp": "2025-07-31T11:52:00.123456+00:00"
}
```

### Bulk Block IPs
```bash
curl -k -X POST -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -H "Content-Type: application/json" \
  -d '{"ip_addresses": ["1.2.3.4", "5.6.7.8"], "reason": "DDoS Attack"}' \
  https://172.16.216.10:8443/emergency/bulk-block
```
**Response**:
```json
{
  "status": "completed",
  "operation_id": "bulk_emergency_dmz_1698765432",
  "blocked_ips": [
    {"ip": "1.2.3.4", "rule_uuid": "123e4567-e89b-12d3-a456-426614174000", "timestamp": "2025-07-31T11:52:00.123456+00:00"}
  ],
  "failed_ips": [
    {"ip": "5.6.7.8", "error": "Invalid IP format"}
  ],
  "total_requested": 2,
  "timestamp": "2025-07-31T11:52:00.123456+00:00"
}
```

## Metrics Example

### Prometheus Metrics
```bash
curl -k https://172.16.216.10:8443/metrics
```
**Response**:
```
# HELP opnsense_active_rules_count Number of active firewall rules
# TYPE opnsense_active_rules_count gauge
opnsense_active_rules_count{bridge_ip="172.16.216.10"} 45
# HELP opnsense_blocked_events_total Total blocked events
# TYPE opnsense_blocked_events_total counter
opnsense_blocked_events_total{bridge_ip="172.16.216.10"} 1000
# HELP opnsense_cpu_usage_percent CPU usage percentage
# TYPE opnsense_cpu_usage_percent gauge
opnsense_cpu_usage_percent{bridge_ip="172.16.216.10"} 45.5
# HELP opnsense_memory_usage_percent Memory usage percentage
# TYPE opnsense_memory_usage_percent gauge
opnsense_memory_usage_percent{bridge_ip="172.16.216.10"} 60.2
# HELP opnsense_threat_score Current threat score
# TYPE opnsense_threat_score gauge
opnsense_threat_score{bridge_ip="172.16.216.10"} 25
# HELP opnsense_emergency_blocks_total Total emergency blocks
# TYPE opnsense_emergency_blocks_total counter
opnsense_emergency_blocks_total{bridge_ip="172.16.216.10"} 10
```

## Notes
- **Authentication**: Replace `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...` with a valid JWT token obtained from your authentication system.
- **SSL Verification**: The `-k` flag is used for self-signed certificates. In production, ensure proper SSL certificates are configured (`certs/server.crt`, `certs/server.key`).
- **Error Handling**: Check responses for `"status": "error"` to handle failures appropriately.
- **Rate Limiting**: Be aware of rate limits configured in `.env` (`RATE_LIMIT_REQUESTS`, `RATE_LIMIT_PERIOD`).