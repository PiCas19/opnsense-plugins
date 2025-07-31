# OPNsense Monitoring Bridge API Endpoints

This document describes the REST API endpoints provided by the OPNsense Monitoring Bridge. All endpoints are served over HTTPS at `https://172.16.216.10:8443` (default configuration) and require JWT authentication unless otherwise specified. Rate limiting and IP whitelisting are enforced as configured in `.env`.

## Base URL
- **URL**: `https://172.16.216.10:8443`
- **Authentication**: JWT token in the `Authorization` header (`Bearer <token>`)
- **Rate Limiting**: Configurable via `RATE_LIMIT_REQUESTS` and `RATE_LIMIT_PERIOD` in `.env`

## Health Endpoints

### GET /health
- **Description**: Basic health check to verify the bridge is operational.
- **Authentication**: None (public endpoint for load balancers).
- **Response**:
  ```json
  {
    "status": "ok",
    "bridge_ip": "172.16.216.10",
    "timestamp": "2025-07-31T11:52:00.123456+00:00"
  }
  ```
- **Error Response** (503 if unhealthy):
  ```json
  {
    "status": "error",
    "message": "Service unhealthy",
    "timestamp": "2025-07-31T11:52:00.123456+00:00"
  }
  ```

### GET /health/detailed
- **Description**: Detailed health check including OPNsense connectivity and system status.
- **Authentication**: JWT required.
- **Response**:
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
- **Error Response** (503 if unhealthy):
  ```json
  {
    "status": "error",
    "message": "OPNsense connection failed",
    "timestamp": "2025-07-31T11:52:00.123456+00:00"
  }
  ```

## Monitoring Endpoints

### GET /monitoring/status
- **Description**: Comprehensive monitoring data including system stats and firewall status.
- **Authentication**: JWT required.
- **Response**:
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
- **Error Response** (500 if data retrieval fails):
  ```json
  {
    "status": "error",
    "message": "Failed to retrieve monitoring data",
    "timestamp": "2025-07-31T11:52:00.123456+00:00"
  }
  ```

### GET /monitoring/firewall-rules
- **Description**: Retrieve firewall rules data (active and inactive).
- **Authentication**: JWT required.
- **Query Parameters**:
  - `active_only` (boolean, optional): If `true`, returns only active rules. Default: `false`.
- **Response**:
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
- **Error Response** (500 if data retrieval fails):
  ```json
  {
    "status": "error",
    "message": "Failed to retrieve firewall rules",
    "timestamp": "2025-07-31T11:52:00.123456+00:00"
  }
  ```

### GET /monitoring/system-stats
- **Description**: Retrieve system statistics (CPU, memory, uptime).
- **Authentication**: JWT required.
- **Response**:
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
- **Error Response** (500 if data retrieval fails):
  ```json
  {
    "status": "error",
    "message": "Failed to retrieve system stats",
    "timestamp": "2025-07-31T11:52:00.123456+00:00"
  }
  ```

## Nagios Integration

### GET /nagios/firewall-rules
- **Description**: Nagios-compatible endpoint for firewall rules check.
- **Authentication**: None (designed for Nagios compatibility).
- **Response** (plain text):
  ```
  OK: 50 firewall rules active | rules=50;5;2
  ```
- **Error Response** (plain text):
  ```
  CRITICAL: Failed to retrieve firewall rules
  ```

### GET /nagios/system-health
- **Description**: Nagios-compatible endpoint for system health check.
- **Authentication**: None (designed for Nagios compatibility).
- **Response** (plain text):
  ```
  OK: System healthy | cpu=45.5%;80;95 memory=60.2%;85;95
  ```
- **Error Response** (plain text):
  ```
  CRITICAL: System unhealthy
  ```

## PRTG Integration

### GET /prtg/firewall-statistics
- **Description**: PRTG-compatible endpoint returning XML sensor data for firewall statistics.
- **Authentication**: None (designed for PRTG compatibility).
- **Response** (XML):
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
- **Error Response** (XML):
  ```xml
  <prtg>
    <error>1</error>
    <text>Failed to retrieve firewall statistics</text>
  </prtg>
  ```

## Emergency Response

### POST /emergency/block-ip
- **Description**: Block a single IP address with a reason.
- **Authentication**: JWT required (admin role).
- **Request Body**:
  ```json
  {
    "ip_address": "1.2.3.4",
    "reason": "Active attack"
  }
  ```
- **Response**:
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
- **Error Response** (400 or 500):
  ```json
  {
    "status": "error",
    "message": "Invalid IP address",
    "timestamp": "2025-07-31T11:52:00.123456+00:00"
  }
  ```

### POST /emergency/bulk-block
- **Description**: Block multiple IP addresses with a reason.
- **Authentication**: JWT required (admin role).
- **Request Body**:
  ```json
  {
    "ip_addresses": ["1.2.3.4", "5.6.7.8"],
    "reason": "DDoS Attack"
  }
  ```
- **Response**:
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
- **Error Response** (400 or 500):
  ```json
  {
    "status": "error",
    "message": "Bulk block limit exceeded",
    "timestamp": "2025-07-31T11:52:00.123456+00:00"
  }
  ```

## Metrics

### GET /metrics
- **Description**: Prometheus-compatible metrics endpoint.
- **Authentication**: None (public for Prometheus scraping).
- **Response** (plain text):
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
- **Error Response** (500 if metrics collection fails):
  ```text
  # HELP opnsense_metrics_error Error collecting metrics
  # TYPE opnsense_metrics_error gauge
  opnsense_metrics_error{bridge_ip="172.16.216.10"} 1
  ```

## Security Considerations
- **JWT Authentication**: Required for all endpoints except `/health`, `/nagios/*`, `/prtg/*`, and `/metrics`. Use `Authorization: Bearer <token>` header.
- **IP Whitelisting**: Configured via `ALLOWED_IPS` in `.env`.
- **Rate Limiting**: Enforced via `RATE_LIMIT_REQUESTS` and `RATE_LIMIT_PERIOD` in `.env`.
- **SSL/TLS**: All endpoints use HTTPS with certificates configured in `certs/`.
- **Role-Based Access**: Emergency endpoints (`/emergency/*`) require admin role.