# PRTG Integration

The OPNsense Monitoring Bridge provides PRTG-compatible endpoints for monitoring OPNsense firewall metrics and system health. This document explains how to configure PRTG to integrate with the bridge.

## Table of Contents
- [Overview](#overview)
- [Endpoints](#endpoints)
- [PRTG Configuration](#prtg-configuration)
- [Troubleshooting](#troubleshooting)

## Overview
The bridge exposes PRTG endpoints at `/prtg/*`, returning data in XML format compatible with PRTG sensors. These endpoints provide metrics such as CPU usage, memory usage, and firewall statistics, accessible at `https://<BRIDGE_IP>:<BRIDGE_PORT>/prtg/*` (e.g., `https://172.16.216.10:8443/prtg/system-health`).

## Endpoints
- `/prtg/system-health`: Returns system metrics (CPU, memory, disk, uptime).
  - Example: `<prtg><result><channel>CPU Usage</channel><value>45.6</value></result>...</prtg>`
- `/prtg/firewall-statistics`: Returns firewall metrics (blocked events, active rules).
  - Example: `<prtg><result><channel>Blocked Events</channel><value>1234</value></result>...</prtg>`

See [API Documentation](../api/endpoints.md) for full endpoint details.

## PRTG Configuration
1. **Add a Sensor in PRTG**:
   - In PRTG, create a new HTTP XML/REST Value Sensor.
   - Set the URL to `https://<BRIDGE_IP>:<BRIDGE_PORT>/prtg/system-health` (e.g., `https://172.16.216.10:8443/prtg/system-health`).
   - Enable "Use SSL" and disable certificate verification if using self-signed certificates (`SSL_VERIFY_PEER=false` in `.env`).

2. **Configure Channels**:
   - Map XML channels (e.g., `CPU Usage`, `Memory Usage`) to PRTG channels.
   - Set thresholds based on `.env` values:
     ```plaintext
     CPU_WARNING_THRESHOLD=80
     CPU_CRITICAL_THRESHOLD=95
     MEMORY_WARNING_THRESHOLD=85
     MEMORY_CRITICAL_THRESHOLD=95
     ```

3. **Add Firewall Statistics Sensor**:
   - Create another sensor for `/prtg/firewall-statistics`.
   - Configure channels for `Blocked Events`, `Active Rules`, etc.
   - Set thresholds:
     ```plaintext
     BLOCKED_EVENTS_WARNING=1000
     BLOCKED_EVENTS_CRITICAL=5000
     ```

4. **Test Connectivity**:
   ```bash
   curl -k https://172.16.216.10:8443/prtg/system-health
   ```

## Troubleshooting
- **Invalid XML Response**: Ensure the endpoint is accessible and returns valid XML (`curl -k https://172.16.216.10:8443/prtg/system-health`).
- **SSL Errors**: Verify `SSL_VERIFY_PEER=false` in `.env` or use valid CA-issued certificates.
- **No Data**: Check `logs/bridge.log` for errors:
  ```bash
  tail -f logs/bridge.log
  ```
- **Test Script**: Run `scripts/test-api.sh` to verify endpoint functionality:
  ```bash
  ./scripts/test-api.sh
  ```

For additional configuration, see [Configuration Guide](../../deployment/configuration.md).