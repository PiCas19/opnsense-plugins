# Nagios Integration

The OPNsense Monitoring Bridge provides Nagios-compatible endpoints for monitoring OPNsense firewall metrics and system health. This document outlines how to configure Nagios to integrate with the bridge.

## Table of Contents
- [Overview](#overview)
- [Endpoints](#endpoints)
- [Nagios Configuration](#nagios-configuration)
- [Troubleshooting](#troubleshooting)

## Overview
The bridge exposes Nagios endpoints at `/nagios/*`, returning data in a format compatible with Nagios plugins (e.g., `OK - Firewall rules retrieved|rules=2`). These endpoints are accessible at `https://<BRIDGE_IP>:<BRIDGE_PORT>/nagios/*` (e.g., `https://172.16.216.10:8443/nagios/system-health`).

## Endpoints
- `/nagios/system-health`: Returns system metrics (CPU, memory, disk).
  - Example: `OK - System health retrieved|cpu_usage=45.6;80;95 memory_usage=60.2;85;95`
- `/nagios/firewall-rules`: Returns firewall rule status.
  - Example: `OK - Firewall rules retrieved|rules=2;5;2`

See [API Documentation](../api/endpoints.md) for full endpoint details.

## Nagios Configuration
1. **Define a Nagios Command**:
   Add the following to your Nagios commands configuration (e.g., `/etc/nagios/objects/commands.cfg`):
   ```plaintext
   define command {
       command_name    check_opnsense_bridge
       command_line    $USER1$/check_http -H $HOSTADDRESS$ -p $ARG1$ -u $ARG2$ -S --sni -e "HTTP/1.1 200 OK" -w 2 -c 5
   }
   ```

2. **Add a Service Check**:
   Add the following to your Nagios services configuration (e.g., `/etc/nagios/objects/services.cfg`):
   ```plaintext
   define service {
       use                     generic-service
       host_name               opnsense-bridge
       service_description     System Health
       check_command           check_opnsense_bridge!8443!/nagios/system-health
   }
   define service {
       use                     generic-service
       host_name               opnsense-bridge
       service_description     Firewall Rules
       check_command           check_opnsense_bridge!8443!/nagios/firewall-rules
   }
   ```

3. **Set Host Address**:
   Ensure `opnsense-bridge` is defined in `hosts.cfg` with `address 172.16.216.10`.

4. **Test Connectivity**:
   ```bash
   curl -k https://172.16.216.10:8443/nagios/system-health
   ```

## Troubleshooting
- **Invalid Output**: Ensure the endpoint returns Nagios-compatible output (`curl -k https://172.16.216.10:8443/nagios/system-health`).
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