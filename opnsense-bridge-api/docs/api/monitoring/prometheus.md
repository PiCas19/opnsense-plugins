# Prometheus Integration

The OPNsense Monitoring Bridge exposes Prometheus metrics at the `/metrics` endpoint, enabling integration with Prometheus for real-time monitoring of system and firewall metrics. This document provides instructions for configuring Prometheus to scrape metrics from the bridge.

## Table of Contents
- [Overview](#overview)
- [Configuration](#configuration)
- [Prometheus Setup](#prometheus-setup)
- [Metrics Exposed](#metrics-exposed)
- [Grafana Integration](#grafana-integration)
- [Troubleshooting](#troubleshooting)

## Overview
The bridge exposes Prometheus-compatible metrics when `PROMETHEUS_ENABLED=true` in `.env`. Metrics include CPU usage, memory usage, disk usage, firewall events, and more, namespaced with `PROMETHEUS_NAMESPACE=opnsense_bridge_dmz`. The metrics are served on `PROMETHEUS_PORT` (default: 9090).

## Configuration
1. **Enable Prometheus**:
   Set the following in `.env`:
   ```plaintext
   PROMETHEUS_ENABLED=true
   PROMETHEUS_PORT=9090
   PROMETHEUS_PATH=/metrics
   PROMETHEUS_NAMESPACE=opnsense_bridge_dmz
   ```

2. **Verify Metrics Endpoint**:
   Access `https://<BRIDGE_IP>:<PROMETHEUS_PORT>/metrics` (e.g., `https://172.16.216.10:9090/metrics`) to confirm metrics are exposed.

## Prometheus Setup
1. **Create Prometheus Configuration**:
   Create a `prometheus/prometheus.yml` file:
   ```yaml
   global:
     scrape_interval: 15s
     evaluation_interval: 15s
   scrape_configs:
     - job_name: 'opnsense-bridge'
       metrics_path: /metrics
       static_configs:
         - targets: ['opnsense-bridge:8443']
       scheme: https
       tls_config:
         insecure_skip_verify: true
   ```

2. **Deploy Prometheus**:
   Use the `prometheus` service defined in `docker-compose.yml`:
   ```bash
   docker-compose up -d prometheus
   ```

3. **Verify Prometheus**:
   Access the Prometheus UI at `http://<BRIDGE_IP>:9090` (e.g., `http://172.16.216.10:9090`) and check the targets page to ensure the bridge is being scraped.

## Metrics Exposed
The `/metrics` endpoint exposes the following metrics (namespaced with `opnsense_bridge_dmz_`):
- `cpu_usage_percent`: CPU usage percentage.
- `memory_usage_percent`: Memory usage percentage.
- `disk_usage_percent`: Disk usage percentage.
- `firewall_blocked_events_total`: Total blocked firewall events.
- `api_response_time_seconds`: API response time for OPNsense requests.
- `emergency_blocks_total`: Total emergency IP blocks executed.

Example metric:
```
opnsense_bridge_dmz_cpu_usage_percent 45.6
```

## Grafana Integration
To visualize metrics in Grafana:
1. Add Prometheus as a data source in Grafana:
   - URL: `http://prometheus:9090`
   - Skip TLS verification if using self-signed certificates.
2. Import or create dashboards using the `opnsense_bridge_dmz_` namespace.
3. Configure webhook notifications in `.env` (optional):
   ```plaintext
   GRAFANA_WEBHOOK_ENABLED=true
   GRAFANA_WEBHOOK_URL=https://192.168.216.110:3000/api/alerts/webhook
   GRAFANA_WEBHOOK_TOKEN=your-grafana-api-token
   ```

## Troubleshooting
- **Metrics Not Available**: Ensure `PROMETHEUS_ENABLED=true` and the `/metrics` endpoint is accessible (`curl -k https://172.16.216.10:9090/metrics`).
- **Prometheus Not Scraping**: Verify the `prometheus.yml` configuration and check the Prometheus targets page.
- **SSL Issues**: Set `insecure_skip_verify: true` in `prometheus.yml` if using self-signed certificates.
- **Logs**: Check `logs/bridge.log` for errors:
  ```bash
  tail -f logs/bridge.log
  ```

For additional configuration, see [Configuration Guide](../../deployment/configuration.md).