# OPNsense Monitoring Bridge Production Guide

This guide provides best practices for deploying and running the OPNsense Monitoring Bridge in a production environment, ensuring security, scalability, and reliability.

## Deployment Architecture
- **DMZ Deployment**: Deploy the bridge in a DMZ network (e.g., `172.16.216.0/24`) to isolate it from internal networks.
- **Containerization**: Use Docker Compose or Kubernetes for containerized deployment.
- **High Availability**:
  - For Docker, use multiple replicas with a load balancer.
  - For Kubernetes, configure `k8s/deployment.yaml` with replicas and pod disruption budgets.
- **Load Balancer**: Use Nginx (`nginx/nginx.conf`) or an ingress controller for Kubernetes to handle traffic.

## Security Best Practices
- **SSL/TLS**:
  - Use production-grade certificates (e.g., Let’s Encrypt or enterprise CA) in `certs/`.
  - Enforce HTTPS for all API endpoints.
- **Authentication**:
  - Generate a secure `JWT_SECRET_KEY` (at least 32 characters, random).
  - Implement role-based access control (RBAC) in `app/middleware/authentication.py`.
  - Restrict `/emergency/*` endpoints to admin roles.
- **IP Whitelisting**:
  - Set `ALLOWED_IPS` in `.env` to restrict API access to trusted networks (e.g., `172.16.216.0/24`).
- **Rate Limiting**:
  - Configure `RATE_LIMIT_REQUESTS` and `RATE_LIMIT_PERIOD` in `.env` to prevent abuse (e.g., 100 requests per 60 seconds).
- **Firewall Rules**:
  - Configure OPNsense firewall rules to allow traffic to/from the bridge (ports 8443, 3000, 9091).
  - Use `app/services/opnsense_client.py` to manage these rules programmatically.
- **Secrets Management**:
  - Store sensitive data (e.g., `OPNSENSE_API_SECRET`, `SMTP_PASSWORD`) in Kubernetes secrets (`k8s/secret.yaml`) or Docker secrets.
  - Avoid exposing `.env` in version control.

## Scalability
- **Horizontal Scaling**:
  - Increase replicas in `docker-compose.yml` or `k8s/deployment.yaml` based on load.
  - Use a load balancer to distribute traffic.
- **Resource Allocation**:
  - Allocate at least 2 vCPUs and 4GB RAM per instance.
  - Monitor CPU and memory usage via `/monitoring/system-stats`.
- **Database** (if added):
  - If extending with a database, use a managed service (e.g., PostgreSQL) and configure in `.env`.

## Monitoring and Logging
- **Prometheus**:
  - Scrape `/metrics` endpoint (port 8443) as configured in `monitoring/prometheus.yml`.
  - Monitor metrics: `opnsense_active_rules_count`, `opnsense_cpu_usage_percent`, etc.
- **Grafana**:
  - Deploy Grafana with dashboards in `monitoring/grafana/dashboards/`.
  - Access at `http://172.16.216.10:3000`.
- **Nagios**:
  - Use `monitoring/nagios/plugins/check_opnsense_bridge.sh` for health checks.
  - Monitor `/nagios/firewall-rules` and `/nagios/system-health`.
- **PRTG**:
  - Deploy sensors in `monitoring/prtg/sensors/` and monitor `/prtg/firewall-statistics`.
- **Logging**:
  - Logs are stored in `logs/` (e.g., `bridge.log`, `emergency.log`).
  - Configure log rotation in `config/logging.yaml` (10MB per file, 5 backups).
  - Forward logs to a SIEM (e.g., Splunk) using `monitoring/` configurations.

## Emergency Response
- **Automatic Blocking**:
  - The `app/services/cyber_defense.py` service triggers IP blocks if `risk_score > RISK_SCORE_CRITICAL`.
  - Monitor `/emergency/block-ip` and `/emergency/bulk-block` responses in `logs/emergency.log`.
- **Manual Blocking**:
  - Use `scripts/emergency-block.sh` for bulk IP blocking:
    ```bash
    ./scripts/emergency-block.sh attack_ips.txt "DDoS Attack"
    ```
- **Notifications**:
  - Configure `SMTP_*`, `SLACK_*`, and `TEAMS_*` in `.env` for emergency alerts.
  - Test notifications with `TEST_MODE=true` and `TEST_EMAIL_RECIPIENT`.

## Backup and Recovery
- **Backups**:
  - Run `scripts/backup-config.sh` to back up `config/`, `certs/`, and `.env`.
  - Schedule daily backups:
    ```bash
    0 0 * * * /opt/opnsense-monitoring-bridge/scripts/backup-config.sh
    ```
- **Recovery**:
  - Restore `.env` and `config/` from backups.
  - Redeploy using `docker-compose up -d` or `kubectl apply -f k8s/`.

## Health Checks
- Use `/health` for load balancer checks (public endpoint).
- Monitor `/health/detailed` for OPNsense connectivity (requires JWT).
- Run `scripts/health-check.sh` for automated checks:
  ```bash
  ./scripts/health-check.sh
  ```

## Performance Tuning
- **API Performance**:
  - Optimize `OPNSENSE_API_TIMEOUT` and `OPNSENSE_API_RETRIES` in `.env`.
  - Use async endpoints in `app/routes/` for high throughput.
- **Resource Limits**:
  - Set CPU and memory limits in `docker-compose.yml` or `k8s/deployment.yaml`.
- **Caching** (optional):
  - Implement caching in `app/middleware/` for frequently accessed endpoints (e.g., `/monitoring/status`).

## Troubleshooting
- Check `logs/bridge.log` and `logs/emergency.log` for errors.
- Verify OPNsense API connectivity with `scripts/test-api.sh`.
- Refer to `docs/troubleshooting/common_issues.md` for solutions.