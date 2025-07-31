# Common Issues - OPNsense Monitoring Bridge

This document outlines common issues encountered when deploying or operating the OPNsense Monitoring Bridge, along with their causes and solutions. Refer to `debugging.md` for advanced debugging techniques.

## 1. API Health Check Fails (`/health` Returns Error)
- **Symptoms**: `curl -k https://172.16.216.10:8443/health` returns `{"status": "error", "message": "Service unhealthy"}`.
- **Possible Causes**:
  - OPNsense API is unreachable (`OPNSENSE_HOST` misconfigured or network issue).
  - Incorrect `OPNSENSE_API_KEY` or `OPNSENSE_API_SECRET` in `.env`.
  - SSL certificate issues in `certs/`.
- **Solutions**:
  - Verify `OPNSENSE_HOST`, `OPNSENSE_API_KEY`, and `OPNSENSE_API_SECRET` in `.env`.
  - Test OPNsense API connectivity:
    ```bash
    ./scripts/test-api.sh
    ```
  - Check `logs/bridge.log` for errors (e.g., `ConnectionError` or `401 Unauthorized`).
  - Ensure `certs/server.crt` and `certs/server.key` are valid and properly mounted in Docker/Kubernetes.
  - Confirm network access to OPNsense (e.g., `ping opnsense.example.com` or `curl -k https://opnsense.example.com`).

## 2. Detailed Health Check Fails (`/health/detailed` Returns Error)
- **Symptoms**: `curl -k -H "Authorization: Bearer <token>" https://172.16.216.10:8443/health/detailed` returns `{"status": "error", "message": "OPNsense connection failed"}` or `401 Unauthorized`.
- **Possible Causes**:
  - Invalid or expired JWT token.
  - OPNsense API connectivity issue.
  - Authentication middleware (`app/middleware/authentication.py`) rejecting requests.
- **Solutions**:
  - Generate a new JWT token and verify `JWT_SECRET_KEY` in `.env`.
  - Check `ALLOWED_IPS` in `.env` to ensure the client IP is whitelisted (e.g., `172.16.216.0/24`).
  - Run `scripts/test-api.sh` to validate OPNsense API connectivity.
  - Check `logs/bridge.log` for authentication errors (e.g., `Invalid JWT` or `Unauthorized IP`).
  - Ensure `app/services/opnsense_client.py` is correctly configured with API credentials.

## 3. Notifications Not Sent (Email, Slack, Teams)
- **Symptoms**: No notifications received despite high risk scores or emergency events; `logs/bridge.log` shows errors like `Email failed` or `Slack notification failed`.
- **Possible Causes**:
  - Incorrect SMTP or webhook settings in `.env`.
  - `DMZ_OFFLINE_MODE=true` preventing notifications.
  - Network restrictions blocking SMTP or webhook endpoints.
- **Solutions**:
  - Verify `SMTP_*`, `SLACK_*`, and `TEAMS_*` settings in `.env` (e.g., `SMTP_SERVER`, `SLACK_WEBHOOK_URL`, `TEAMS_WEBHOOK_URL`).
  - Set `TEST_MODE=true` and `TEST_EMAIL_RECIPIENT` to test notifications:
    ```bash
    curl -k -X POST -H "Authorization: Bearer <token>" -H "Content-Type: application/json" \
      -d '{"ip_address": "1.2.3.4", "reason": "Test"}' https://172.16.216.10:8443/emergency/block-ip
    ```
  - Check `logs/bridge.log` for errors (e.g., `SMTPAuthenticationError`, `HTTP 400` for webhooks).
  - Ensure `app/services/notification_service.py` is configured correctly.
  - Temporarily set `DEBUG_NOTIFICATIONS=true` in `.env` to log notification attempts without sending.

## 4. Monitoring Integrations Not Working
- **Symptoms**: Nagios, PRTG, or Grafana dashboards show no data; `/nagios/*` or `/prtg/*` endpoints return errors.
- **Possible Causes**:
  - Incorrect configuration in `monitoring/nagios/` or `monitoring/prtg/`.
  - Prometheus not scraping `/metrics` endpoint.
  - Network or firewall blocking monitoring endpoints.
- **Solutions**:
  - **Nagios**: Verify `monitoring/nagios/plugins/check_opnsense_bridge.sh` is executable and configured in `opnsense-commands.cfg`. Test:
    ```bash
    ./monitoring/nagios/plugins/check_opnsense_bridge.sh
    ```
  - **PRTG**: Ensure `monitoring/prtg/sensors/firewall_stats.py` points to `https://172.16.216.10:8443/prtg/firewall-statistics`. Test:
    ```bash
    python3 monitoring/prtg/sensors/firewall_stats.py
    ```
  - **Prometheus/Grafana**: Confirm `monitoring/prometheus.yml` targets `172.16.216.10:8443/metrics`. Check Prometheus UI (`http://172.16.216.10:9091`) and Grafana dashboards (`http://172.16.216.10:3000`).
  - Check `logs/monitoring.log` for errors.
  - Ensure firewall rules allow access to ports 8443, 3000 (Grafana), and 9091 (Prometheus).

## 5. Emergency IP Blocking Fails
- **Symptoms**: `POST /emergency/block-ip` or `/emergency/bulk-block` returns `{"status": "error"}`; IPs not blocked on OPNsense.
- **Possible Causes**:
  - Invalid JWT token or insufficient permissions (admin role required).
  - OPNsense API failure or rate limiting.
  - Invalid IP addresses in request.
- **Solutions**:
  - Verify JWT token has admin role (`app/middleware/authentication.py`).
  - Check `logs/emergency.log` for errors (e.g., `Failed to apply firewall rule`).
  - Test with a single IP:
    ```bash
    curl -k -X POST -H "Authorization: Bearer <token>" -H "Content-Type: application/json" \
      -d '{"ip_address": "1.2.3.4", "reason": "Test"}' https://172.16.216.10:8443/emergency/block-ip
    ```
  - Run `scripts/emergency-block.sh` manually:
    ```bash
    ./scripts/emergency-block.sh attack_ips.txt "Test Attack"
    ```
  - Validate OPNsense API with `scripts/test-api.sh`.

## 6. Kubernetes Deployment Issues
- **Symptoms**: Pods in `opnsense-bridge` namespace fail to start; `kubectl -n opnsense-bridge get pods` shows `CrashLoopBackOff` or `Pending`.
- **Possible Causes**:
  - Missing or incorrect `opnsense-bridge-secrets` or `opnsense-bridge-certs` Secrets.
  - Resource limits too restrictive in `k8s/deployment.yaml`.
  - Image pull failure or network issues.
- **Solutions**:
  - Check pod logs:
    ```bash
    kubectl -n opnsense-bridge logs <pod-name>
    ```
  - Verify Secrets:
    ```bash
    kubectl -n opnsense-bridge describe secret opnsense-bridge-secrets
    kubectl -n opnsense-bridge describe secret opnsense-bridge-certs
    ```
  - Ensure `certs/server.crt`, `certs/server.key`, and `certs/ca.crt` are base64-encoded in `k8s/secret.yaml`.
  - Adjust resource limits in `k8s/deployment.yaml` (e.g., increase CPU/memory).
  - Check `logs/bridge.log` for application errors.

## 7. High CPU or Memory Usage
- **Symptoms**: `/monitoring/system-stats` reports high CPU/memory usage; Kubernetes pods restart frequently.
- **Possible Causes**:
  - High API request volume exceeding rate limits.
  - Inefficient queries to OPNsense API.
  - Insufficient resources allocated.
- **Solutions**:
  - Monitor `/metrics` endpoint with Prometheus and Grafana (`http://172.16.216.10:3000`).
  - Increase replicas in `k8s/deployment.yaml` (e.g., `replicas: 3`).
  - Adjust `RATE_LIMIT_REQUESTS` and `RATE_LIMIT_PERIOD` in `.env`.
  - Optimize OPNsense API calls in `app/services/opnsense_client.py` (e.g., increase `OPNSENSE_API_TIMEOUT`).

## 8. SSL/TLS Errors
- **Symptoms**: `curl -k` works, but `curl https://172.16.216.10:8443/health` fails with SSL errors.
- **Possible Causes**:
  - Invalid or expired certificates in `certs/`.
  - Misconfigured Ingress in `k8s/ingress.yaml`.
- **Solutions**:
  - Verify certificates:
    ```bash
    openssl x509 -in certs/server.crt -text -noout
    ```
  - Recreate certificates if expired:
    ```bash
    openssl req -x509 -newkey rsa:4096 -nodes -out certs/server.crt -keyout certs/server.key -days 365
    ```
  - Update `k8s/secret.yaml` with new base64-encoded certificates.
  - Check Ingress configuration:
    ```bash
    kubectl -n opnsense-bridge describe ingress opnsense-monitoring-bridge
    ```