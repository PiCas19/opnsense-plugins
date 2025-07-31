# Debugging - OPNsense Monitoring Bridge

This guide provides advanced debugging techniques for diagnosing issues with the OPNsense Monitoring Bridge. It covers log analysis, script usage, and monitoring tools to identify and resolve problems. Refer to `common_issues.md` for specific issue resolutions.

## 1. Enable Debug Logging
- **Purpose**: Increase log verbosity to capture detailed information about application behavior.
- **Steps**:
  - Set `DEBUG=true` in `.env` to enable debug logging for all services.
  - Optionally, enable specific debug modes:
    - `DEBUG_SMTP=true` for email notifications (`app/services/notification_service.py`).
    - `DEBUG_NOTIFICATIONS=true` for Slack/Teams notifications.
  - Restart the application:
    ```bash
    docker-compose restart
    # Or for Kubernetes
    kubectl -n opnsense-bridge rollout restart deployment opnsense-monitoring-bridge
    ```
  - Check `logs/bridge.log` for detailed logs:
    ```bash
    tail -f logs/bridge.log
    ```

## 2. Analyze Logs
- **Log Files**:
  - `logs/bridge.log`: Main application logs (API requests, service operations).
  - `logs/emergency.log`: Emergency operations (IP blocks, critical alerts).
  - `logs/monitoring.log`: Monitoring service logs (metrics, health checks).
  - `logs/audit.log`: Security and access logs (JWT validation, IP whitelisting).
  - `logs/access.log`: API access logs.
- **Commands**:
  - View recent logs:
    ```bash
    tail -n 100 logs/bridge.log
    ```
  - Search for errors:
    ```bash
    grep "ERROR" logs/bridge.log
    ```
  - Monitor emergency operations:
    ```bash
    tail -f logs/emergency.log
    ```
- **Common Log Patterns**:
  - `ConnectionError`: OPNsense API connectivity issues (`app/services/opnsense_client.py`).
  - `401 Unauthorized`: Invalid JWT or API credentials.
  - `429 Too Many Requests`: Rate limit exceeded (`app/middleware/rate_limiting.py`).
  - `SMTPAuthenticationError`: Invalid SMTP credentials (`app/services/notification_service.py`).

## 3. Test OPNsense API Connectivity
- **Purpose**: Verify connectivity to the OPNsense API.
- **Steps**:
  - Run the test script:
    ```bash
    ./scripts/test-api.sh
    ```
  - Expected output:
    ```
    OPNsense API test successful
    Host: https://opnsense.example.com
    Status: OK
    ```
  - If it fails, check:
    - `OPNSENSE_HOST`, `OPNSENSE_API_KEY`, `OPNSENSE_API_SECRET` in `.env`.
    - Network connectivity (`ping opnsense.example.com` or `curl -k https://opnsense.example.com`).
    - OPNsense firewall rules allowing API access from `172.16.216.10`.

## 4. Test API Endpoints
- **Purpose**: Validate API functionality.
- **Steps**:
  - Test health endpoint (no authentication):
    ```bash
    curl -k https://172.16.216.10:8443/health
    ```
  - Test detailed health endpoint (requires JWT):
    ```bash
    curl -k -H "Authorization: Bearer <token>" https://172.16.216.10:8443/health/detailed
    ```
  - Test emergency block (admin JWT required):
    ```bash
    curl -k -X POST -H "Authorization: Bearer <token>" -H "Content-Type: application/json" \
      -d '{"ip_address": "1.2.3.4", "reason": "Test"}' https://172.16.216.10:8443/emergency/block-ip
    ```
  - Check `logs/bridge.log` and `logs/emergency.log` for results.

## 5. Debug Monitoring Integrations
- **Nagios**:
  - Test the Nagios plugin:
    ```bash
    ./monitoring/nagios/plugins/check_opnsense_bridge.sh
    ```
  - Check `monitoring/nagios/commands/opnsense-commands.cfg` and `monitoring/nagios/services/opnsense-services.cfg`.
  - Verify endpoint responses:
    ```bash
    curl -k https://172.16.216.10:8443/nagios/firewall-rules
    ```
- **PRTG**:
  - Run the PRTG sensor script:
    ```bash
    python3 monitoring/prtg/sensors/firewall_stats.py
    ```
  - Verify XML output:
    ```bash
    curl -k https://172.16.216.10:8443/prtg/firewall-statistics
    ```
- **Prometheus/Grafana**:
  - Check Prometheus metrics:
    ```bash
    curl -k https://172.16.216.10:8443/metrics
    ```
  - Access Prometheus UI (`http://172.16.216.10:9091`) and verify targets.
  - Check Grafana dashboards (`http://172.16.216.10:3000`) and data source (`monitoring/grafana/provisioning/datasources.yaml`).
  - Review `logs/monitoring.log` for errors.

## 6. Debug Kubernetes Issues
- **Purpose**: Diagnose pod or service issues in the `opnsense-bridge` namespace.
- **Steps**:
  - Check pod status:
    ```bash
    kubectl -n opnsense-bridge get pods
    ```
  - View pod logs:
    ```bash
    kubectl -n opnsense-bridge logs <pod-name>
    ```
  - Describe pod for events:
    ```bash
    kubectl -n opnsense-bridge describe pod <pod-name>
    ```
  - Verify Services and Ingress:
    ```bash
    kubectl -n opnsense-bridge get svc
    kubectl -n opnsense-bridge describe ingress opnsense-monitoring-bridge
    ```
  - Check Secrets and ConfigMaps:
    ```bash
    kubectl -n opnsense-bridge describe secret opnsense-bridge-secrets
    kubectl -n opnsense-bridge describe configmap opnsense-bridge-config
    ```
  - Redeploy if necessary:
    ```bash
    kubectl -n opnsense-bridge rollout restart deployment opnsense-monitoring-bridge
    ```

## 7. Debug SSL/TLS Issues
- **Purpose**: Resolve certificate-related errors.
- **Steps**:
  - Verify certificates:
    ```bash
    openssl x509 -in certs/server.crt -text -noout
    ```
  - Test HTTPS endpoint without bypassing SSL:
    ```bash
    curl https://172.16.216.10:8443/health
    ```
  - If using Kubernetes, check Ingress:
    ```bash
    kubectl -n opnsense-bridge describe ingress opnsense-monitoring-bridge
    ```
  - Update `k8s/secret.yaml` with new certificates if expired:
    ```bash
    kubectl -n opnsense-bridge apply -f k8s/secret.yaml
    ```

## 8. Debug High Risk Scores or False Positives
- **Purpose**: Investigate unexpected threat detections in `app/services/cyber_defense_service.py`.
- **Steps**:
  - Enable debug logging (`DEBUG=true` in `.env`).
  - Check `logs/bridge.log` for threat analysis:
    ```bash
    grep "Threat patterns analyzed" logs/bridge.log
    ```
  - Review risk score calculations:
    ```bash
    curl -k -H "Authorization: Bearer <token>" https://172.16.216.10:8443/monitoring/status
    ```
  - Adjust thresholds in `.env` (e.g., `RISK_SCORE_WARNING`, `FAILED_LOGINS_CRITICAL`).
  - Inspect `app/services/cyber_defense_service.py` for logic errors.

## 9. Use Monitoring Tools
- **Prometheus**: Check metrics at `http://172.16.216.10:9091` for anomalies (e.g., `opnsense_cpu_usage_percent`, `opnsense_threat_score`).
- **Grafana**: Analyze dashboards at `http://172.16.216.10:3000` for trends.
- **Nagios/PRTG**: Verify check results and sensor data.

## 10. Backup and Restore for Debugging
- **Purpose**: Preserve state before making changes.
- **Steps**:
  - Back up configuration:
    ```bash
    ./scripts/backup-config.sh
    ```
  - Restore from backup if needed:
    ```bash
    cp backups/config_<timestamp>.tar.gz config/
    tar -xzf config/config_<timestamp>.tar.gz
    ```