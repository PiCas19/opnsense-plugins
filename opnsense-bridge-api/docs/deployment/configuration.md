# OPNsense Monitoring Bridge Configuration Guide

This guide explains how to configure the OPNsense Monitoring Bridge, including environment variables, logging, and integration settings. All configuration files are located in the `config/` directory, with environment variables primarily defined in `.env`.

## Environment Variables (.env)
The `.env` file is the primary configuration source, loaded by `app/config.py`. Below are the key variables and their purposes:

```plaintext
# OPNsense API Configuration
OPNSENSE_HOST=https://opnsense.example.com
OPNSENSE_API_KEY=your-api-key
OPNSENSE_API_SECRET=your-api-secret
OPNSENSE_API_TIMEOUT=10
OPNSENSE_API_RETRIES=3
OPNSENSE_API_RETRY_BACKOFF=2

# SMTP Configuration
SMTP_SERVER=smtp.company.com
SMTP_PORT=587
SMTP_USERNAME=bridge@company.com
SMTP_PASSWORD=your-smtp-password
SMTP_USE_TLS=true
SMTP_USE_SSL=false
SMTP_FROM_ADDRESS=bridge@company.com
SMTP_FROM_NAME=OPNsense Bridge
ADMIN_EMAILS=admin1@example.com,admin2@example.com
EMERGENCY_EMAILS=soc@example.com
TEST_EMAIL_RECIPIENT=test@example.com

# Webhook Configuration
SLACK_ENABLED=true
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
SLACK_DEFAULT_CHANNEL=#alerts
SLACK_EMERGENCY_CHANNEL=#emergency
TEAMS_ENABLED=true
TEAMS_WEBHOOK_URL=https://company.webhook.office.com/...

# Thresholds
CPU_WARNING_THRESHOLD=80
CPU_CRITICAL_THRESHOLD=95
MEMORY_WARNING_THRESHOLD=85
MEMORY_CRITICAL_THRESHOLD=95
FIREWALL_RULES_WARNING=50
FIREWALL_RULES_CRITICAL=100
BLOCKED_EVENTS_WARNING=1000
BLOCKED_EVENTS_CRITICAL=5000
RISK_SCORE_WARNING=50
RISK_SCORE_CRITICAL=80
FAILED_LOGINS_WARNING=10
FAILED_LOGINS_CRITICAL=50

# Security
JWT_SECRET_KEY=your-jwt-secret
ALLOWED_IPS=172.16.216.0/24
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_PERIOD=60

# Modes
DMZ_OFFLINE_MODE=false
DEBUG=false
DEBUG_SMTP=false
DEBUG_NOTIFICATIONS=false
TEST_MODE=false
```

### Key Configuration Details
- **OPNsense API**:
  - `OPNSENSE_HOST`: URL of the OPNsense firewall (e.g., `https://opnsense.example.com`).
  - `OPNSENSE_API_KEY` and `OPNSENSE_API_SECRET`: Credentials for OPNsense API access.
  - `OPNSENSE_API_TIMEOUT`, `OPNSENSE_API_RETRIES`, `OPNSENSE_API_RETRY_BACKOFF`: Control API request resilience.
- **SMTP**:
  - Configure `SMTP_*` variables for email notifications.
  - `ADMIN_EMAILS` and `EMERGENCY_EMAILS` are comma-separated lists of recipients.
- **Webhooks**:
  - Enable Slack and Teams notifications with `SLACK_ENABLED` and `TEAMS_ENABLED`.
  - Set webhook URLs and channel names.
- **Thresholds**:
  - Define warning and critical thresholds for CPU, memory, firewall rules, blocked events, risk scores, and failed logins.
- **Security**:
  - `JWT_SECRET_KEY`: Secret for signing JWT tokens.
  - `ALLOWED_IPS`: IP ranges allowed to access the API (e.g., `172.16.216.0/24`).
  - `RATE_LIMIT_*`: Configure rate limiting for API protection.
- **Modes**:
  - `DMZ_OFFLINE_MODE`: Set to `true` to disable external connections (e.g., OPNsense API, notifications).
  - `DEBUG`, `DEBUG_SMTP`, `DEBUG_NOTIFICATIONS`: Enable debug logging.
  - `TEST_MODE`: Redirects notifications to `TEST_EMAIL_RECIPIENT` for testing.

### Logging Configuration
The logging configuration is defined in `config/logging.yaml`. Example:

```yaml
version: 1
formatters:
  detailed:
    format: '%(asctime)s %(name)s %(levelname)s: %(message)s'
handlers:
  file:
    class: logging.handlers.RotatingFileHandler
    formatter: detailed
    filename: logs/bridge.log
    maxBytes: 10485760 # 10MB
    backupCount: 5
  emergency:
    class: logging.handlers.RotatingFileHandler
    formatter: detailed
    filename: logs/emergency.log
    maxBytes: 10485760
    backupCount: 5
loggers:
  app:
    level: INFO
    handlers: [file]
  emergency:
    level: ERROR
    handlers: [emergency]
root:
  level: INFO
  handlers: [file]
```

- Logs are written to `logs/bridge.log` (main), `logs/emergency.log` (emergency operations), and other files as specified.
- Enable debug logging by setting `DEBUG=true` in `.env` to increase verbosity.

### Integration Configuration
- **Nagios**: Configure `monitoring/nagios/commands/opnsense-commands.cfg` and `monitoring/nagios/services/opnsense-services.cfg` to define checks for `/nagios/firewall-rules` and `/nagios/system-health`.
- **PRTG**: Ensure `monitoring/prtg/sensors/*.py` scripts are executable and configured to point to the bridge API.
- **Grafana**: Update `monitoring/grafana/provisioning/datasources.yaml` to connect to Prometheus (`http://172.16.216.10:9091`).
- **Prometheus**: Configure `monitoring/prometheus.yml` to scrape `/metrics` endpoint:
  ```yaml
  scrape_configs:
    - job_name: 'opnsense_bridge'
      static_configs:
        - targets: ['172.16.216.10:8443']
  ```

### SSL/TLS Configuration
- Place certificates in `certs/`:
  - `server.crt`: Server certificate.
  - `server.key`: Private key.
  - `ca.crt`: CA certificate (optional).
- Update `docker-compose.yml` or `k8s/secret.yaml` to mount certificates.
- For Nginx proxy, configure `nginx/nginx.conf` and `nginx/ssl/` with certificates.

### Backup Configuration
- Use `scripts/backup-config.sh` to back up `.env`, `config/*.yaml`, and `certs/`.
- Schedule backups using cron:
  ```bash
  0 0 * * * /opt/opnsense-monitoring-bridge/scripts/backup-config.sh
  ```

### Testing Configuration
- Run `scripts/test-api.sh` to verify OPNsense API connectivity.
- Test notifications by enabling `TEST_MODE` and checking `TEST_EMAIL_RECIPIENT`.