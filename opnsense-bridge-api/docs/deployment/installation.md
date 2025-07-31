# OPNsense Monitoring Bridge Installation Guide

This guide outlines the steps to install the OPNsense Monitoring Bridge on a server or containerized environment. The application can be deployed using Docker Compose or Kubernetes, with support for monitoring integrations (Nagios, PRTG, Grafana) and secure API access.

## Prerequisites

- **Operating System**: Linux (Ubuntu 20.04+ recommended) or any OS supporting Docker.
- **Dependencies**:
  - **Docker**: Version 20.10+ (for Docker Compose deployment).
  - **Docker Compose**: Version 1.29+.
  - **Python**: 3.9+ (if running without Docker).
  - **Git**: For cloning the repository.
  - **OpenSSL**: For generating SSL certificates (if not provided).
- **Network**:
  - Access to OPNsense firewall API (default: `https://opnsense.example.com:443`).
  - DMZ network (e.g., `172.16.216.0/24`) for secure deployment.
  - Ports: 8443 (API), 3000 (Grafana, optional), 9091 (Prometheus, optional).
- **Credentials**:
  - OPNsense API key and secret.
  - SMTP credentials for email notifications.
  - Slack and Microsoft Teams webhook URLs (optional).
- **Hardware** (recommended):
  - 2 vCPUs, 4GB RAM, 20GB storage (adjust based on load).

## Installation Steps

### 1. Clone the Repository
Clone the OPNsense Monitoring Bridge repository to your server:

```bash
git clone <repository-url>
cd opnsense-monitoring-bridge
```

Replace `<repository-url>` with the actual repository URL (e.g., `https://github.com/your-org/opnsense-monitoring-bridge.git`).

### 2. Set Up Environment Variables
Copy the example environment file and configure it:

```bash
cp .env.example .env
```

Edit `.env` with your settings. Key variables include:

```plaintext
# OPNsense API
OPNSENSE_HOST=https://opnsense.example.com
OPNSENSE_API_KEY=your-api-key
OPNSENSE_API_SECRET=your-api-secret

# SMTP Configuration
SMTP_SERVER=smtp.company.com
SMTP_PORT=587
SMTP_USERNAME=bridge@company.com
SMTP_PASSWORD=your-smtp-password
SMTP_FROM_ADDRESS=bridge@company.com
SMTP_FROM_NAME=OPNsense Bridge
ADMIN_EMAILS=admin1@example.com,admin2@example.com
EMERGENCY_EMAILS=soc@example.com

# Webhooks
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
TEST_MODE=false
TEST_EMAIL_RECIPIENT=test@example.com
```

Ensure all required fields are set, especially `OPNSENSE_HOST`, `OPNSENSE_API_KEY`, and `OPNSENSE_API_SECRET`.

### 3. Install Dependencies (Non-Docker)
If running without Docker, install Python dependencies:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Required packages (in `requirements.txt`):
```
fastapi==0.95.0
uvicorn==0.20.0
pydantic==1.10.0
aiohttp==3.8.0
smtplib==3.8.0
python-jose[cryptography]==3.3.0
python-dotenv==1.0.0
pyyaml==6.0
```

### 4. Set Up SSL Certificates
Generate or place SSL certificates in the `certs/` directory:

```bash
mkdir -p certs
openssl req -x509 -newkey rsa:4096 -nodes -out certs/server.crt -keyout certs/server.key -days 365
```

Alternatively, use existing certificates and update `docker-compose.yml` or `k8s/secret.yaml` with paths to `server.crt`, `server.key`, and `ca.crt`.

### 5. Deploy with Docker Compose
To deploy using Docker Compose:

```bash
docker-compose up -d
```

This starts the FastAPI application, Prometheus, and Grafana (if configured). Verify the containers are running:

```bash
docker-compose ps
```

### 6. Deploy with Kubernetes (Optional)
If using Kubernetes, apply the manifests in the `k8s/` directory:

```bash
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/secret.yaml
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
kubectl apply -f k8s/ingress.yaml
```

Ensure the `secret.yaml` includes the `.env` file and SSL certificates as secrets.

### 7. Verify Installation
Check the health endpoint:

```bash
curl -k https://172.16.216.10:8443/health
```

Expected response:
```json
{
  "status": "ok",
  "bridge_ip": "172.16.216.10",
  "timestamp": "2025-07-31T11:52:00.123456+00:00"
}
```

### 8. Configure Monitoring Integrations
- **Nagios**: Run the Nagios plugin installation script:
  ```bash
  ./scripts/install-nagios-plugin.sh
  ```
  This sets up `monitoring/nagios/plugins/check_opnsense_bridge.sh` and configuration files.

- **PRTG**: Test the PRTG sensor:
  ```bash
  python3 monitoring/prtg/sensors/firewall_stats.py
  ```

- **Grafana**: Access Grafana at `http://172.16.216.10:3000` and import dashboards from `monitoring/grafana/dashboards/`.

- **Prometheus**: Verify metrics at `http://172.16.216.10:9091` and ensure `prometheus.yml` is configured.

### Troubleshooting
- Check logs in `logs/bridge.log` for errors.
- Verify OPNsense API connectivity with `./scripts/test-api.sh`.
- Refer to `docs/troubleshooting/common_issues.md` for common problems.
