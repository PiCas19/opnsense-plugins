# Deployment Guide

Comprehensive deployment guide for the OPNsense Management Platform. This guide covers all deployment scenarios from development to production environments.

## 📋 Table of Contents

- [Prerequisites](#prerequisites)
- [Environment Setup](#environment-setup)
- [Development Deployment](#development-deployment)
- [Production Deployment](#production-deployment)
- [SSL Certificate Setup](#ssl-certificate-setup)
- [Configuration Reference](#configuration-reference)
- [Monitoring & Maintenance](#monitoring--maintenance)
- [Troubleshooting](#troubleshooting)

---

## 🔧 Prerequisites

### System Requirements

#### Minimum Requirements
- **CPU**: 2 cores
- **RAM**: 4GB
- **Storage**: 10GB available space
- **Network**: Stable connection to OPNsense firewall

#### Recommended Requirements
- **CPU**: 4+ cores
- **RAM**: 8GB+
- **Storage**: 20GB+ SSD
- **Network**: Gigabit connection

### Software Dependencies

#### Required
- **Docker**: 20.10+ or Docker Desktop
- **Docker Compose**: 2.0+
- **Git**: For cloning repository

#### Optional (for development)
- **Python**: 3.11+
- **Node.js**: 18+ (for frontend development)
- **Make**: For automation scripts

### Network Requirements

#### Ports
- **443**: HTTPS (Reverse Proxy)
- **8080**: HTTP (Wrapper Service, if exposed)
- **8000**: HTTP (DMZ API, internal only)

#### Firewall Access
- Network connectivity to OPNsense management interface
- OPNsense API access enabled
- Valid API credentials configured

---

## 🌍 Environment Setup

### 1. Clone Repository

```bash
git clone <repository-url>
cd opnsense-management-platform
```

### 2. Directory Structure Verification

```bash
tree -L 3
```

Expected structure:
```
.
├── README.md
├── docs/
│   ├── api-documentation.md
│   └── deployment-guide.md
├── reverse-proxy/
│   ├── api/
│   ├── nginx/
│   ├── ui/
│   └── docker-compose.yml
└── wrapper/
    ├── src/
    ├── tests/
    └── docker-compose.yml
```

### 3. Environment Files Setup

#### Wrapper Service Environment

```bash
cd wrapper
cp .env.example .env
```

Edit `wrapper/.env`:
```env
# OPNsense Configuration
OPNSENSE_URL=https://your-opnsense-host
OPNSENSE_API_KEY=your-api-key-here
OPNSENSE_API_SECRET=your-api-secret-here
OPNSENSE_VERIFY_SSL=true
OPNSENSE_TIMEOUT=30

# Service Configuration
PORT=8080
LOG_LEVEL=INFO

# Health Check Configuration
HEALTH_CHECK_INTERVAL=30
```

#### Reverse Proxy Environment

```bash
cd ../reverse-proxy
cp .env.example .env
```

Edit `reverse-proxy/.env`:
```env
# DMZ API Configuration
DMZ_HOST=dmz-api
DMZ_PORT=8000

# Wrapper Service Configuration
WRAPPER_BASE_URL=http://opnsense-wrapper:8080/api
WRAPPER_VERIFY_SSL=false
WRAPPER_TIMEOUT=30

# Authentication Configuration
JWT_SECRET=your-super-secure-jwt-secret-key-here-minimum-32-chars
JWT_EXPIRE_MINUTES=60
DEMO_USERNAME=admin
DEMO_PASSWORD=your-secure-password-here

# Logging Configuration
LOG_LEVEL=INFO
```

---

## 🚀 Development Deployment

### Quick Start (Single Command)

```bash
# Start all services
make dev-start

# Or manually:
docker-compose -f wrapper/docker-compose.yml up -d
docker-compose -f reverse-proxy/docker-compose.yml up -d
```

### Individual Service Deployment

#### 1. Wrapper Service Only

```bash
cd wrapper
docker-compose up -d

# Verify deployment
curl http://localhost:8080/api/health
```

#### 2. Reverse Proxy Only

```bash
cd reverse-proxy
docker-compose up -d

# Verify deployment (requires SSL setup)
curl -k https://localhost/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"your-password"}'
```

### Development with Hot Reload

#### Python Backend Development

```bash
# Terminal 1 - Wrapper Service
cd wrapper
python -m pip install -r requirements.txt
uvicorn src.app:api --reload --host 0.0.0.0 --port 8080

# Terminal 2 - Reverse Proxy API
cd reverse-proxy/api
python -m pip install -r requirements.txt
uvicorn src.app:api --reload --host 0.0.0.0 --port 8000
```

#### Frontend Development

```bash
# Terminal 3 - Static Files
cd reverse-proxy/ui
python -m http.server 3000

# Or with live reload (requires live-server)
npm install -g live-server
live-server --port=3000
```

### Development Docker Compose Override

Create `docker-compose.override.yml` for development:

```yaml
# wrapper/docker-compose.override.yml
services:
  opnsense-wrapper:
    volumes:
      - ./src:/app/src
    command: uvicorn src.app:api --reload --host 0.0.0.0 --port 8080
    environment:
      - LOG_LEVEL=DEBUG
```

```yaml
# reverse-proxy/docker-compose.override.yml
services:
  dmz-api:
    volumes:
      - ./api/src:/app/src
    command: uvicorn src.app:api --reload --host 0.0.0.0 --port 8000
    environment:
      - LOG_LEVEL=DEBUG
```

---

## 🏭 Production Deployment

### 1. Pre-Production Checklist

#### Security Checklist
- [ ] Strong JWT secret generated (32+ characters)
- [ ] Default passwords changed
- [ ] SSL certificates obtained and verified
- [ ] OPNsense API credentials secured
- [ ] Network access properly configured
- [ ] Firewall rules reviewed

#### Performance Checklist
- [ ] Resource limits configured
- [ ] Log rotation setup
- [ ] Monitoring configured
- [ ] Backup procedures in place
- [ ] Health checks configured

### 2. SSL Certificate Setup

#### Option A: Let's Encrypt (Recommended)

```bash
# Install certbot
sudo apt-get update
sudo apt-get install certbot

# Generate certificates
sudo certbot certonly --standalone -d your-domain.com

# Copy to nginx directory
sudo cp /etc/letsencrypt/live/your-domain.com/fullchain.pem reverse-proxy/nginx/certs/
sudo cp /etc/letsencrypt/live/your-domain.com/privkey.pem reverse-proxy/nginx/certs/

# Set proper permissions
sudo chown -R $(whoami):$(whoami) reverse-proxy/nginx/certs/
chmod 600 reverse-proxy/nginx/certs/privkey.pem
chmod 644 reverse-proxy/nginx/certs/fullchain.pem
```

#### Option B: Self-Signed (Development/Testing)

```bash
# Generate self-signed certificate
openssl req -x509 -newkey rsa:4096 -keyout reverse-proxy/nginx/certs/privkey.pem \
        -out reverse-proxy/nginx/certs/fullchain.pem -days 365 -nodes \
        -subj "/CN=localhost"

# Set permissions
chmod 600 reverse-proxy/nginx/certs/privkey.pem
chmod 644 reverse-proxy/nginx/certs/fullchain.pem
```

#### Option C: Commercial Certificate

```bash
# Copy your commercial certificates
cp your-domain.crt reverse-proxy/nginx/certs/fullchain.pem
cp your-domain.key reverse-proxy/nginx/certs/privkey.pem

# Include intermediate certificates in fullchain.pem if needed
cat your-domain.crt intermediate.crt > reverse-proxy/nginx/certs/fullchain.pem
```

### 3. Production Environment Configuration

#### Production Environment Files

```bash
# Production wrapper .env
cat > wrapper/.env.prod << EOF
OPNSENSE_URL=https://production-opnsense.company.com
OPNSENSE_API_KEY=${OPNSENSE_API_KEY}
OPNSENSE_API_SECRET=${OPNSENSE_API_SECRET}
OPNSENSE_VERIFY_SSL=true
OPNSENSE_TIMEOUT=30
PORT=8080
LOG_LEVEL=INFO
EOF

# Production reverse-proxy .env
cat > reverse-proxy/.env.prod << EOF
DMZ_HOST=dmz-api
DMZ_PORT=8000
WRAPPER_BASE_URL=http://opnsense-wrapper:8080/api
WRAPPER_VERIFY_SSL=false
WRAPPER_TIMEOUT=30
JWT_SECRET=${JWT_SECRET}
JWT_EXPIRE_MINUTES=60
DEMO_USERNAME=${ADMIN_USERNAME}
DEMO_PASSWORD=${ADMIN_PASSWORD}
LOG_LEVEL=INFO
EOF
```

#### Production Docker Compose

```yaml
# production-docker-compose.yml
version: '3.8'

services:
  opnsense-wrapper:
    build: ./wrapper
    container_name: opnsense-wrapper-prod
    env_file: wrapper/.env.prod
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/api/health"]
      interval: 30s
      timeout: 10s
      retries: 3
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
    networks:
      - opnsense-net

  dmz-api:
    build: ./reverse-proxy/api
    container_name: dmz-api-prod
    env_file: reverse-proxy/.env.prod
    restart: unless-stopped
    depends_on:
      - opnsense-wrapper
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/api/health"]
      interval: 30s
      timeout: 10s
      retries: 3
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
    networks:
      - opnsense-net

  nginx:
    image: nginx:1.27-alpine
    container_name: nginx-prod
    env_file: reverse-proxy/.env.prod
    depends_on:
      - dmz-api
    volumes:
      - ./reverse-proxy/nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./reverse-proxy/ui:/usr/share/nginx/html:ro
      - ./reverse-proxy/nginx/certs:/etc/nginx/certs:ro
    ports:
      - "443:443"
      - "80:80"  # For HTTP redirect
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-fk", "https://localhost"]
      interval: 30s
      timeout: 10s
      retries: 3
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
    networks:
      - opnsense-net

networks:
  opnsense-net:
    driver: bridge
```

### 4. Production Deployment Commands

```bash
# Build and start production environment
docker-compose -f production-docker-compose.yml up -d --build

# Verify all services are healthy
docker-compose -f production-docker-compose.yml ps

# Check logs
docker-compose -f production-docker-compose.yml logs -f
```

### 5. Production Nginx Configuration

Edit `reverse-proxy/nginx/nginx.conf` for production:

```nginx
worker_processes auto;
error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;

events {
    worker_connections 1024;
    use epoll;
    multi_accept on;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    # Logging
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for" '
                    'rt=$request_time uct="$upstream_connect_time" '
                    'uht="$upstream_header_time" urt="$upstream_response_time"';

    access_log /var/log/nginx/access.log main;

    # Performance
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    server_tokens off;

    # Gzip
    gzip on;
    gzip_vary on;
    gzip_min_length 10240;
    gzip_proxied any;
    gzip_types
        text/plain
        text/css
        text/xml
        text/javascript
        application/xml+rss
        application/javascript
        application/json;

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;

    # HTTP to HTTPS redirect
    server {
        listen 80;
        server_name _;
        return 301 https://$host$request_uri;
    }

    # Main HTTPS server
    server {
        listen 443 ssl http2;
        server_name _;

        # SSL Configuration
        ssl_certificate /etc/nginx/certs/fullchain.pem;
        ssl_certificate_key /etc/nginx/certs/privkey.pem;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
        ssl_prefer_server_ciphers off;
        ssl_session_cache shared:SSL:10m;
        ssl_session_timeout 10m;
        
        # Security headers
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
        add_header X-Content-Type-Options nosniff always;
        add_header X-Frame-Options DENY always;
        add_header X-XSS-Protection "1; mode=block" always;
        add_header Referrer-Policy "strict-origin-when-cross-origin" always;

        root /usr/share/nginx/html;
        index index.html;

        # Static files with caching
        location ~* \.(css|js|png|jpg|jpeg|gif|ico|svg)$ {
            expires 1y;
            add_header Cache-Control "public, immutable";
            access_log off;
        }

        location ~* \.(html)$ {
            expires 1h;
            add_header Cache-Control "public";
        }

        # API endpoints with rate limiting
        location /api/auth/login {
            limit_req zone=login burst=3 nodelay;
            proxy_pass http://dmz-api:8000/api/auth/login;
            include /etc/nginx/proxy_params;
        }

        location /api/ {
            limit_req zone=api burst=20 nodelay;
            proxy_pass http://dmz-api:8000/api/;
            include /etc/nginx/proxy_params;
        }

        # Documentation
        location /docs {
            proxy_pass http://dmz-api:8000/docs;
            include /etc/nginx/proxy_params;
        }

        location /openapi.json {
            proxy_pass http://dmz-api:8000/openapi.json;
            include /etc/nginx/proxy_params;
        }

        # SPA fallback
        location / {
            try_files $uri $uri/ /index.html;
        }

        # Health check endpoint
        location /health {
            access_log off;
            return 200 "healthy\n";
            add_header Content-Type text/plain;
        }
    }
}
```

Create `/etc/nginx/proxy_params`:
```nginx
proxy_http_version 1.1;
proxy_set_header Host $host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_set_header X-Forwarded-Host $host;
proxy_set_header X-Forwarded-Port $server_port;
proxy_cache_bypass $http_upgrade;
proxy_connect_timeout 30s;
proxy_send_timeout 30s;
proxy_read_timeout 30s;
```

---

## 🔧 Configuration Reference

### Wrapper Service Configuration

#### Environment Variables

| Variable | Description | Default | Example |
|----------|-------------|---------|---------|
| `OPNSENSE_URL` | OPNsense base URL | - | `https://firewall.local` |
| `OPNSENSE_API_KEY` | API key | - | `abcd1234...` |
| `OPNSENSE_API_SECRET` | API secret | - | `xyz9876...` |
| `OPNSENSE_VERIFY_SSL` | SSL verification | `true` | `false` |
| `OPNSENSE_TIMEOUT` | Request timeout (seconds) | `30` | `60` |
| `PORT` | Service port | `8080` | `8080` |
| `LOG_LEVEL` | Logging level | `INFO` | `DEBUG` |

#### OPNsense API Setup

1. **Access OPNsense Web Interface**
   ```
   https://your-opnsense-ip
   ```

2. **Navigate to API Settings**
   ```
   System → Access → Users → [Your User] → API keys
   ```

3. **Generate API Credentials**
   - Click "+" to add new API key
   - Note the generated key and secret
   - Assign appropriate privileges

4. **Required Privileges**
   - Firewall: Filter rules
   - System: Configuration reload

### Reverse Proxy Configuration

#### Environment Variables

| Variable | Description | Default | Example |
|----------|-------------|---------|---------|
| `DMZ_HOST` | DMZ API hostname | `dmz-api` | `localhost` |
| `DMZ_PORT` | DMZ API port | `8000` | `8000` |
| `WRAPPER_BASE_URL` | Wrapper service URL | - | `http://wrapper:8080/api` |
| `WRAPPER_VERIFY_SSL` | Wrapper SSL verification | `false` | `true` |
| `WRAPPER_TIMEOUT` | Wrapper timeout (seconds) | `30` | `60` |
| `JWT_SECRET` | JWT signing secret | - | `your-secret-key` |
| `JWT_EXPIRE_MINUTES` | Token expiration | `60` | `120` |
| `DEMO_USERNAME` | Demo user | `admin` | `administrator` |
| `DEMO_PASSWORD` | Demo password | - | `secure-password` |
| `LOG_LEVEL` | Logging level | `INFO` | `DEBUG` |

---

## 📊 Monitoring & Maintenance

### Health Checks

#### Service Health Monitoring

```bash
#!/bin/bash
# health-check.sh - Add to cron for regular monitoring

WRAPPER_URL="http://localhost:8080/api/health"
PROXY_URL="https://your-domain.com/health"

# Check wrapper service
if curl -sf "$WRAPPER_URL" > /dev/null; then
    echo "$(date): Wrapper service OK"
else
    echo "$(date): Wrapper service FAILED"
    # Add alert mechanism here
fi

# Check reverse proxy
if curl -sfk "$PROXY_URL" > /dev/null; then
    echo "$(date): Reverse proxy OK"
else
    echo "$(date): Reverse proxy FAILED"
    # Add alert mechanism here
fi
```

#### OPNsense Connectivity Check

```bash
#!/bin/bash
# opnsense-check.sh

HEALTH_URL="http://localhost:8080/api/health/opnsense"

RESPONSE=$(curl -s "$HEALTH_URL")
STATUS=$(echo "$RESPONSE" | jq -r '.ok')

if [ "$STATUS" = "true" ]; then
    LATENCY=$(echo "$RESPONSE" | jq -r '.latency_ms')
    echo "$(date): OPNsense OK (${LATENCY}ms)"
else
    echo "$(date): OPNsense FAILED - $RESPONSE"
    # Add alert mechanism here
fi
```

### Log Management

#### Log Rotation Configuration

```bash
# /etc/logrotate.d/opnsense-platform
/var/lib/docker/containers/*/*-json.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 644 root root
    postrotate
        docker kill --signal="USR1" $(docker ps -q) 2>/dev/null || true
    endscript
}
```

#### Centralized Logging (Optional)

```yaml
# Add to docker-compose.yml for ELK stack integration
logging:
  driver: "gelf"
  options:
    gelf-address: "udp://logstash:12201"
    tag: "opnsense-platform"
```

### Performance Monitoring

#### Prometheus Metrics (Optional Enhancement)

```python
# Add to wrapper service for metrics
from prometheus_client import Counter, Histogram, generate_latest

REQUEST_COUNT = Counter('http_requests_total', 'Total HTTP requests')
REQUEST_LATENCY = Histogram('http_request_duration_seconds', 'HTTP request latency')

@router.get("/metrics")
def metrics():
    return Response(generate_latest(), media_type="text/plain")
```

### Backup Procedures

#### Configuration Backup

```bash
#!/bin/bash
# backup-config.sh

BACKUP_DIR="/backup/opnsense-platform/$(date +%Y%m%d)"
mkdir -p "$BACKUP_DIR"

# Backup environment files
cp wrapper/.env "$BACKUP_DIR/wrapper.env"
cp reverse-proxy/.env "$BACKUP_DIR/reverse-proxy.env"

# Backup SSL certificates
cp -r reverse-proxy/nginx/certs "$BACKUP_DIR/"

# Backup custom configurations
cp reverse-proxy/nginx/nginx.conf "$BACKUP_DIR/"
cp -r reverse-proxy/ui "$BACKUP_DIR/"

# Create archive
tar -czf "$BACKUP_DIR.tar.gz" -C "$BACKUP_DIR" .
rm -rf "$BACKUP_DIR"

echo "Backup created: $BACKUP_DIR.tar.gz"
```

#### Database Backup (if using external database)

```bash
#!/bin/bash
# backup-database.sh

BACKUP_DIR="/backup/database/$(date +%Y%m%d)"
mkdir -p "$BACKUP_DIR"

# PostgreSQL example
pg_dump -h database-host -U username opnsense_db > "$BACKUP_DIR/opnsense_db.sql"

# MySQL example
# mysqldump -h database-host -u username -p opnsense_db > "$BACKUP_DIR/opnsense_db.sql"

gzip "$BACKUP_DIR/opnsense_db.sql"
echo "Database backup created: $BACKUP_DIR/opnsense_db.sql.gz"
```

---

## 🔄 Updates and Maintenance

### Update Procedures

#### 1. Pre-Update Checklist

```bash
# Create backup
./backup-config.sh

# Check current versions
docker-compose ps
docker images | grep opnsense

# Verify services are healthy
curl -sf http://localhost:8080/api/health
curl -sfk https://your-domain.com/health
```

#### 2. Rolling Update (Zero Downtime)

```bash
#!/bin/bash
# rolling-update.sh

# Update wrapper service
echo "Updating wrapper service..."
cd wrapper
docker-compose pull
docker-compose up -d --no-deps opnsense-wrapper

# Wait for health check
sleep 30
if ! curl -sf http://localhost:8080/api/health; then
    echo "Wrapper update failed, rolling back..."
    docker-compose down
    docker-compose up -d
    exit 1
fi

# Update reverse proxy
echo "Updating reverse proxy..."
cd ../reverse-proxy
docker-compose pull
docker-compose up -d --no-deps dmz-api nginx

# Verify update
sleep 30
if ! curl -sfk https://your-domain.com/health; then
    echo "Proxy update failed, rolling back..."
    docker-compose down
    docker-compose up -d
    exit 1
fi

echo "Update completed successfully"
```

#### 3. Full System Update

```bash
# Stop services
docker-compose -f wrapper/docker-compose.yml down
docker-compose -f reverse-proxy/docker-compose.yml down

# Update images
docker-compose -f wrapper/docker-compose.yml pull
docker-compose -f reverse-proxy/docker-compose.yml pull

# Rebuild if needed
docker-compose -f wrapper/docker-compose.yml build --no-cache
docker-compose -f reverse-proxy/docker-compose.yml build --no-cache

# Start services
docker-compose -f wrapper/docker-compose.yml up -d
docker-compose -f reverse-proxy/docker-compose.yml up -d

# Verify
sleep 60
curl -sf http://localhost:8080/api/health
curl -sfk https://your-domain.com/health
```

### Maintenance Tasks

#### Daily Maintenance

```bash
#!/bin/bash
# daily-maintenance.sh

# Clean up old docker images
docker image prune -f

# Check disk space
df -h /var/lib/docker

# Rotate logs if needed
logrotate -f /etc/logrotate.d/opnsense-platform

# Health checks
./health-check.sh >> /var/log/opnsense-health.log
```

#### Weekly Maintenance

```bash
#!/bin/bash
# weekly-maintenance.sh

# Full backup
./backup-config.sh

# Security updates
apt update && apt upgrade -y

# Docker system cleanup
docker system prune -f

# Certificate renewal check (Let's Encrypt)
certbot renew --dry-run
```

---

## 🐛 Troubleshooting

### Common Issues

#### 1. SSL Certificate Issues

**Problem**: SSL certificate errors
```
SSL certificate verification failed
```

**Solutions**:
```bash
# Check certificate files
ls -la reverse-proxy/nginx/certs/
openssl x509 -in reverse-proxy/nginx/certs/fullchain.pem -text -noout

# Verify certificate chain
openssl verify -CAfile /etc/ssl/certs/ca-certificates.crt reverse-proxy/nginx/certs/fullchain.pem

# Test SSL configuration
openssl s_client -connect your-domain.com:443 -servername your-domain.com
```

#### 2. OPNsense Connection Issues

**Problem**: Cannot connect to OPNsense
```
Connection refused to OPNsense host
```

**Diagnosis**:
```bash
# Test network connectivity
ping your-opnsense-host
telnet your-opnsense-host 443

# Check API credentials
curl -k -u "api-key:api-secret" https://your-opnsense-host/api/firewall/filter/searchRule

# Verify wrapper configuration
docker exec opnsense-wrapper env | grep OPNSENSE
```

#### 3. Authentication Issues

**Problem**: JWT authentication failures
```
JWT token validation failed
```

**Solutions**:
```bash
# Check JWT secret configuration
docker exec dmz-api env | grep JWT_SECRET

# Verify token generation
curl -X POST https://your-domain.com/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"your-password"}' \
  -v

# Test token validation
TOKEN="your-jwt-token"
curl -H "Authorization: Bearer $TOKEN" https://your-domain.com/api/rules -v
```

#### 4. Service Discovery Issues

**Problem**: Services cannot communicate
```
Connection refused to backend service
```

**Solutions**:
```bash
# Check Docker networks
docker network ls
docker network inspect reverse-proxy_dmznet

# Test inter-service connectivity
docker exec dmz-api ping opnsense-wrapper
docker exec nginx ping dmz-api

# Check service status
docker-compose ps
docker-compose logs dmz-api
```

#### 5. Performance Issues

**Problem**: Slow response times
```
Request timeout after 30 seconds
```

**Solutions**:
```bash
# Check resource usage
docker stats

# Monitor response times
curl -w "@curl-format.txt" -o /dev/null -s https://your-domain.com/api/rules

# Increase timeouts
# Edit .env file:
WRAPPER_TIMEOUT=60
OPNSENSE_TIMEOUT=60
```

### Debug Commands

#### Service Debugging

```bash
# View all logs
docker-compose logs -f

# Debug specific service
docker-compose logs -f dmz-api

# Enter container for debugging
docker exec -it opnsense-wrapper bash
docker exec -it dmz-api bash

# Check service health
docker-compose exec opnsense-wrapper curl http://localhost:8080/api/health
docker-compose exec dmz-api curl http://localhost:8000/api/health
```

#### Network Debugging

```bash
# Test internal networking
docker run --rm --network reverse-proxy_dmznet curlimages/curl:latest \
  curl http://dmz-api:8000/api/health

# Test external connectivity
docker run --rm --network reverse-proxy_dmznet curlimages/curl:latest \
  curl -k https://your-opnsense-host

# Port testing
nmap -p 443,8080 localhost
```

### Recovery Procedures

#### Service Recovery

```bash
#!/bin/bash
# service-recovery.sh

SERVICE=$1

case $SERVICE in
  "wrapper")
    cd wrapper
    docker-compose down
    docker-compose up -d
    ;;
  "proxy")
    cd reverse-proxy
    docker-compose down
    docker-compose up -d
    ;;
  "all")
    docker-compose -f wrapper/docker-compose.yml down
    docker-compose -f reverse-proxy/docker-compose.yml down
    docker-compose -f wrapper/docker-compose.yml up -d
    docker-compose -f reverse-proxy/docker-compose.yml up -d
    ;;
  *)
    echo "Usage: $0 {wrapper|proxy|all}"
    exit 1
    ;;
esac

echo "Recovery completed for $SERVICE"
```

#### Configuration Recovery

```bash
#!/bin/bash
# config-recovery.sh

BACKUP_FILE=$1

if [ ! -f "$BACKUP_FILE" ]; then
    echo "Backup file not found: $BACKUP_FILE"
    exit 1
fi

# Stop services
docker-compose -f wrapper/docker-compose.yml down
docker-compose -f reverse-proxy/docker-compose.yml down

# Extract backup
tar -xzf "$BACKUP_FILE" -C /tmp/restore/

# Restore configurations
cp /tmp/restore/wrapper.env wrapper/.env
cp /tmp/restore/reverse-proxy.env reverse-proxy/.env
cp -r /tmp/restore/certs reverse-proxy/nginx/
cp /tmp/restore/nginx.conf reverse-proxy/nginx/

# Restart services
docker-compose -f wrapper/docker-compose.yml up -d
docker-compose -f reverse-proxy/docker-compose.yml up -d

echo "Configuration restored from $BACKUP_FILE"
```

---

## 📋 Deployment Automation

### Automation Scripts

#### Complete Deployment Script

```bash
#!/bin/bash
# deploy.sh - Complete deployment automation

set -e

ENVIRONMENT=${1:-development}
DOMAIN=${2:-localhost}

echo "Deploying OPNsense Platform for $ENVIRONMENT environment..."

# Validate environment
if [[ ! "$ENVIRONMENT" =~ ^(development|staging|production)$ ]]; then
    echo "Error: Environment must be development, staging, or production"
    exit 1
fi

# Check prerequisites
command -v docker >/dev/null 2>&1 || { echo "Docker is required but not installed."; exit 1; }
command -v docker-compose >/dev/null 2>&1 || { echo "Docker Compose is required but not installed."; exit 1; }

# Setup environment files
echo "Setting up environment configuration..."
if [ ! -f "wrapper/.env" ]; then
    cp wrapper/.env.example wrapper/.env
    echo "Please configure wrapper/.env with your OPNsense credentials"
    exit 1
fi

if [ ! -f "reverse-proxy/.env" ]; then
    cp reverse-proxy/.env.example reverse-proxy/.env
    echo "Please configure reverse-proxy/.env with your settings"
    exit 1
fi

# SSL certificate setup for production
if [ "$ENVIRONMENT" = "production" ]; then
    echo "Setting up SSL certificates..."
    if [ ! -f "reverse-proxy/nginx/certs/fullchain.pem" ]; then
        echo "SSL certificates not found. Please run:"
        echo "sudo certbot certonly --standalone -d $DOMAIN"
        echo "Then copy certificates to reverse-proxy/nginx/certs/"
        exit 1
    fi
fi

# Deploy services
echo "Deploying services..."
docker-compose -f wrapper/docker-compose.yml up -d --build
docker-compose -f reverse-proxy/docker-compose.yml up -d --build

# Wait for services to be ready
echo "Waiting for services to start..."
sleep 30

# Health checks
echo "Performing health checks..."
if curl -sf http://localhost:8080/api/health >/dev/null; then
    echo "✓ Wrapper service is healthy"
else
    echo "✗ Wrapper service health check failed"
    exit 1
fi

if [ "$ENVIRONMENT" = "production" ]; then
    HEALTH_URL="https://$DOMAIN/health"
else
    HEALTH_URL="https://localhost/health"
fi

if curl -sfk "$HEALTH_URL" >/dev/null; then
    echo "✓ Reverse proxy is healthy"
else
    echo "✗ Reverse proxy health check failed"
    exit 1
fi

echo "🎉 Deployment completed successfully!"
echo "Access the platform at: $HEALTH_URL"
```

#### CI/CD Integration

```yaml
# .github/workflows/deploy.yml
name: Deploy OPNsense Platform

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install dependencies
        run: |
          cd wrapper
          pip install -r requirements.txt
          cd ../reverse-proxy/api
          pip install -r requirements.txt
      
      - name: Run tests
        run: |
          cd wrapper
          python -m pytest tests/ -v --cov=src
          cd ../reverse-proxy/api
          python -m pytest tests/ -v --cov=src

  deploy:
    needs: test
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Deploy to staging
        run: |
          # Add your deployment commands here
          ./deploy.sh staging
```

---

## 📚 Additional Resources

### Documentation Links
- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [Nginx Documentation](https://nginx.org/en/docs/)
- [Docker Compose Reference](https://docs.docker.com/compose/)
- [OPNsense API Documentation](https://docs.opnsense.org/development/api.html)

### Monitoring Tools
- [Prometheus](https://prometheus.io/) - Metrics collection
- [Grafana](https://grafana.com/) - Visualization
- [ELK Stack](https://www.elastic.co/elk-stack) - Log analysis
- [Uptime Kuma](https://github.com/louislam/uptime-kuma) - Simple monitoring

### Security Tools
- [Let's Encrypt](https://letsencrypt.org/) - Free SSL certificates
- [OWASP ZAP](https://owasp.org/www-project-zap/) - Security scanning
- [Trivy](https://trivy.dev/) - Container security scanning

---

**Guide Version**: 1.0.0  
**Last Updated**: 2024  
**Compatibility**: Docker 20.10+, Docker Compose 2.0+