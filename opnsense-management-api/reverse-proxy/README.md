# OPNsense Reverse Proxy

A secure reverse proxy solution built with Nginx and FastAPI that provides authenticated access to OPNsense management services. This component acts as a secure gateway with SSL termination, JWT authentication, and a responsive web interface.

## 🎯 Overview

The reverse proxy provides:
- **SSL/TLS termination** with certificate management
- **JWT-based authentication** system
- **Static web interface** for user interaction
- **API proxying** to backend services
- **Security headers** and protection mechanisms
- **Gzip compression** and caching optimization

## 🏗️ Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Web Browser   │───►│     Nginx        │───►│   DMZ API       │
│    (HTTPS)      │    │  (SSL + Proxy)   │    │   (FastAPI)     │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │
                                ▼
                       ┌──────────────────┐
                       │   Static Files   │
                       │   (Web UI)       │
                       └──────────────────┘
```

## 🚀 Quick Start

### Prerequisites

- Docker and Docker Compose
- SSL certificates (Let's Encrypt recommended)
- Domain name configured for SSL

### Docker Deployment (Recommended)

1. Navigate to the reverse proxy directory:
```bash
cd reverse-proxy
```

2. Create environment configuration:
```bash
cp .env.example .env
```

3. Configure your `.env` file:
```env
# DMZ API Configuration
DMZ_HOST=dmz-api
DMZ_PORT=8000
WRAPPER_BASE_URL=http://opnsense-wrapper:8080
WRAPPER_VERIFY_SSL=false
WRAPPER_TIMEOUT=30

# Authentication
JWT_SECRET=your-super-secure-jwt-secret-key-here
JWT_EXPIRE_MINUTES=60
DEMO_USERNAME=admin
DEMO_PASSWORD=secure-password

# Logging
LOG_LEVEL=INFO
```

4. Place your SSL certificates:
```bash
# Copy your SSL certificates to the certs directory
cp /path/to/your/fullchain.pem nginx/certs/
cp /path/to/your/privkey.pem nginx/certs/
```

5. Deploy with Docker Compose:
```bash
docker-compose up -d
```

6. Access the web interface:
```
https://your-domain.com
```

## 🔧 Service Components

### Nginx Proxy
- **Port**: 443 (HTTPS)
- **Purpose**: SSL termination, static file serving, API proxying
- **Features**: Security headers, compression, caching

### DMZ API Service
- **Port**: 8000 (internal)
- **Purpose**: Authentication and API gateway
- **Features**: JWT authentication, request validation, logging

## 📋 API Endpoints

### Authentication

#### POST /api/auth/login
Authenticate user and receive JWT token.

**Request:**
```json
{
  "username": "admin",
  "password": "secure-password"
}
```

**Response:**
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "token_type": "bearer",
  "expires_in": 3600
}
```

#### POST /api/auth/refresh
Refresh an existing JWT token.

**Headers:**
```
Authorization: Bearer <token>
```

### Proxy Rules Management

#### GET /api/proxy-rules
Get current proxy configuration.

**Headers:**
```
Authorization: Bearer <token>
```

**Response:**
```json
{
  "rules": [
    {
      "id": "rule-1",
      "source": "/api/wrapper/*",
      "target": "http://wrapper-service:8080/*",
      "enabled": true
    }
  ]
}
```

#### POST /api/proxy-rules
Create a new proxy rule.

#### PUT /api/proxy-rules/{rule_id}
Update an existing proxy rule.

#### DELETE /api/proxy-rules/{rule_id}
Delete a proxy rule.

## 🔒 Security Features

### SSL/TLS Configuration
- **TLS 1.2+** minimum version
- **Strong cipher suites** configuration
- **HSTS headers** for security
- **Certificate validation**

### Security Headers
```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000
```

### Authentication System
- **JWT tokens** with configurable expiration
- **Password hashing** using bcrypt
- **Token validation** on all protected endpoints
- **Automatic token refresh**

## 🏗️ Project Structure

```
reverse-proxy/
├── api/                    # FastAPI backend service
│   ├── src/
│   │   ├── app.py         # Main FastAPI application
│   │   ├── config.py      # Configuration management
│   │   ├── routes/
│   │   │   ├── auth.py    # Authentication endpoints
│   │   │   └── proxy_rules.py  # Proxy management
│   │   └── utils/
│   │       ├── logger.py  # Logging utilities
│   │       └── security.py # Security utilities
│   ├── tests/             # Test suite
│   ├── Dockerfile
│   └── requirements.txt
├── nginx/                 # Nginx configuration
│   ├── nginx.conf        # Main Nginx config
│   └── certs/            # SSL certificates
├── ui/                   # Static web interface
│   └── index.html       # Main web page
├── docker-compose.yml   # Docker composition
└── README.md
```

## 🎨 Web Interface

### Features
- **Responsive design** for mobile and desktop
- **JWT authentication** integration
- **Real-time status** indicators
- **Configuration management** interface
- **Dark/light theme** support

### Customization

Edit `ui/index.html` to customize:
- Branding and logos
- Color schemes and themes
- Layout and navigation
- Additional features

## 🧪 Testing

### Running API Tests

```bash
cd api
python -m pytest tests/ -v --cov=src
```

### Test Categories

- **Authentication tests**: Login, token validation, refresh
- **Security tests**: Header validation, input sanitization
- **Configuration tests**: Environment variable handling
- **Integration tests**: End-to-end API workflows

### Load Testing

```bash
# Install Apache Bench for load testing
sudo apt-get install apache2-utils

# Test authentication endpoint
ab -n 1000 -c 10 -H "Content-Type: application/json" \
   -p login.json https://your-domain.com/api/auth/login
```

## 🔧 Configuration

### Environment Variables

#### DMZ API Configuration
| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `DMZ_HOST` | DMZ API hostname | `dmz-api` | No |
| `DMZ_PORT` | DMZ API port | `8000` | No |
| `WRAPPER_BASE_URL` | Wrapper service URL | - | Yes |
| `WRAPPER_VERIFY_SSL` | Enable SSL verification | `true` | No |
| `WRAPPER_TIMEOUT` | Request timeout | `30` | No |

#### Authentication Configuration
| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `JWT_SECRET` | JWT signing secret | - | Yes |
| `JWT_EXPIRE_MINUTES` | Token expiration time | `60` | No |
| `DEMO_USERNAME` | Demo user login | `admin` | No |
| `DEMO_PASSWORD` | Demo user password | - | Yes |

### SSL Certificate Setup

#### Using Let's Encrypt (Recommended)

```bash
# Install certbot
sudo apt-get install certbot

# Generate certificates
sudo certbot certonly --standalone -d your-domain.com

# Copy certificates
sudo cp /etc/letsencrypt/live/your-domain.com/fullchain.pem nginx/certs/
sudo cp /etc/letsencrypt/live/your-domain.com/privkey.pem nginx/certs/
```

#### Using Self-Signed Certificates (Development)

```bash
# Generate self-signed certificate
openssl req -x509 -newkey rsa:4096 -keyout nginx/certs/privkey.pem \
        -out nginx/certs/fullchain.pem -days 365 -nodes \
        -subj "/CN=localhost"
```

### Nginx Configuration Customization

Edit `nginx/nginx.conf` to customize:

#### Custom Proxy Rules
```nginx
location /custom-api/ {
    proxy_pass http://custom-backend:8080/;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
}
```

#### Rate Limiting
```nginx
http {
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;
    
    server {
        location /api/auth/login {
            limit_req zone=login burst=5;
            proxy_pass http://dmz-api:8000/api/auth/login;
        }
    }
}
```

## 📊 Monitoring & Logging

### Log Files
- **Nginx Access Logs**: Request logging with response times
- **Nginx Error Logs**: Server errors and warnings
- **API Logs**: Application-level logging with structured format

### Health Monitoring

```bash
# Check service health
curl -k https://your-domain.com/api/health

# Check detailed status
curl -k https://your-domain.com/api/status
```

### Metrics Integration

Consider adding monitoring tools:
- **Prometheus**: Metrics collection
- **Grafana**: Visualization dashboards
- **ELK Stack**: Log aggregation and analysis

## 🐛 Troubleshooting

### Common Issues

#### SSL Certificate Errors
```
ERROR: SSL certificate verification failed
```
**Solution**: Verify certificate files are correctly mounted and accessible.

#### Authentication Failures
```
ERROR: JWT token validation failed
```
**Solution**: Check JWT secret configuration and token expiration settings.

#### Proxy Connection Errors
```
ERROR: Connection refused to backend service
```
**Solution**: Verify backend service is running and network connectivity.

#### Static Files Not Loading
```
ERROR: 404 Not Found for CSS/JS files
```
**Solution**: Check MIME type configuration in Nginx.

### Debug Mode

Enable debug logging:
```bash
export LOG_LEVEL=DEBUG
docker-compose up
```

View logs in real-time:
```bash
docker-compose logs -f
```

## 🔄 Development

### Local Development Setup

1. Install dependencies:
```bash
cd api
pip install -r requirements.txt
```

2. Run API service locally:
```bash
cd api
uvicorn src.app:api --reload --port 8000
```

3. Serve static files:
```bash
cd ui
python -m http.server 3000
```

4. Configure local Nginx (optional):
```bash
nginx -c $(pwd)/nginx/nginx.conf -p $(pwd)
```

### Adding New Features

1. **API Endpoints**: Add routes in `api/src/routes/`
2. **Frontend Features**: Modify `ui/index.html`
3. **Nginx Rules**: Update `nginx/nginx.conf`
4. **Tests**: Add tests in `api/tests/`

## 📈 Performance Optimization

### Nginx Optimization
- **Worker processes**: Configure based on CPU cores
- **Connection limits**: Set appropriate limits
- **Buffer sizes**: Optimize for your use case
- **Keepalive**: Enable connection reuse

### Caching Strategy
- **Static files**: Long-term caching with versioning
- **API responses**: Short-term caching where appropriate
- **SSL session**: Session caching for performance

### Resource Management
- **Memory limits**: Set Docker memory limits
- **CPU limits**: Configure CPU constraints
- **File descriptors**: Increase limits if needed

## 🐳 Docker Configuration

### Custom Docker Build

```bash
# Build custom images
docker build -t reverse-proxy-api:custom api/
docker build -t nginx:custom nginx/

# Use in docker-compose.yml
services:
  dmz-api:
    image: reverse-proxy-api:custom
  nginx:
    image: nginx:custom
```

### Docker Compose Profiles

```yaml
# docker-compose.yml
services:
  dmz-api:
    profiles: ["api", "full"]
  nginx:
    profiles: ["proxy", "full"]

# Deploy specific profiles
docker-compose --profile api up -d
docker-compose --profile full up -d
```

## 🔐 Production Deployment

### Security Checklist
- [ ] SSL certificates properly configured
- [ ] Strong JWT secret generated
- [ ] Default passwords changed
- [ ] Security headers enabled
- [ ] Rate limiting configured
- [ ] Log monitoring set up
- [ ] Backup procedures in place

### Performance Checklist
- [ ] Resource limits configured
- [ ] Caching strategy implemented
- [ ] Monitoring tools deployed
- [ ] Load balancing configured (if needed)
- [ ] SSL session caching enabled
- [ ] Gzip compression optimized

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch
3. Add comprehensive tests
4. Update documentation
5. Ensure security compliance
6. Submit a pull request

---

**Service Version**: 1.0.0  
**Nginx Version**: 1.27-alpine  
**FastAPI Version**: 0.112.0