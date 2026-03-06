# OPNsense Security & Management Platform

A comprehensive ecosystem for OPNsense firewall management and security enhancement, consisting of advanced management APIs and specialized security plugins.

## 🏗️ Project Overview

This platform provides two complementary components:

- **🌐 Management API** - RESTful API platform for OPNsense firewall management
- **🔒 Security Plugins** - Advanced security plugins suite for enhanced protection

```
┌─────────────────────────────────────────────────────────────┐
│                OPNsense Security Platform                   │
├─────────────────────────────┬───────────────────────────────┤
│       Management API        │      Security Plugins         │
│                             │                               │
│  ┌─────────────────────┐    │  ┌─────────────────────────┐  │
│  │   Reverse Proxy     │    │  │    AdvInspector         │  │
│  │  (Auth + SSL + UI)  │    │  │ (Packet Inspection)     │  │
│  └─────────────────────┘    │  └─────────────────────────┘  │
│            │                │                               │
│  ┌─────────────────────┐    │  ┌─────────────────────────┐  │
│  │  Wrapper Service    │    │  │   DeepInspector         │  │
│  │  (OPNsense API)     │◄───┼──┤ (Industrial Protocols)  │  │
│  └─────────────────────┘    │  └─────────────────────────┘  │
│                             │                               │
│                             │  ┌─────────────────────────┐  │
│                             │  │     NetZones            │  │
│                             │  │ (Network Segmentation)  │  │
│                             │  └─────────────────────────┘  │
│                             │                               │
│                             │  ┌─────────────────────────┐  │
│                             │  │     WebGuard            │  │
│                             │  │   (WAF Protection)      │  │
│                             │  └─────────────────────────┘  │
└─────────────────────────────┴───────────────────────────────┘
```

## 📁 Repository Structure

```
.
├── README.md                          # This file
├── opnsense-management-api/           # Management API Platform
│   ├── README.md
│   ├── docs/
│   │   ├── api-documentation.md
│   │   └── deployment-guide.md
│   ├── reverse-proxy/                 # Secure Gateway & Web UI
│   │   ├── api/                       # FastAPI backend
│   │   ├── nginx/                     # SSL termination & proxy
│   │   ├── ui/                        # Web interface
│   │   └── docker-compose.yml
│   └── wrapper/                       # OPNsense API Wrapper
│       ├── src/                       # Python FastAPI service
│       ├── tests/                     # Comprehensive test suite
│       └── docker-compose.yml
└── plugins/                           # Security Plugins Suite
    ├── README.md
    ├── install_signed_plugins.sh      # Automated installer
    ├── os-advinspector/               # Advanced packet inspection
    ├── os-deepinspector/              # Deep packet inspection
    ├── os-netzones/                   # Network segmentation
    └── os-webguard/                   # Web application firewall
```

## 🚀 Quick Start

### Prerequisites

- **OPNsense**: 23.1 or higher
- **Docker & Docker Compose**: 20.10+ and 2.0+
- **Python**: 3.11+ (for development)
- **Git**: For cloning repositories

### 📦 Download Complete Package (Recommended)

Get the complete pre-built platform package with all components included:

```bash
# Download the latest release package
wget https://github.com/your-repo/opnsense-platform/releases/latest/download/opnsense-platform-latest.tar.gz

# Extract the package
tar -xzf opnsense-platform-latest.tar.gz
cd opnsense-platform-*

# Run the automated installation
./install.sh
```

**Package includes:**
- ✅ Management API (Wrapper + Reverse Proxy)
- ✅ Security Plugins Suite (4 plugins)
- ✅ Pre-built plugin packages
- ✅ Complete documentation
- ✅ Automated installation scripts
- ✅ Example configurations

### Alternative Installation Methods

### Option 1: Management API Only

```bash
# Clone and deploy the management API
git clone <repository-url>
cd opnsense-management-api

# Configure environment
cp wrapper/.env.example wrapper/.env
cp reverse-proxy/.env.example reverse-proxy/.env
# Edit .env files with your OPNsense credentials

# Deploy services
docker-compose -f wrapper/docker-compose.yml up -d
docker-compose -f reverse-proxy/docker-compose.yml up -d

# Access the platform
open https://your-domain.com
```

### Option 2: Security Plugins Only

```bash
# Clone and install plugins
git clone <repository-url>
cd plugins

# Run automated installation
sudo ./install_signed_plugins.sh

# Access plugins via OPNsense web interface
# Services → [Plugin Name]
```

### Option 3: Complete Platform

```bash
# Deploy both components
git clone <repository-url>

# Deploy Management API
cd opnsense-management-api
# Configure .env files
docker-compose -f wrapper/docker-compose.yml up -d
docker-compose -f reverse-proxy/docker-compose.yml up -d

# Install Security Plugins
cd ../plugins
sudo ./install_signed_plugins.sh
```

## 🌐 Management API Platform

### Features
- **🔐 JWT Authentication** - Secure token-based authentication
- **🛡️ SSL/TLS Termination** - End-to-end encryption
- **📊 Health Monitoring** - Service and OPNsense connectivity checks
- **🔧 Firewall Management** - Complete CRUD operations for firewall rules
- **📝 Comprehensive Logging** - Structured logging with multiple levels
- **🚀 Docker Deployment** - Containerized microservices architecture

### Services

#### Reverse Proxy (Port 443)
- **Nginx**: SSL termination, static file serving, load balancing
- **DMZ API**: Authentication, request validation, API gateway
- **Web UI**: Responsive interface for firewall management

#### Wrapper Service (Port 8080)
- **FastAPI**: RESTful API wrapper for OPNsense
- **Health Checks**: Service and upstream connectivity monitoring
- **Error Handling**: Comprehensive error management and logging

### API Endpoints

```bash
# Authentication
POST /api/auth/login
POST /api/auth/refresh

# Firewall Rules
GET    /api/rules
POST   /api/rules
GET    /api/rules/{uuid}
PUT    /api/rules/{uuid}
DELETE /api/rules/{uuid}
POST   /api/rules/{uuid}/toggle
POST   /api/rules/apply

# Health Monitoring
GET /api/health
GET /api/health/opnsense
```

## 🔒 Security Plugins Suite

### Plugin Overview

#### 🔍 AdvInspector
**Advanced Packet Inspection Engine**
- Real-time packet analysis
- Custom rule creation and management
- Threat detection and alerting
- Traffic flow monitoring

#### 🛡️ DeepInspector  
**Industrial Protocol Deep Inspection**
- Layer 7 protocol analysis
- Industrial protocol support (Modbus, DNP3)
- Machine learning threat detection
- SCADA system protection

#### 🌐 NetZones
**Network Segmentation & Zone Management**
- Automatic network zone discovery
- Inter-zone policy enforcement
- Zero-trust architecture support
- Dynamic traffic control

#### 🛡️ WebGuard
**Web Application Firewall**
- Layer 7 web protection
- Geographic threat intelligence
- Behavioral analysis engine
- Real-time attack blocking

### Plugin Installation

```bash
# Automated installation
cd plugins
sudo ./install_signed_plugins.sh

# Manual installation per plugin
cd /usr/plugins/security/os-advinspector
git init && git add . && git commit -m "Initial commit: os-advinspector"
make clean && make package

# Repeat for each plugin
```

## 📚 Documentation

### Management API Documentation
- [📖 Main API README](opnsense-management-api/README.md)
- [🔌 API Documentation](opnsense-management-api/docs/api-documentation.md)
- [🚀 Deployment Guide](opnsense-management-api/docs/deployment-guide.md)
- [🔄 Wrapper Service](opnsense-management-api/wrapper/README.md)
- [🌐 Reverse Proxy](opnsense-management-api/reverse-proxy/README.md)

### Security Plugins Documentation
- [🔒 Plugins README](plugins/README.md)
- [🔧 Installation Guide](plugins/README.md#manual-installation)
- [⚙️ Configuration](plugins/README.md#configuration)
- [🔌 API Integration](plugins/README.md#api-integration)

## 🔧 Configuration

### Management API Configuration

#### Environment Variables
```env
# OPNsense Configuration
OPNSENSE_URL=https://your-opnsense-host
OPNSENSE_API_KEY=your-api-key
OPNSENSE_API_SECRET=your-api-secret

# Authentication
JWT_SECRET=your-secure-jwt-secret
DEMO_USERNAME=admin
DEMO_PASSWORD=secure-password

# Service Configuration
LOG_LEVEL=INFO
WRAPPER_TIMEOUT=30
```

### Security Plugins Configuration

Access plugin configurations via OPNsense web interface:
- **AdvInspector**: `Services → AdvInspector`
- **DeepInspector**: `Services → DeepInspector`
- **NetZones**: `Services → NetZones`
- **WebGuard**: `Services → WebGuard`

## 🧪 Testing

### Management API Tests

```bash
# Wrapper service tests
cd opnsense-management-api/wrapper
python -m pytest tests/ -v --cov=src

# Reverse proxy tests
cd opnsense-management-api/reverse-proxy/api
python -m pytest tests/ -v --cov=src
```

### Security Plugins Tests

```bash
# Test individual plugin functionality
cd plugins/os-advinspector
make test

# Integration testing
cd plugins
./test_all_plugins.sh
```

## 🔍 Monitoring & Health Checks

### Service Health Monitoring

```bash
# Management API health
curl http://localhost:8080/api/health
curl https://your-domain.com/api/health

# OPNsense connectivity
curl http://localhost:8080/api/health/opnsense

# Plugin status via OPNsense web interface
```

### Log Monitoring

```bash
# Management API logs
docker-compose logs -f wrapper
docker-compose logs -f reverse-proxy

# Plugin logs
tail -f /var/log/advinspector/packet_inspector.log
tail -f /var/log/deepinspector/engine.log
tail -f /var/log/netzones/evaluator.log
tail -f /var/log/webguard/threats.log
```

## 🐛 Troubleshooting

### Common Issues

#### Management API Issues
```bash
# Service connectivity
docker-compose ps
curl http://localhost:8080/api/health

# OPNsense connection
ping your-opnsense-host
curl -k https://your-opnsense-host/api/core/firmware/status
```

#### Plugin Issues
```bash
# Check plugin installation
pkg info | grep -E "(advinspector|deepinspector|netzones|webguard)"

# Verify plugin services
service advinspector status
service deepinspector status
service netzones status
service webguard status
```

### Debug Mode

```bash
# Enable debug logging for API
export LOG_LEVEL=DEBUG

# Check plugin configuration
configctl plugin list

# Restart services
service configd restart
configctl plugin reload
```

## 🔄 Development

### Development Environment

```bash
# Management API development
cd opnsense-management-api
# See individual service README files for detailed setup

# Plugin development
cd plugins
# Install opnsense-code framework
pkg install opnsense-code
```

### Contributing

1. **Fork the repository**
2. **Create feature branch** (`git checkout -b feature/amazing-feature`)
3. **Add comprehensive tests**
4. **Update documentation**
5. **Commit changes** (`git commit -m 'Add amazing feature'`)
6. **Push to branch** (`git push origin feature/amazing-feature`)
7. **Create Pull Request**

## 🔐 Security Considerations

### Management API Security
- **JWT Authentication** with configurable expiration
- **SSL/TLS encryption** for all communications
- **Security headers** (HSTS, CSP, XSS protection)
- **Rate limiting** on sensitive endpoints
- **Input validation** and sanitization

### Plugin Security
- **Privilege separation** for plugin services
- **Secure configuration** storage
- **Audit logging** for all security events
- **Regular security updates** via package management

## 📈 Performance & Scalability

### Management API Performance
- **Docker containerization** for easy scaling
- **Nginx load balancing** for high availability
- **Connection pooling** for OPNsense API calls
- **Caching strategies** for frequently accessed data

### Plugin Performance
- **Optimized packet processing** for minimal latency
- **Efficient rule evaluation** algorithms
- **Resource monitoring** and limits
- **Background processing** for intensive operations

## 🛡️ Use Cases

### Enterprise Network Security
- **Centralized firewall management** via API
- **Advanced threat detection** with DeepInspector
- **Network segmentation** with NetZones
- **Web application protection** with WebGuard

### Industrial Network Protection
- **SCADA system monitoring** with DeepInspector
- **Critical infrastructure protection**
- **Protocol-specific threat detection**
- **Compliance reporting** and auditing

### Managed Security Services
- **Multi-tenant firewall management**
- **Automated security policies**
- **Real-time threat intelligence**
- **Customer portal integration**

## 📋 Deployment Checklist

### Pre-Deployment
- [ ] OPNsense 23.1+ running
- [ ] API credentials configured
- [ ] SSL certificates obtained
- [ ] Network connectivity verified
- [ ] Docker environment ready

### Management API Deployment
- [ ] Environment files configured
- [ ] SSL certificates installed
- [ ] Services deployed and healthy
- [ ] Authentication tested
- [ ] API endpoints verified

### Security Plugins Deployment
- [ ] opnsense-code installed
- [ ] Plugins built and packaged
- [ ] Services installed and started
- [ ] Web interface accessible
- [ ] Plugin functionality verified

## 📞 Support & Community

### Documentation
- [🔌 API Reference](opnsense-management-api/docs/api-documentation.md)
- [🚀 Deployment Guide](opnsense-management-api/docs/deployment-guide.md)

### Community
- **GitHub Issues**: Report bugs and request features
- **Discussions**: Community support and Q&A
- **Wiki**: Additional documentation and tutorials

### Professional Support
- **Email**: pierpaolo.casati@bluewin.ch

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **OPNsense Team** for the excellent firewall platform
- **Community Contributors** for testing and feedback
- **Security Researchers** for vulnerability reporting
- **Open Source Community** for libraries and tools

---

**Platform Version**: 1.0.0  
**OPNsense Compatibility**: 25.1.10   
**Last Updated**: 2025  
**Maintainer**: Pierpoalo Casati
