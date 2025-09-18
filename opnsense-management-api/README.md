# OPNsense Management Platform

A comprehensive microservices-based platform for managing OPNsense firewall configurations through a secure reverse proxy architecture. This platform provides authenticated access to OPNsense API endpoints with enhanced security, logging, and monitoring capabilities.

## 🏗️ Architecture Overview

The platform consists of two main components:

- **Wrapper Service**: Direct interface to OPNsense API with health monitoring and rule management
- **Reverse Proxy**: Secure gateway with authentication, SSL termination, and web UI

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Web Browser   │◄──►│  Reverse Proxy   │◄──►│ Wrapper Service │
│                 │    │  (Nginx + API)   │    │  (OPNsense API) │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

## 🚀 Quick Start

### Prerequisites

- Docker and Docker Compose
- SSL certificates for HTTPS
- OPNsense firewall with API access configured

### Environment Setup

1. Clone the repository:
```bash
git clone <repository-url>
cd opnsense-management-platform
```

2. Configure environment variables:
```bash
# Copy example environment files
cp wrapper/.env.example wrapper/.env
cp reverse-proxy/.env.example reverse-proxy/.env
```

3. Update configuration files with your OPNsense credentials and SSL certificates.

### Deployment Options

#### Option 1: Full Platform Deployment
```bash
# Deploy both services
docker-compose -f wrapper/docker-compose.yml up -d
docker-compose -f reverse-proxy/docker-compose.yml up -d
```

#### Option 2: Individual Service Deployment
```bash
# Deploy only the wrapper service
cd wrapper
docker-compose up -d

# Deploy only the reverse proxy
cd reverse-proxy
docker-compose up -d
```

## 📚 Documentation

- [API Documentation](docs/api-documentation.md) - Complete API reference and usage examples
- [Deployment Guide](docs/deployment-guide.md) - Detailed deployment instructions and configuration
- [Wrapper Service README](wrapper/README.md) - Specific documentation for the wrapper service
- [Reverse Proxy README](reverse-proxy/README.md) - Specific documentation for the reverse proxy

## 🔧 Services Overview

### Wrapper Service
- **Port**: 8080 (configurable)
- **Purpose**: Direct OPNsense API integration
- **Features**: Health checks, firewall rule management, error handling
- **Technology**: FastAPI, Python 3.11

### Reverse Proxy
- **Port**: 443 (HTTPS)
- **Purpose**: Secure gateway and web interface
- **Features**: JWT authentication, SSL termination, static file serving
- **Technology**: Nginx, FastAPI, Python 3.11

## 🛡️ Security Features

- **HTTPS/TLS**: End-to-end encryption with SSL certificates
- **JWT Authentication**: Token-based authentication system
- **Security Headers**: XSS protection, content type options, frame options
- **Network Isolation**: Docker network segmentation
- **Input Validation**: Request validation and sanitization

## 🔍 Monitoring & Logging

- Structured logging with configurable log levels
- Health check endpoints for service monitoring
- Request/response logging for audit trails
- Error tracking and reporting

## 🧪 Testing

Both services include comprehensive test suites:

```bash
# Run wrapper service tests
cd wrapper
python -m pytest tests/ -v --cov=src

# Run reverse proxy tests
cd reverse-proxy
python -m pytest api/tests/ -v --cov=src
```

## 📋 Configuration

### Environment Variables

#### Wrapper Service
- `OPNSENSE_HOST`: OPNsense firewall hostname/IP
- `OPNSENSE_API_KEY`: API key for authentication
- `OPNSENSE_API_SECRET`: API secret for authentication
- `LOG_LEVEL`: Logging level (DEBUG, INFO, WARNING, ERROR)

#### Reverse Proxy
- `DMZ_HOST`: API service hostname
- `DMZ_PORT`: API service port
- `JWT_SECRET`: Secret key for JWT token signing
- `DEMO_USERNAME`: Demo user credentials
- `DEMO_PASSWORD`: Demo user password

## 🔄 Development

### Local Development Setup

1. Install Python dependencies:
```bash
cd wrapper
pip install -r requirements.txt

cd ../reverse-proxy/api
pip install -r requirements.txt
```

2. Run services locally:
```bash
# Wrapper service
cd wrapper
uvicorn src.app:api --reload --port 8080

# Reverse proxy API
cd reverse-proxy/api
uvicorn src.app:api --reload --port 8000
```

3. Serve static files (reverse proxy UI):
```bash
cd reverse-proxy
python -m http.server 3000 --directory ui
```

## 📈 Performance Considerations

- **Caching**: Static file caching with appropriate expiration headers
- **Compression**: Gzip compression for text-based responses
- **Connection Pooling**: HTTP connection reuse for backend requests
- **Resource Limits**: Configurable timeout and connection limits

## 🐛 Troubleshooting

### Common Issues

1. **SSL Certificate Issues**: Ensure certificates are properly mounted and accessible
2. **Network Connectivity**: Verify Docker network configuration and service discovery
3. **Authentication Failures**: Check JWT secret configuration and token expiration
4. **OPNsense Connection**: Verify API credentials and network accessibility

### Debug Mode

Enable debug logging by setting `LOG_LEVEL=DEBUG` in environment variables.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For support and questions:
- Create an issue in the repository
- Check the documentation in the `docs/` directory
- Review service-specific README files for detailed configuration

---

**Version**: 1.0.0  
**Last Updated**: 2024