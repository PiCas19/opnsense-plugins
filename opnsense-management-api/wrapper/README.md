# OPNsense Wrapper Service

A FastAPI-based microservice that provides a RESTful interface to OPNsense firewall API. This service acts as a wrapper around the OPNsense API, offering enhanced error handling, logging, and health monitoring capabilities.

## 🎯 Overview

The wrapper service simplifies interaction with OPNsense firewalls by providing:
- Standardized REST API endpoints
- Comprehensive error handling and logging
- Health check monitoring
- Request/response validation
- Automatic connection management

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Client App    │───►│ Wrapper Service │───►│ OPNsense API    │
│                 │    │   (FastAPI)     │    │   (Firewall)    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 🚀 Quick Start

### Prerequisites

- Docker and Docker Compose
- Python 3.11+ (for local development)
- Access to OPNsense firewall with API enabled
- OPNsense API key and secret

### Docker Deployment (Recommended)

1. Clone the repository and navigate to the wrapper directory:
```bash
cd wrapper
```

2. Create environment configuration:
```bash
cp .env.example .env
```

3. Configure your `.env` file:
```env
# OPNsense Configuration
OPNSENSE_HOST=https://your-opnsense-host
OPNSENSE_API_KEY=your-api-key
OPNSENSE_API_SECRET=your-api-secret
OPNSENSE_VERIFY_SSL=true
OPNSENSE_TIMEOUT=30

# Service Configuration
PORT=8080
LOG_LEVEL=INFO
```

4. Deploy with Docker Compose:
```bash
docker-compose up -d
```

5. Verify the service is running:
```bash
curl http://localhost:8080/health
```

### Local Development

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Run the service:
```bash
uvicorn src.app:api --reload --host 0.0.0.0 --port 8080
```

## 📋 API Endpoints

### Health Endpoints

#### GET /health
Basic health check endpoint.

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2024-01-01T12:00:00Z"
}
```

#### GET /health/detailed
Comprehensive health check with OPNsense connectivity test.

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2024-01-01T12:00:00Z",
  "opnsense_connectivity": "ok",
  "response_time_ms": 150
}
```

### Firewall Rules Management

#### GET /api/firewall/rules
Retrieve all firewall rules.

**Response:**
```json
{
  "rules": [
    {
      "uuid": "rule-uuid-1",
      "description": "Allow HTTP",
      "action": "pass",
      "interface": "wan",
      "source": "any",
      "destination": "any",
      "enabled": true
    }
  ]
}
```

#### POST /api/firewall/rules
Create a new firewall rule.

**Request:**
```json
{
  "description": "Allow HTTPS",
  "action": "pass",
  "interface": "wan",
  "protocol": "tcp",
  "destination_port": "443"
}
```

#### PUT /api/firewall/rules/{rule_id}
Update an existing firewall rule.

#### DELETE /api/firewall/rules/{rule_id}
Delete a firewall rule.

## 🔧 Configuration

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `OPNSENSE_HOST` | OPNsense firewall URL | - | Yes |
| `OPNSENSE_API_KEY` | API key for authentication | - | Yes |
| `OPNSENSE_API_SECRET` | API secret for authentication | - | Yes |
| `OPNSENSE_VERIFY_SSL` | Enable SSL certificate verification | `true` | No |
| `OPNSENSE_TIMEOUT` | Request timeout in seconds | `30` | No |
| `PORT` | Service port | `8080` | No |
| `LOG_LEVEL` | Logging level | `INFO` | No |

### OPNsense API Setup

1. Access your OPNsense web interface
2. Navigate to **System > Access > Users**
3. Create a new user or edit existing user
4. Generate API credentials in the **API keys** tab
5. Assign appropriate privileges (e.g., Firewall: Rules)

## 🏗️ Project Structure

```
wrapper/
├── src/
│   ├── app.py              # FastAPI application
│   ├── config.py           # Configuration management
│   ├── opnsense/
│   │   ├── __init__.py
│   │   ├── client.py       # OPNsense API client
│   │   └── errors.py       # Custom exception classes
│   ├── routes/
│   │   ├── health.py       # Health check endpoints
│   │   └── rules.py        # Firewall rules endpoints
│   ├── swagger/
│   │   └── openapi.yaml    # OpenAPI specification
│   └── utils/
│       └── logger.py       # Logging configuration
├── tests/
│   ├── conftest.py         # Test configuration
│   └── unit/
│       ├── test_app.py
│       ├── test_client.py
│       ├── test_config.py
│       ├── test_errors.py
│       ├── test_routes_health.py
│       └── test_routes_rules.py
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

## 🧪 Testing

### Running Tests

```bash
# Run all tests
python -m pytest tests/ -v

# Run with coverage
python -m pytest tests/ -v --cov=src

# Run specific test file
python -m pytest tests/unit/test_client.py -v

# Run tests in watch mode (requires pytest-watch)
ptw tests/
```

### Test Coverage

The project maintains high test coverage across all components:
- API client functionality
- Route handlers
- Configuration management
- Error handling
- Health checks

## 🔍 Monitoring & Logging

### Logging Configuration

The service uses structured logging with the following levels:
- `DEBUG`: Detailed debugging information
- `INFO`: General operational messages
- `WARNING`: Warning messages for potential issues
- `ERROR`: Error messages for failures

### Health Monitoring

The service provides multiple health check endpoints:
- `/health`: Basic service health
- `/health/detailed`: Comprehensive health with OPNsense connectivity

### Metrics

Consider integrating with monitoring solutions:
- Prometheus metrics endpoint (can be added)
- Health check monitoring
- Response time tracking

## 🐛 Troubleshooting

### Common Issues

#### Connection Refused
```
ERROR: Connection refused to OPNsense host
```
**Solution**: Verify OPNsense host URL and network connectivity.

#### Authentication Failed
```
ERROR: Authentication failed - Invalid API credentials
```
**Solution**: Check API key and secret configuration.

#### SSL Certificate Error
```
ERROR: SSL certificate verification failed
```
**Solution**: Set `OPNSENSE_VERIFY_SSL=false` or install proper certificates.

#### Timeout Errors
```
ERROR: Request timeout after 30 seconds
```
**Solution**: Increase `OPNSENSE_TIMEOUT` value or check network latency.

### Debug Mode

Enable debug logging:
```bash
export LOG_LEVEL=DEBUG
```

This will provide detailed information about:
- HTTP requests and responses
- API client operations
- Error stack traces

## 🔒 Security Considerations

- **API Credentials**: Store credentials securely using environment variables
- **SSL/TLS**: Enable SSL certificate verification in production
- **Network Security**: Use Docker networks to isolate services
- **Input Validation**: All inputs are validated using Pydantic models
- **Error Handling**: Sensitive information is not exposed in error messages

## 📈 Performance Optimization

- **Connection Pooling**: HTTP client reuses connections
- **Async Operations**: FastAPI provides async request handling
- **Timeout Configuration**: Configurable timeouts prevent hanging requests
- **Resource Limits**: Docker container resource limits

## 🔄 Development Workflow

### Adding New Endpoints

1. Define the route in `src/routes/`
2. Add corresponding client methods in `src/opnsense/client.py`
3. Create unit tests in `tests/unit/`
4. Update OpenAPI documentation in `src/swagger/openapi.yaml`

### Adding New Features

1. Create feature branch: `git checkout -b feature/new-feature`
2. Implement changes with tests
3. Run test suite: `pytest tests/ -v --cov=src`
4. Update documentation
5. Submit pull request

## 🐳 Docker Configuration

### Building Custom Images

```bash
# Build custom image
docker build -t opnsense-wrapper:custom .

# Run with custom image
docker run -p 8080:8080 --env-file .env opnsense-wrapper:custom
```

### Docker Compose Override

Create `docker-compose.override.yml` for local development:
```yaml
services:
  opnsense-wrapper:
    volumes:
      - ./src:/app/src
    command: uvicorn src.app:api --reload --host 0.0.0.0 --port 8080
```

## 📚 API Documentation

Interactive API documentation is available at:
- **Swagger UI**: `http://localhost:8080/docs`
- **ReDoc**: `http://localhost:8080/redoc`
- **OpenAPI JSON**: `http://localhost:8080/openapi.json`

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Update documentation
6. Submit a pull request

---

**Service Version**: 1.0.0  
**FastAPI Version**: 0.112.0  
**Python Version**: 3.11+