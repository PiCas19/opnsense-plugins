# API Documentation

Complete API reference for the OPNsense Management Platform. This documentation covers both the Wrapper Service API and the Reverse Proxy API endpoints.

## 📋 Table of Contents

- [Authentication](#authentication)
- [Wrapper Service API](#wrapper-service-api)
- [Reverse Proxy API](#reverse-proxy-api)
- [Error Handling](#error-handling)
- [Rate Limiting](#rate-limiting)
- [Examples](#examples)

## 🔐 Authentication

The Reverse Proxy uses JWT (JSON Web Token) based authentication. All API endpoints (except authentication endpoints) require a valid JWT token.

### Authentication Flow

1. **Login** with username/password to get access and refresh tokens
2. **Use access token** in Authorization header for API requests
3. **Refresh token** when access token expires

### Headers

```http
Authorization: Bearer <access_token>
Content-Type: application/json
```

---

## 🌐 Wrapper Service API

The Wrapper Service provides direct access to OPNsense firewall functionality. This service runs on port 8080 and does not require authentication.

### Base URL
```
http://localhost:8080
```

### Health Endpoints

#### GET /api/health

Basic service health check.

**Response:**
```json
{
  "ok": true,
  "service": "opnsense-wrapper-python",
  "docs": "/docs",
  "swagger": "/swagger.yaml"
}
```

**Status Codes:**
- `200` - Service is healthy

---

#### GET /api/health/opnsense

Comprehensive health check including OPNsense connectivity.

**Response (Success):**
```json
{
  "ok": true,
  "upstream": "opnsense",
  "latency_ms": 150,
  "details": {
    "total_rules": 25,
    "verify_ssl": true,
    "base_url": "https://opnsense.local"
  }
}
```

**Response (Error):**
```json
{
  "ok": false,
  "latency_ms": 5000,
  "upstream_status": 500,
  "upstream_url": "https://opnsense.local/api/firewall/filter/searchRule",
  "body": "Internal Server Error"
}
```

**Status Codes:**
- `200` - OPNsense is reachable
- `4xx` - Client error (propagated from OPNsense)
- `502` - Bad Gateway (OPNsense server error)
- `500` - Internal service error

---

### Firewall Rules Management

#### GET /api/rules

List all firewall rules with optional search filtering.

**Query Parameters:**
- `search` (string, optional): Filter rules by description

**Example Request:**
```http
GET /api/rules?search=web
```

**Response:**
```json
{
  "success": true,
  "total": 2,
  "rows": [
    {
      "uuid": "12345678-1234-1234-1234-123456789012",
      "sequence": "1",
      "enabled": "1",
      "action": "pass",
      "quick": "1",
      "interface": "wan",
      "direction": "in",
      "ipprotocol": "inet",
      "protocol": "tcp",
      "source_net": "any",
      "source_port": "",
      "destination_net": "any",
      "destination_port": "80,443",
      "description": "Allow web traffic"
    }
  ]
}
```

**Status Codes:**
- `200` - Success
- `502` - OPNsense server error
- `4xx` - Client error from OPNsense

---

#### GET /api/rules/{uuid}

Get details of a specific firewall rule.

**Path Parameters:**
- `uuid` (string, required): Rule UUID

**Response:**
```json
{
  "success": true,
  "rule": {
    "uuid": "12345678-1234-1234-1234-123456789012",
    "enabled": "1",
    "action": "pass",
    "interface": "wan",
    "protocol": "tcp",
    "destination_port": "80,443",
    "description": "Allow web traffic"
  }
}
```

**Status Codes:**
- `200` - Success
- `404` - Rule not found
- `502` - OPNsense server error

---

#### POST /api/rules

Create a new firewall rule.

**Request Body:**
```json
{
  "rule": {
    "action": "pass",
    "interface": "wan",
    "protocol": "tcp",
    "destination_port": "22",
    "description": "Allow SSH",
    "enabled": "1"
  },
  "apply": false
}
```

**Response:**
```json
{
  "success": true,
  "result": {
    "uuid": "new-rule-uuid-here"
  },
  "applied": false
}
```

**Status Codes:**
- `200` - Rule created successfully
- `400` - Invalid rule data
- `502` - OPNsense server error

---

#### POST /api/rules/{uuid}/toggle

Enable or disable a firewall rule.

**Path Parameters:**
- `uuid` (string, required): Rule UUID

**Request Body:**
```json
{
  "enabled": true,
  "apply": false
}
```

**Response:**
```json
{
  "success": true,
  "result": "saved",
  "applied": false
}
```

**Status Codes:**
- `200` - Rule toggled successfully
- `404` - Rule not found
- `502` - OPNsense server error

---

#### PUT /api/rules/{uuid}

Update an existing firewall rule.

**Path Parameters:**
- `uuid` (string, required): Rule UUID

**Request Body:**
```json
{
  "rule": {
    "description": "Updated description",
    "destination_port": "80,443,8080"
  }
}
```

**Response:**
```json
{
  "success": true,
  "result": "saved"
}
```

**Status Codes:**
- `200` - Rule updated successfully
- `404` - Rule not found
- `400` - Invalid rule data
- `502` - OPNsense server error

---

#### DELETE /api/rules/{uuid}

Delete a firewall rule.

**Path Parameters:**
- `uuid` (string, required): Rule UUID

**Response:**
```json
{
  "success": true,
  "result": "deleted"
}
```

**Status Codes:**
- `200` - Rule deleted successfully
- `404` - Rule not found
- `502` - OPNsense server error

---

#### POST /api/rules/apply

Apply pending firewall configuration changes.

**Response:**
```json
{
  "success": true,
  "result": "applied"
}
```

**Status Codes:**
- `200` - Configuration applied successfully
- `502` - OPNsense server error

---

## 🔒 Reverse Proxy API

The Reverse Proxy provides authenticated access to the wrapper service and additional management features. This service runs on port 443 (HTTPS) and requires JWT authentication.

### Base URL
```
https://your-domain.com
```

### Authentication Endpoints

#### POST /api/auth/login

Authenticate user and receive JWT tokens.

**Request Body:**
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
  "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "token_type": "bearer",
  "expires_in": 3600
}
```

**Status Codes:**
- `200` - Authentication successful
- `401` - Invalid credentials

---

#### POST /api/auth/refresh

Refresh access token using refresh token.

**Request Body:**
```json
{
  "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
}
```

**Response:**
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "token_type": "bearer",
  "expires_in": 3600
}
```

**Status Codes:**
- `200` - Token refreshed successfully
- `401` - Invalid or expired refresh token

---

### Authenticated Firewall Rules Endpoints

All endpoints below require authentication via JWT token in the Authorization header.

#### GET /api/rules

List firewall rules (authenticated proxy to wrapper service).

**Headers:**
```http
Authorization: Bearer <access_token>
```

**Query Parameters:**
- `search` (string, optional): Filter rules by description

**Response:** Same as wrapper service `/api/rules`

---

#### GET /api/rules/{uuid}

Get specific rule details (authenticated proxy).

**Headers:**
```http
Authorization: Bearer <access_token>
```

**Response:** Same as wrapper service `/api/rules/{uuid}`

---

#### POST /api/rules

Create new rule (authenticated proxy).

**Headers:**
```http
Authorization: Bearer <access_token>
Content-Type: application/json
```

**Request Body:**
```json
{
  "rule": {
    "action": "pass",
    "interface": "wan",
    "protocol": "tcp",
    "destination_port": "22",
    "description": "Allow SSH"
  },
  "apply": false
}
```

**Response:** Same as wrapper service `POST /api/rules`

---

#### POST /api/rules/{uuid}/toggle

Toggle rule enabled/disabled (authenticated proxy).

**Headers:**
```http
Authorization: Bearer <access_token>
Content-Type: application/json
```

**Request Body:**
```json
{
  "enabled": true,
  "apply": false
}
```

**Response:** Same as wrapper service `POST /api/rules/{uuid}/toggle`

---

#### PUT /api/rules/{uuid}

Update existing rule (authenticated proxy).

**Headers:**
```http
Authorization: Bearer <access_token>
Content-Type: application/json
```

**Request Body:**
```json
{
  "rule": {
    "description": "Updated rule description"
  }
}
```

**Response:** Same as wrapper service `PUT /api/rules/{uuid}`

---

#### DELETE /api/rules/{uuid}

Delete rule (authenticated proxy).

**Headers:**
```http
Authorization: Bearer <access_token>
```

**Response:** Same as wrapper service `DELETE /api/rules/{uuid}`

---

#### POST /api/rules/apply

Apply configuration changes (authenticated proxy).

**Headers:**
```http
Authorization: Bearer <access_token>
```

**Response:** Same as wrapper service `POST /api/rules/apply`

---

## ❌ Error Handling

### Error Response Format

All API errors follow a consistent format:

```json
{
  "detail": {
    "ok": false,
    "error": "Error description",
    "upstream": 500,
    "body": "Upstream error details"
  }
}
```

### HTTP Status Codes

| Code | Description |
|------|-------------|
| `200` | Success |
| `400` | Bad Request - Invalid input data |
| `401` | Unauthorized - Missing or invalid JWT token |
| `404` | Not Found - Resource doesn't exist |
| `422` | Unprocessable Entity - Validation error |
| `500` | Internal Server Error - Unexpected error |
| `502` | Bad Gateway - Upstream service error |
| `503` | Service Unavailable - Service temporarily down |

### Common Error Scenarios

#### Authentication Errors
```json
{
  "detail": "Invalid credentials"
}
```

#### Upstream Service Errors
```json
{
  "detail": {
    "upstream": 500,
    "body": "OPNsense API returned an error"
  }
}
```

#### Validation Errors
```json
{
  "detail": [
    {
      "loc": ["body", "rule", "action"],
      "msg": "field required",
      "type": "value_error.missing"
    }
  ]
}
```

---

## 🚦 Rate Limiting

Rate limiting can be configured at the Nginx level for production deployments:

```nginx
# Add to nginx.conf
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;

location /api/ {
    limit_req zone=api burst=20 nodelay;
    # ... rest of configuration
}
```

---

## 💡 Examples

### Complete Authentication Flow

```bash
# 1. Login
curl -X POST https://your-domain.com/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "secure-password"}'

# Response:
# {
#   "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
#   "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
#   "token_type": "bearer",
#   "expires_in": 3600
# }

# 2. Use access token for API calls
ACCESS_TOKEN="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."

curl -X GET https://your-domain.com/api/rules \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```

### Create and Apply Firewall Rule

```bash
# Create rule
curl -X POST https://your-domain.com/api/rules \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "rule": {
      "action": "pass",
      "interface": "wan",
      "protocol": "tcp",
      "destination_port": "22",
      "description": "Allow SSH access",
      "enabled": "1"
    },
    "apply": false
  }'

# Apply configuration
curl -X POST https://your-domain.com/api/rules/apply \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```

### Search and Filter Rules

```bash
# Search for web-related rules
curl -X GET "https://your-domain.com/api/rules?search=web" \
  -H "Authorization: Bearer $ACCESS_TOKEN"

# Get specific rule details
curl -X GET https://your-domain.com/api/rules/12345678-1234-1234-1234-123456789012 \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```

### Health Monitoring

```bash
# Check wrapper service health (direct)
curl -X GET http://localhost:8080/api/health

# Check OPNsense connectivity (direct)
curl -X GET http://localhost:8080/api/health/opnsense

# Through reverse proxy (requires authentication)
curl -X GET https://your-domain.com/health \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```

### Token Refresh

```bash
# When access token expires, use refresh token
REFRESH_TOKEN="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."

curl -X POST https://your-domain.com/api/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "'$REFRESH_TOKEN'"}'
```

---

## 🔍 Interactive Documentation

Both services provide interactive API documentation:

### Wrapper Service
- **Swagger UI**: `http://localhost:8080/docs`
- **ReDoc**: `http://localhost:8080/redoc`
- **OpenAPI JSON**: `http://localhost:8080/openapi.json`

### Reverse Proxy
- **Swagger UI**: `https://your-domain.com/docs`
- **ReDoc**: `https://your-domain.com/redoc`
- **OpenAPI JSON**: `https://your-domain.com/openapi.json`

---

**API Version**: 1.0.0  
**Last Updated**: 2024  
**OpenAPI Version**: 3.0.0