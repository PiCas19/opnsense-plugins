#!/bin/bash

# health-check.sh - Check health of OPNsense Monitoring Bridge
# Queries /health and /health/detailed endpoints

# Load .env file
if [ -f .env ]; then
    export $(grep -v '^#' .env | xargs)
else
    echo "Error: .env file not found in $(pwd)"
    exit 1
fi

# Check for required variables
if [ -z "$BRIDGE_IP" ] || [ -z "$BRIDGE_PORT" ] || [ -z "$JWT_SECRET_KEY" ]; then
    echo "Error: BRIDGE_IP, BRIDGE_PORT, or JWT_SECRET_KEY not set in .env"
    exit 1
fi

# Generate JWT token for /health/detailed (requires python-jose)
JWT_TOKEN=$(python3 -c "import os; from jose import jwt; from datetime import datetime, timedelta; payload = {'exp': datetime.utcnow() + timedelta(hours=1), 'iat': datetime.utcnow(), 'sub': 'health_check', 'role': 'monitor'}; print(jwt.encode(payload, os.getenv('JWT_SECRET_KEY'), algorithm='HS256'))")
if [ $? -ne 0 ]; then
    echo "Error: Failed to generate JWT token"
    exit 1
fi

# Test /health endpoint
echo "Testing /health endpoint at https://$BRIDGE_IP:$BRIDGE_PORT/health..."
response=$(curl -k -s "https://$BRIDGE_IP:$BRIDGE_PORT/health")
if [ $? -eq 0 ] && echo "$response" | grep -q '"status": "ok"'; then
    echo "Health check passed: $response"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - /health: $response" >> logs/bridge.log
else
    echo "Health check failed: $response"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - /health failed: $response" >> logs/bridge.log
    exit 1
fi

# Test /health/detailed endpoint
echo "Testing /health/detailed endpoint..."
response=$(curl -k -s -H "Authorization: Bearer $JWT_TOKEN" "https://$BRIDGE_IP:$BRIDGE_PORT/health/detailed")
if [ $? -eq 0 ] && echo "$response" | grep -q '"status": "ok"'; then
    echo "Detailed health check passed: $response"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - /health/detailed: $response" >> logs/bridge.log
else
    echo "Detailed health check failed: $response"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - /health/detailed failed: $response" >> logs/bridge.log
    exit 1
fi

echo "All health checks passed."