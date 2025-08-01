#!/bin/bash

# test-api.sh - Test OPNsense API and bridge health endpoints
# Uses .env variables for configuration

# Load .env file
if [ -f .env ]; then
    export $(grep -v '^#' .env | xargs)
else
    echo "Error: .env file not found in $(pwd)"
    exit 1
fi

# Test OPNsense API connectivity
echo "Testing OPNsense API at $OPNSENSE_HOST..."
curl -k -u "$OPNSENSE_API_KEY:$OPNSENSE_API_SECRET" "$OPNSENSE_HOST/api/diagnostics/systemhealth" > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "OPNsense API test successful"
else
    echo "OPNsense API test failed. Check OPNSENSE_HOST, OPNSENSE_API_KEY, and OPNSENSE_API_SECRET."
    exit 1
fi

# Test bridge health endpoint
echo "Testing bridge health endpoint at https://$BRIDGE_IP:$BRIDGE_PORT/health..."
curl -k "https://$BRIDGE_IP:$BRIDGE_PORT/health" > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "Bridge health endpoint test successful"
else
    echo "Bridge health endpoint test failed. Check BRIDGE_IP, BRIDGE_PORT, and SSL configuration."
    exit 1
fi

echo "All tests passed."