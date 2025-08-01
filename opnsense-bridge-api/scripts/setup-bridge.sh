#!/bin/bash
# setup-bridge.sh - Setup script for OPNsense Monitoring Bridge

set -e

# Load .env file
if [ -f .env ]; then
    export $(grep -v '^#' .env | xargs)
else
    echo "Error: .env file not found in $(pwd)"
    exit 1
fi

# Create directories (including app/certs)
mkdir -p app/certs logs backups prometheus

# Convert container paths to host paths
HOST_CERT_PATH="app/certs/server.crt"
HOST_KEY_PATH="app/certs/server.key"
HOST_CA_PATH="app/certs/ca.crt"

echo "Container SSL_CERT_PATH: $SSL_CERT_PATH"
echo "Container SSL_KEY_PATH: $SSL_KEY_PATH"
echo "Host cert path: $HOST_CERT_PATH"
echo "Host key path: $HOST_KEY_PATH"

# Generate self-signed certificates if they don't exist
if [ ! -f "$HOST_CERT_PATH" ] || [ ! -f "$HOST_KEY_PATH" ]; then
    echo "Generating self-signed certificates..."
    
    openssl req -x509 -newkey rsa:4096 -nodes \
        -out "$HOST_CERT_PATH" \
        -keyout "$HOST_KEY_PATH" \
        -days 365 \
        -subj "/C=IT/ST=DMZ/L=DMZ/O=OPNsenseBridge/OU=DMZ/CN=172.16.216.10"
    
    if [ $? -eq 0 ]; then
        echo "Certificates generated successfully!"
        echo "Certificate: $HOST_CERT_PATH"
        echo "Private Key: $HOST_KEY_PATH"
        
        # Set secure permissions
        chmod 600 "$HOST_KEY_PATH"
        chmod 644 "$HOST_CERT_PATH"
    else
        echo "Error: Failed to generate certificates"
        exit 1
    fi
else
    echo "Certificates already exist:"
    echo "Certificate: $HOST_CERT_PATH"
    echo "Private Key: $HOST_KEY_PATH"
fi

# Set permissions for directories
chmod 755 logs backups prometheus app/certs

# Verify environment variables
required_vars=(BRIDGE_IP BRIDGE_PORT JWT_SECRET_KEY OPNSENSE_HOST OPNSENSE_API_KEY OPNSENSE_API_SECRET)
for var in "${required_vars[@]}"; do
    if [ -z "${!var}" ]; then
        echo "Error: Required environment variable $var is not set in .env"
        exit 1
    fi
done

echo ""
echo "Setup completed successfully."
echo "BRIDGE_IP: $BRIDGE_IP"
echo "BRIDGE_PORT: $BRIDGE_PORT"
echo "Certificates created on host: $HOST_CERT_PATH, $HOST_KEY_PATH"
echo "Container will read from: $SSL_CERT_PATH, $SSL_KEY_PATH"
echo "Logs directory: $(pwd)/logs"
echo "Backups directory: $(pwd)/backups"