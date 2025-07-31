#!/bin/bash

# setup-bridge.sh - Setup script for OPNsense Monitoring Bridge
# Loads environment variables from .env and initializes directories and certificates

# Load .env file
if [ -f .env ]; then
    export $(grep -v '^#' .env | xargs)
else
    echo "Error: .env file not found in $(pwd)"
    exit 1
fi

# Create directories
mkdir -p certs logs backups

# Generate self-signed certificates if they don't exist
if [ ! -f "$SSL_CERT_PATH" ] || [ ! -f "$SSL_KEY_PATH" ]; then
    echo "Generating self-signed certificates..."
    openssl req -x509 -newkey rsa:4096 -nodes \
        -out "$SSL_CERT_PATH" \
        -keyout "$SSL_KEY_PATH" \
        -days 365 \
        -subj "/C=CH/ST=Zurich/L=Zurich/O=OPNsenseBridge/OU=DMZ/CN=bridge.example.com"
    if [ $? -eq 0 ]; then
        echo "Certificates generated: $SSL_CERT_PATH, $SSL_KEY_PATH"
    else
        echo "Error: Failed to generate certificates"
        exit 1
    fi
fi

# Copy CA certificate if provided
if [ -n "$SSL_CA_PATH" ] && [ ! -f "$SSL_CA_PATH" ]; then
    echo "Warning: CA certificate ($SSL_CA_PATH) not found. Skipping CA setup."
fi

# Set permissions
chmod -R 600 certs
chmod -R 700 logs backups

# Verify environment variables
required_vars=(BRIDGE_IP BRIDGE_PORT JWT_SECRET_KEY OPNSENSE_HOST OPNSENSE_API_KEY OPNSENSE_API_SECRET)
for var in "${required_vars[@]}"; do
    if [ -z "${!var}" ]; then
        echo "Error: Required environment variable $var is not set in .env"
        exit 1
    fi
done

echo "Setup completed successfully."
echo "BRIDGE_IP: $BRIDGE_IP"
echo "BRIDGE_PORT: $BRIDGE_PORT"
echo "SSL_CERT_PATH: $SSL_CERT_PATH"
echo "Logs directory: $(pwd)/logs"
echo "Backups directory: $(pwd)/backups"