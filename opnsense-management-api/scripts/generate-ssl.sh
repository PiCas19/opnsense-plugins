#!/bin/bash

# Script to generate self-signed SSL certificates for Nginx
# Usage: ./scripts/generate-ssl.sh

set -euo pipefail

# Output colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
SSL_DIR="./monitoring/nginx/ssl"
CERT_DAYS=365
KEY_SIZE=2048

# Certificate details
COUNTRY="CH"
STATE="Ticino"
CITY="Viganello"
ORG="OPNsense Monitoring"
OU="IT Department"
CN="localhost"
EMAIL="admin@localhost"

echo -e "${BLUE} Generating SSL certificates for OPNsense Monitoring${NC}"
echo -e "${YELLOW} Directory: ${SSL_DIR}${NC}"

# Create directory if it doesn't exist
mkdir -p "${SSL_DIR}"

# Check if OpenSSL is installed
if ! command -v openssl &> /dev/null; then
    echo -e "${RED} OpenSSL is not installed!${NC}"
    echo "Install OpenSSL:"
    echo "  Ubuntu/Debian: sudo apt-get install openssl"
    echo "  CentOS/RHEL:   sudo yum install openssl"
    echo "  macOS:         brew install openssl"
    exit 1
fi

# Generate private key
echo -e "${YELLOW} Generating private key (${KEY_SIZE} bits)...${NC}"
openssl genrsa -out "${SSL_DIR}/nginx.key" ${KEY_SIZE}

# Generate Certificate Signing Request (CSR)
echo -e "${YELLOW} Generating Certificate Signing Request...${NC}"
openssl req -new -key "${SSL_DIR}/nginx.key" -out "${SSL_DIR}/nginx.csr" \
    -subj "/C=${COUNTRY}/ST=${STATE}/L=${CITY}/O=${ORG}/OU=${OU}/CN=${CN}/emailAddress=${EMAIL}"

# Create OpenSSL config for extensions
cat > "${SSL_DIR}/nginx.conf" << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = ${COUNTRY}
ST = ${STATE}
L = ${CITY}
O = ${ORG}
OU = ${OU}
CN = ${CN}
emailAddress = ${EMAIL}

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = *.localhost
DNS.3 = opnsense-monitoring
DNS.4 = *.opnsense-monitoring
IP.1 = 127.0.0.1
IP.2 = 172.16.216.20
IP.3 = 192.168.216.50
IP.4 = ::1
EOF

# Generate self-signed certificate
echo -e "${YELLOW}📜 Generating self-signed certificate (${CERT_DAYS} days)...${NC}"
openssl x509 -req -in "${SSL_DIR}/nginx.csr" \
    -signkey "${SSL_DIR}/nginx.key" \
    -out "${SSL_DIR}/nginx.crt" \
    -days ${CERT_DAYS} \
    -extensions v3_req \
    -extfile "${SSL_DIR}/nginx.conf"

# Create alternate copies for compatibility
echo -e "${YELLOW}📄 Creating compatibility copies...${NC}"
cp "${SSL_DIR}/nginx.crt" "${SSL_DIR}/fullchain.pem"
cp "${SSL_DIR}/nginx.key" "${SSL_DIR}/privkey.pem"

# Set proper permissions
chmod 600 "${SSL_DIR}"/*.key "${SSL_DIR}"/*.pem
chmod 644 "${SSL_DIR}"/*.crt

# Cleanup temporary files
rm -f "${SSL_DIR}/nginx.csr" "${SSL_DIR}/nginx.conf"

# Verify generated certificate
echo -e "${YELLOW}🔍 Verifying generated certificate...${NC}"
CERT_INFO=$(openssl x509 -in "${SSL_DIR}/nginx.crt" -text -noout)

# Extract key info
VALID_FROM=$(echo "$CERT_INFO" | grep "Not Before" | cut -d: -f2-)
VALID_TO=$(echo "$CERT_INFO" | grep "Not After" | cut -d: -f2-)
FINGERPRINT=$(openssl x509 -in "${SSL_DIR}/nginx.crt" -fingerprint -sha256 -noout | cut -d= -f2)

echo -e "${GREEN} SSL certificates successfully generated!${NC}"
echo ""
echo -e "${BLUE} Certificate Information:${NC}"
echo "   CN: ${CN}"
echo "   Valid from:${VALID_FROM}"
echo "   Valid until:${VALID_TO}"
echo "   SHA256 Fingerprint: ${FINGERPRINT}"
echo ""
echo -e "${BLUE} Generated files:${NC}"
echo "   ${SSL_DIR}/nginx.key      (private key)"
echo "   ${SSL_DIR}/nginx.crt      (certificate)"
echo "   ${SSL_DIR}/fullchain.pem  (certificate alias)"
echo "   ${SSL_DIR}/privkey.pem    (private key alias)"
echo ""
echo -e "${YELLOW} WARNING:${NC}"
echo "   - These are self-signed certificates for testing/development"
echo "   - Browsers will show a security warning"
echo "   - For production, use certificates from a trusted CA"
echo ""
echo -e "${GREEN} Ready to start services with HTTPS!${NC}"
