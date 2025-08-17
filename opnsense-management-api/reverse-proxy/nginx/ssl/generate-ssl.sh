#!/bin/sh

SSL_DIR="/etc/ssl/nginx"
CERT_FILE="$SSL_DIR/server.crt"
KEY_FILE="$SSL_DIR/server.key"

# Crea la directory se non esiste
mkdir -p "$SSL_DIR"

# Genera certificato self-signed se non esiste
if [ ! -f "$CERT_FILE" ] || [ ! -f "$KEY_FILE" ]; then
    echo "Generating SSL certificate..."
    
    # Install openssl se non presente
    apk add --no-cache openssl
    
    # Genera certificato self-signed
    openssl req -x509 -newkey rsa:4096 -keyout "$KEY_FILE" -out "$CERT_FILE" \
        -days 365 -nodes -subj "/C=CH/ST=Ticino/L=Massagno/O=OPNsense Management/OU=IT/CN=opnsense-proxy" \
        -addext "subjectAltName=DNS:localhost,DNS:opnsense-proxy,IP:127.0.0.1,IP:192.168.216.50"
    
    # Set permissions
    chmod 600 "$KEY_FILE"
    chmod 644 "$CERT_FILE"
    
    echo "SSL certificate generated successfully"
else
    echo "SSL certificate already exists"
fi