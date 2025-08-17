#!/usr/bin/env bash
set -euo pipefail

SSL_DIR="/etc/ssl/nginx"
CERT_FILE="${SSL_DIR}/server.crt"
KEY_FILE="${SSL_DIR}/server.key"

# Variabili opzionali
PUBLIC_FQDN="${PUBLIC_FQDN:-localhost}"

mkdir -p "$SSL_DIR"

# Genera self-signed se mancano
if [ ! -f "$CERT_FILE" ] || [ ! -f "$KEY_FILE" ]; then
  echo "[entrypoint] Genero certificato self-signed per ${PUBLIC_FQDN}..."
  openssl req -x509 -newkey rsa:4096 \
    -keyout "$KEY_FILE" -out "$CERT_FILE" \
    -days 365 -nodes -subj "/CN=${PUBLIC_FQDN}" \
    -addext "subjectAltName=DNS:${PUBLIC_FQDN},DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1
  chmod 600 "$KEY_FILE"
  chmod 644 "$CERT_FILE"
else
  echo "[entrypoint] Certificati SSL già presenti, OK."
fi

# Mostra info di base
echo "[entrypoint] Avvio Nginx con:"
echo "  - PUBLIC_FQDN=${PUBLIC_FQDN}"
echo "  - OPNSENSE_API_HOST=${OPNSENSE_API_HOST:-unset}"
echo "  - OPNSENSE_API_PORT=${OPNSENSE_API_PORT:-unset}"
echo "  - NGINX_CLIENT_MAX_BODY_SIZE=${NGINX_CLIENT_MAX_BODY_SIZE:-10m}"

# Test configurazione
nginx -t

# Avvio Nginx in foreground
exec nginx -g "daemon off;"