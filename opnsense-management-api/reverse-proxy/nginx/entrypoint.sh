#!/bin/sh
set -e

SSL_DIR="/etc/ssl/nginx"
CERT_FILE="$SSL_DIR/server.crt"
KEY_FILE="$SSL_DIR/server.key"

# usa il valore passato da compose, default localhost
PUBLIC_FQDN="${PUBLIC_FQDN:-localhost}"

mkdir -p "$SSL_DIR"

# se mancano, genera self-signed
if [ ! -f "$CERT_FILE" ] || [ ! -f "$KEY_FILE" ]; then
  echo "[entrypoint] Genero certificato self-signed per ${PUBLIC_FQDN}..."
  openssl req -x509 -newkey rsa:4096 \
    -keyout "$KEY_FILE" -out "$CERT_FILE" \
    -days 365 -nodes -subj "/CN=${PUBLIC_FQDN}" \
    -addext "subjectAltName=DNS:${PUBLIC_FQDN},DNS:localhost,IP:127.0.0.1" \
    >/dev/null 2>&1
  chmod 600 "$KEY_FILE"
  chmod 644 "$CERT_FILE"
else
  echo "[entrypoint] Certificati già presenti."
fi

echo "[entrypoint] Avvio Nginx…"
nginx -t
exec nginx -g "daemon off;"