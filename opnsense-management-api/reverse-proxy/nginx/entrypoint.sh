#!/usr/bin/env bash
set -euo pipefail

: "${PUBLIC_FQDN:=localhost}"
: "${NGINX_CLIENT_MAX_BODY_SIZE:=10m}"

SSL_DIR="/etc/ssl/nginx"
HTPASS="/etc/nginx/htpasswd"
TEMPLATE="/etc/nginx/templates/nginx.conf.template"
CONF="/etc/nginx/nginx.conf"

# 1) Certificati TLS (self-signed se mancano)
if [[ ! -f "$SSL_DIR/server.crt" || ! -f "$SSL_DIR/server.key" ]]; then
  echo "[entrypoint] Genero self-signed cert per ${PUBLIC_FQDN}"
  mkdir -p "$SSL_DIR"
  openssl req -x509 -nodes -newkey rsa:2048 \
    -days 365 \
    -keyout "$SSL_DIR/server.key" \
    -out "$SSL_DIR/server.crt" \
    -subj "/CN=${PUBLIC_FQDN}"
fi
chmod 600 "$SSL_DIR/server.key" || true

# 2) Basic Auth (se non monti il file, lo creo dalle env)
if [[ -f "$HTPASS" && -s "$HTPASS" ]]; then
  echo "[entrypoint] Uso htpasswd esistente in $HTPASS"
else
  if [[ -n "${BASIC_AUTH_USER:-}" && -n "${BASIC_AUTH_PASSWORD:-}" ]]; then
    echo "[entrypoint] Creo htpasswd per utente '$BASIC_AUTH_USER'"
    htpasswd -bBc "$HTPASS" "$BASIC_AUTH_USER" "$BASIC_AUTH_PASSWORD" >/dev/null
  else
    echo "[entrypoint][ERROR] Niente /etc/nginx/htpasswd e variabili BASIC_AUTH_* non settate."
    exit 1
  fi
fi
chmod 640 "$HTPASS" || true

# 3) Render del template nginx con le env
echo "[entrypoint] Rendering di $TEMPLATE -> $CONF"
export WRAPPER_SCHEME WRAPPER_HOST NGINX_CLIENT_MAX_BODY_SIZE
envsubst '${WRAPPER_SCHEME} ${WRAPPER_HOST} ${NGINX_CLIENT_MAX_BODY_SIZE}' \
  < "$TEMPLATE" > "$CONF"

# 4) Avvia Nginx
echo "[entrypoint] Avvio Nginx"
exec nginx -g 'daemon off;'