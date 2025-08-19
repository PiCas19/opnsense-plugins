#!/bin/bash

# Setup script for Wrapper-only Reverse Proxy (Nginx)
# Builds & runs the edge, validates template, checks wrapper reachability.

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging
log_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $1"; }

# Compose wrapper
compose() {
  if command -v docker-compose >/dev/null 2>&1; then docker-compose "$@"; else docker compose "$@"; fi
}

# Defaults
CONTAINER_NAME="${CONTAINER_NAME:-opnsense-reverse-proxy}"

check_docker() {
  log_info "Checking Docker/Compose..."
  command -v docker >/dev/null || { log_error "Docker not installed"; exit 1; }
  docker info >/dev/null 2>&1 || { log_error "Docker is not running"; exit 1; }
  (command -v docker-compose >/dev/null || docker compose version >/dev/null 2>&1) || { log_error "Compose not available"; exit 1; }
  log_success "Docker/Compose OK"
}

create_dirs() {
  log_info "Creating directories..."
  mkdir -p logs/nginx nginx/ssl temp scripts
  log_success "Directories ready"
}

gen_env() {
  if [[ ! -f .env ]]; then
    log_info "Generating default .env ..."
    cat > .env <<'EOF'
PUBLIC_FQDN=fw.example.com
WRAPPER_SCHEME=http
WRAPPER_HOST=192.168.216.50:3000
NGINX_CLIENT_MAX_BODY_SIZE=10m
BASIC_AUTH_USER=monitoring-api
BASIC_AUTH_PASSWORD=CambiaSubito_!
DOCKER_DNS=172.16.216.1
EOF
    log_success ".env created"
  else
    log_info ".env already present"
  fi
  # shellcheck disable=SC1091
  source .env
}

gen_certs() {
  if [[ ! -f nginx/ssl/server.crt || ! -f nginx/ssl/server.key ]]; then
    log_info "Creating self-signed TLS certs for ${PUBLIC_FQDN}..."
    openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
      -keyout nginx/ssl/server.key -out nginx/ssl/server.crt \
      -subj "/CN=${PUBLIC_FQDN}"
    chmod 600 nginx/ssl/server.key
    chmod 644 nginx/ssl/server.crt
    log_success "TLS certs generated"
  else
    log_info "TLS certs already exist"
  fi
}

verify_tpl() {
  log_info "Verifying Nginx template..."
  docker run --rm -i \
    -e WRAPPER_SCHEME -e WRAPPER_HOST -e NGINX_CLIENT_MAX_BODY_SIZE \
    -v "$(pwd)/nginx/nginx.conf.template:/tmp/nginx.conf.template:ro" \
    alpine:3.20 sh -c 'apk add --no-cache gettext >/dev/null && envsubst \
      "${WRAPPER_SCHEME} ${WRAPPER_HOST} ${NGINX_CLIENT_MAX_BODY_SIZE}" \
      < /tmp/nginx.conf.template' > temp/nginx.conf 2>/dev/null || true

  if [[ -s temp/nginx.conf ]] && docker run --rm \
       -v "$(pwd)/temp/nginx.conf:/etc/nginx/nginx.conf:ro" nginx:1.25-alpine nginx -t >/dev/null 2>&1; then
    log_success "Nginx syntax OK"
  else
    log_warning "Template render/syntax test failed (check nginx.conf.template)"
  fi
}

check_wrapper() {
  log_info "Checking wrapper reachability..."
  local host="${WRAPPER_HOST%:*}" port="${WRAPPER_HOST##*:}"
  if curl -sf --connect-timeout 5 "http://${host}:${port}/health" >/dev/null \
  || curl -sf --connect-timeout 5 "http://${host}:${port}/api/v1/health" >/dev/null; then
    log_success "Wrapper reachable at ${WRAPPER_HOST}"
  else
    log_warning "Wrapper NOT reachable at ${WRAPPER_HOST}"
  fi
}

start_services() {
  log_info "Starting services..."
  compose down >/dev/null 2>&1 || true
  compose up -d --build
  log_success "Services up"
}

post_checks() {
  log_info "Edge quick checks..."
  sleep 6
  curl -ksf "https://${PUBLIC_FQDN}/health" >/dev/null && log_success "/health OK" || log_warning "/health KO"
  curl -ksI -u "${BASIC_AUTH_USER}:${BASIC_AUTH_PASSWORD}" "https://${PUBLIC_FQDN}/api/api-docs" >/dev/null \
    && log_success "/api/api-docs OK (auth)" || log_warning "/api/api-docs KO"
}

final_banner() {
  echo -e "${BLUE}"
  echo "╔══════════════════════════════════════════════════════════════╗"
  echo "║                 Wrapper Reverse Proxy: READY                ║"
  echo "╚══════════════════════════════════════════════════════════════╝"
  echo -e "${NC}"
  echo -e "${BLUE}Endpoints:${NC}"
  echo "  Health:   https://${PUBLIC_FQDN}/health"
  echo "  Wrapper:  https://${PUBLIC_FQDN}/api/  (redir -> /api/api-docs)"
  echo -e "${BLUE}Basic Auth:${NC}"
  echo "  User: ${BASIC_AUTH_USER}"
  echo "  Pass: ${BASIC_AUTH_PASSWORD}"
  echo -e "${BLUE}Compose:${NC}"
  echo "  docker compose logs -f"
  echo "  docker compose ps"
  echo "  docker compose restart"
  echo "  docker compose down"
}

echo -e "${BLUE}
╔══════════════════════════════════════════════════════════════╗
║                Wrapper-only Reverse Proxy Setup              ║
╚══════════════════════════════════════════════════════════════╝${NC}"

check_docker
create_dirs
gen_env
gen_certs
verify_tpl
check_wrapper
start_services
post_checks
final_banner