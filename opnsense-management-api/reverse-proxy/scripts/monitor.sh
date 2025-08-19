#!/bin/bash

# Monitor script for Wrapper-only Reverse Proxy (Nginx)
# Checks edge endpoints (/health, /api/), container health,
# TLS certificate expiry, and optionally backend reachability.

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

# Defaults (will be overridden by .env if present)
PUBLIC_FQDN="${PUBLIC_FQDN:-localhost}"
BASIC_AUTH_USER="${BASIC_AUTH_USER:-monitoring-api}"
BASIC_AUTH_PASSWORD="${BASIC_AUTH_PASSWORD:-}"

WRAPPER_HOST="${WRAPPER_HOST:-192.168.216.50:3000}"
CONTAINER_NAME="${CONTAINER_NAME:-opnsense-reverse-proxy}"

HOST_URL=""
CHECK_BACKEND=0
COUNT=1
INTERVAL=5
NO_AUTH=0

load_env() {
  if [[ -f .env ]]; then
    # shellcheck disable=SC1091
    source .env
    PUBLIC_FQDN="${PUBLIC_FQDN:-$PUBLIC_FQDN}"
    BASIC_AUTH_USER="${BASIC_AUTH_USER:-$BASIC_AUTH_USER}"
    BASIC_AUTH_PASSWORD="${BASIC_AUTH_PASSWORD:-$BASIC_AUTH_PASSWORD}"
    WRAPPER_HOST="${WRAPPER_HOST:-$WRAPPER_HOST}"
  fi
  HOST_URL="${HOST_URL:-https://${PUBLIC_FQDN}}"
}

usage() {
  cat <<EOF
Usage: $0 [options]

Options:
  --host URL            Override edge host URL (default: https://\$PUBLIC_FQDN)
  --no-auth             Do not send Basic Auth (default: send if BASIC_AUTH_PASSWORD set)
  --backend             Also check wrapper backend reachability
  --count N             Run N iterations (default: 1)
  --interval S          Sleep S seconds between iterations (default: 5)
  --container NAME      Container name (default: ${CONTAINER_NAME})
  --help                Show this help

Reads .env for PUBLIC_FQDN, BASIC_AUTH_USER/PASSWORD, WRAPPER_HOST.
EOF
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --host) HOST_URL="$2"; shift 2 ;;
      --no-auth) NO_AUTH=1; shift ;;
      --backend) CHECK_BACKEND=1; shift ;;
      --count) COUNT="$2"; shift 2 ;;
      --interval) INTERVAL="$2"; shift 2 ;;
      --container) CONTAINER_NAME="$2"; shift 2 ;;
      --help|-h) usage; exit 0 ;;
      *) log_error "Unknown option: $1"; usage; exit 1 ;;
    esac
  done
}

http_probe() {
  local url="$1"; shift
  local auth_flag=()
  if [[ "$NO_AUTH" -eq 0 && -n "$BASIC_AUTH_PASSWORD" ]]; then
    auth_flag=(-u "${BASIC_AUTH_USER}:${BASIC_AUTH_PASSWORD}")
  fi
  curl -sk -o /dev/null -w "%{http_code} %{time_total}" "${auth_flag[@]}" "$url" || echo "000 0"
}

check_edge() {
  log_info "Checking edge endpoints on ${HOST_URL} ..."
  local code t

  read -r code t < <(http_probe "${HOST_URL}/health")
  [[ "$code" == "200" ]] && log_success "/health OK (${t}s)" || log_warning "/health -> ${code} (${t}s)"

  # Swagger (o cambia in /api/v1/health se preferisci)
  read -r code t < <(http_probe "${HOST_URL}/api/api-docs")
  if [[ "$code" =~ ^(200|301|302|401)$ ]]; then
    log_success "/api/api-docs reachable (HTTP ${code}, ${t}s)"
  else
    log_warning "/api/api-docs -> ${code} (${t}s)"
  fi
}

check_container() {
  log_info "Checking container '${CONTAINER_NAME}' ..."
  local state health
  state=$(docker inspect -f '{{.State.Status}}' "${CONTAINER_NAME}" 2>/dev/null || echo "not_found")
  health=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "${CONTAINER_NAME}" 2>/dev/null || echo "")
  if [[ "$state" == "running" ]]; then
    if [[ -n "$health" ]]; then
      [[ "$health" == "healthy" ]] && log_success "Container running (health: ${health})" || log_warning "Container running (health: ${health})"
    else
      log_success "Container running"
    fi
  else
    log_error "Container state: ${state}"
  fi
}

check_tls_expiry() {
  local host port days_left exp
  host=$(echo "$HOST_URL" | sed -E 's#https?://([^/:]+).*#\1#')
  port=443
  log_info "Checking TLS certificate expiry for ${host}:${port} ..."
  if command -v openssl >/dev/null 2>&1; then
    exp=$(echo | openssl s_client -servername "$host" -connect "$host:$port" 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2 || true)
    if [[ -n "$exp" ]]; then
      if date -d "$exp" +%s >/dev/null 2>&1; then
        days_left=$(( ( $(date -d "$exp" +%s) - $(date +%s) ) / 86400 ))
      else
        days_left=$(( ( $(date -j -f "%b %d %T %Y %Z" "$exp" +%s 2>/dev/null || echo $(date +%s)) - $(date +%s) ) / 86400 ))
      fi
      if [[ "$days_left" -ge 14 ]]; then
        log_success "TLS cert valid; expires in ${days_left} days (${exp})"
      elif [[ "$days_left" -ge 0 ]]; then
        log_warning "TLS cert close to expiry: ${days_left} days left (${exp})"
      else
        log_error "TLS cert EXPIRED (${exp})"
      fi
    else
      log_warning "Unable to read certificate end date"
    fi
  else
    log_warning "OpenSSL not available; skipping TLS check"
  fi
}

check_backend() {
  [[ "$CHECK_BACKEND" -eq 1 ]] || return 0
  log_info "Checking wrapper backend reachability..."
  local wrp_host wrp_port
  wrp_host="${WRAPPER_HOST%:*}"
  wrp_port="${WRAPPER_HOST##*:}"

  if curl -sf --connect-timeout 5 "http://${wrp_host}:${wrp_port}/health" >/dev/null \
  || curl -sf --connect-timeout 5 "http://${wrp_host}:${wrp_port}/api/v1/health" >/dev/null; then
    log_success "Wrapper backend reachable at ${WRAPPER_HOST}"
  else
    log_warning "Wrapper backend NOT reachable at ${WRAPPER_HOST}"
  fi
}

iteration() {
  echo -e "${BLUE}\n——— Probe @ $(date -Is) ———${NC}"
  check_container
  check_edge
  check_tls_expiry
  check_backend
}

main_loop() {
  local i=1
  while [[ $i -le $COUNT ]]; do
    iteration
    (( i==COUNT )) && break
    sleep "$INTERVAL"
    i=$((i+1))
  done
}

# Main
parse_args "$@"
load_env

echo -e "${BLUE}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║              Wrapper Reverse Proxy Monitoring Tool          ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

main_loop
log_success "Monitoring run completed."
