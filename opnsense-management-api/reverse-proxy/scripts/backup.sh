#!/bin/bash

# Backup script for Wrapper-only Reverse Proxy (Nginx)
# Creates a timestamped tarball of configs/ssl/logs + manifest.
# Optional encryption and retention.

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
BACKUP_DIR="${BACKUP_DIR:-backups}"
RETENTION="${RETENTION:-7}"
ENCRYPT="${BACKUP_ENCRYPT:-0}"
PASSPHRASE="${BACKUP_PASSPHRASE:-}"
CONTAINER_NAME="${CONTAINER_NAME:-opnsense-reverse-proxy}"

ts() { date +"%Y%m%d-%H%M%S"; }

ensure_dirs() { mkdir -p "$BACKUP_DIR" temp || true; }

manifest() {
  log_info "Generating manifest..."
  {
    echo "==== Wrapper Reverse Proxy Backup ===="
    echo "Created: $(date -Is)"
    echo "Host: $(hostname || echo unknown)"
    echo
    echo "[compose ps]"
    compose ps || true
    echo
    echo "[images]"
    docker images --digests 2>/dev/null || true
    echo
    echo "[inspect ${CONTAINER_NAME}]"
    docker inspect "${CONTAINER_NAME}" 2>/dev/null || true
  } > temp/manifest.txt
}

redact_env() {
  if [[ -f .env ]]; then
    log_info "Redacting secrets from .env..."
    sed -E 's/^(([^#]*)(PASS|SECRET|TOKEN|KEY)([^=]*)=).*/\1********/I' .env > temp/.env.redacted || cp .env temp/.env.redacted
  else
    : > temp/.env.redacted
  fi
}

make_tar() {
  local out="reverse-proxy-backup-$(ts).tgz"
  log_info "Creating archive $BACKUP_DIR/$out ..."
  tar czf "$BACKUP_DIR/$out" \
    --exclude='.git' \
    --exclude='node_modules' \
    docker-compose.yml Dockerfile .env temp/.env.redacted \
    nginx logs scripts temp/manifest.txt 2>/dev/null || true
  echo "$BACKUP_DIR/$out"
}

maybe_encrypt() {
  local in="$1"
  if [[ "$ENCRYPT" != "1" ]]; then echo "$in"; return; fi
  [[ -n "$PASSPHRASE" ]] || { log_error "BACKUP_PASSPHRASE missing"; exit 1; }
  local out="${in}.enc"
  log_info "Encrypting archive (AES-256, PBKDF2)..."
  openssl enc -aes-256-cbc -pbkdf2 -salt -in "$in" -out "$out" -pass pass:"$PASSPHRASE"
  rm -f "$in"
  echo "$out"
}

prune() {
  log_info "Applying retention (keep last ${RETENTION})..."
  ( ls -1t "${BACKUP_DIR}"/reverse-proxy-backup-*.tgz* 2>/dev/null || true ) | awk "NR>${RETENTION}" | xargs -r rm -f
}

usage() {
  cat <<EOF
Usage: $0 [--encrypt] [--keep N] [--container NAME] [--out DIR]

Options:
  --encrypt               Encrypt the backup (.tgz.enc) using \$BACKUP_PASSPHRASE
  --keep N                Retention: keep last N backups (default: ${RETENTION})
  --container NAME        Container name (default: ${CONTAINER_NAME})
  --out DIR               Backup directory (default: ${BACKUP_DIR})
  --help                  Show this help
EOF
}

# Args
while [[ $# -gt 0 ]]; do
  case "$1" in
    --encrypt) ENCRYPT=1; shift ;;
    --keep) RETENTION="${2:-7}"; shift 2 ;;
    --container) CONTAINER_NAME="${2:-opnsense-reverse-proxy}"; shift 2 ;;
    --out) BACKUP_DIR="${2:-backups}"; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) log_error "Unknown option: $1"; usage; exit 1 ;;
  esac
done

# Main
echo -e "${BLUE}
╔══════════════════════════════════════════════════════════════╗
║                 Wrapper Reverse Proxy Backup                 ║
╚══════════════════════════════════════════════════════════════╝${NC}"

ensure_dirs
manifest
redact_env
TAR_PATH=$(make_tar)
FINAL_PATH=$(maybe_encrypt "$TAR_PATH")
prune

log_success "Backup created: ${FINAL_PATH}"
[[ "$ENCRYPT" == "1" ]] && log_warning "Remember: you need BACKUP_PASSPHRASE to decrypt."
