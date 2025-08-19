#!/bin/bash

# Backup script for OPNsense Reverse Proxy (Nginx only)
# Creates a timestamped tarball of configs, SSL certs, logs and a manifest.
# Optional: encryption and retention.

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
RETENTION="${RETENTION:-7}"             # keep last N backups
ENCRYPT="${BACKUP_ENCRYPT:-0}"          # 1 to encrypt
PASSPHRASE="${BACKUP_PASSPHRASE:-}"     # required if ENCRYPT=1
CONTAINER_NAME="${CONTAINER_NAME:-opnsense-reverse-proxy}"

timestamp() { date +"%Y%m%d-%H%M%S"; }

ensure_dirs() {
  mkdir -p "$BACKUP_DIR" || true
  mkdir -p temp || true
}

generate_manifest() {
  log_info "Generating manifest..."
  {
    echo "==== OPNsense Reverse Proxy Backup Manifest ===="
    echo "Created at: $(date -Is)"
    echo "Host: $(hostname || echo unknown)"
    echo "Working dir: $(pwd)"
    echo "Docker: $(docker --version 2>/dev/null || echo 'not found')"
    if command -v docker-compose >/dev/null 2>&1; then
      echo "Compose: $(docker-compose --version 2>/dev/null)"
    else
      echo "Compose: $(docker compose version --short 2>/dev/null || echo 'plugin not found')"
    fi
    echo
    echo "[compose ps]"
    compose ps || true
    echo
    echo "[images]"
    docker images --digests 2>/dev/null || true
    echo
    echo "[container inspect: $CONTAINER_NAME]"
    docker inspect "$CONTAINER_NAME" 2>/dev/null || true
  } > temp/manifest.txt
}

redact_env() {
  if [[ -f .env ]]; then
    log_info "Redacting secrets from .env..."
    sed -E 's/^(([^#]*)(PASS|SECRET|TOKEN|KEY)([^=]*)=).*/\1********/I' .env > temp/.env.redacted || cp .env temp/.env.redacted
  else
    log_warning ".env not found; skipping redaction"
    : > temp/.env.redacted
  fi
}

create_tarball() {
  local ts fname
  ts=$(timestamp)
  fname="reverse-proxy-backup-${ts}.tgz"
  log_info "Creating archive ${BACKUP_DIR}/${fname} ..."

  tar czf "${BACKUP_DIR}/${fname}" \
    --exclude='.git' \
    --exclude='node_modules' \
    docker-compose.yml \
    Dockerfile \
    .env \
    temp/.env.redacted \
    nginx \
    logs \
    scripts/stup.sh \
    temp/manifest.txt 2>/dev/null || true

  echo "${BACKUP_DIR}/${fname}"
}

encrypt_file() {
  local input="$1"
  if [[ "$ENCRYPT" != "1" ]]; then
    echo "$input"; return
  fi
  if [[ -z "$PASSPHRASE" ]]; then
    log_error "ENCRYPT=1 but BACKUP_PASSPHRASE is empty"; exit 1
  fi
  local out="${input}.enc"
  log_info "Encrypting archive (AES-256, PBKDF2)..."
  openssl enc -aes-256-cbc -pbkdf2 -salt -in "$input" -out "$out" -pass pass:"$PASSPHRASE"
  rm -f "$input"
  echo "$out"
}

prune_old_backups() {
  log_info "Applying retention policy (keep last ${RETENTION})..."
  # List newest first, skip first N, delete the rest
  ( ls -1t "${BACKUP_DIR}"/reverse-proxy-backup-*.tgz* 2>/dev/null || true ) | awk "NR>${RETENTION}" | while read -r f; do
    [[ -f "$f" ]] && { log_info "Deleting old backup: $f"; rm -f "$f"; }
  done
}

show_help() {
  cat <<EOF
Usage: $0 [--encrypt] [--keep N] [--container NAME] [--out DIR]

Options:
  --encrypt               Encrypt the backup (.tgz.enc) using \$BACKUP_PASSPHRASE
  --keep N                Retention: keep last N backups (default: ${RETENTION})
  --container NAME        Container name (default: ${CONTAINER_NAME})
  --out DIR               Backup directory (default: ${BACKUP_DIR})
  --help                  Show this help

Env:
  BACKUP_ENCRYPT=1        Same as --encrypt
  BACKUP_PASSPHRASE=...   Passphrase for encryption
  BACKUP_DIR=backups      Output directory
  RETENTION=7             Keep last N
EOF
}

# Parse args
while [[ $# -gt 0 ]]; do
  case "$1" in
    --encrypt) ENCRYPT=1; shift ;;
    --keep) RETENTION="${2:-7}"; shift 2 ;;
    --container) CONTAINER_NAME="${2:-opnsense-reverse-proxy}"; shift 2 ;;
    --out) BACKUP_DIR="${2:-backups}"; shift 2 ;;
    --help|-h) show_help; exit 0 ;;
    *) log_error "Unknown option: $1"; show_help; exit 1 ;;
  esac
done

main() {
  echo -e "${BLUE}"
  echo "╔══════════════════════════════════════════════════════════════╗"
  echo "║                  Reverse Proxy Backup Utility                ║"
  echo "╚══════════════════════════════════════════════════════════════╝"
  echo -e "${NC}"

  ensure_dirs
  generate_manifest
  redact_env
  local tar_path enc_path
  tar_path=$(create_tarball)
  enc_path=$(encrypt_file "$tar_path")
  prune_old_backups

  log_success "Backup created: ${enc_path}"
  if [[ "$ENCRYPT" == "1" ]]; then
    log_warning "Encrypted backup requires the same BACKUP_PASSPHRASE to restore."
  fi
  echo
  echo -e "${BLUE}Restore (example):${NC}"
  if [[ "$ENCRYPT" == "1" ]]; then
    echo "  openssl enc -d -aes-256-cbc -pbkdf2 -in ${enc_path} -out backup.tgz -pass pass:\$BACKUP_PASSPHRASE"
    echo "  tar xzf backup.tgz"
  else
    echo "  tar xzf ${enc_path}"
  fi
}

main "$@"