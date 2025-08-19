#!/bin/bash

# Setup script for OPNsense Reverse Proxy (Nginx only)
# Configures Nginx to proxy OPNsense web/API and your wrapper API, ready for WAN exposure.

set -e

echo "Starting OPNsense Reverse Proxy Setup..."

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging
log_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $1"; }

# Compose wrapper (docker compose vs docker-compose)
compose() {
    if command -v docker-compose >/dev/null 2>&1; then
        docker-compose "$@"
    else
        docker compose "$@"
    fi
}

# Check Docker
check_docker() {
    log_info "Checking Docker installation..."
    if ! command -v docker >/dev/null 2>&1; then
        log_error "Docker not installed. Please install Docker."
        exit 1
    fi
    if ! docker info >/dev/null 2>&1; then
        log_error "Docker is not running. Start the Docker service."
        exit 1
    fi
    if ! command -v docker-compose >/dev/null 2>&1 && ! docker compose version >/dev/null 2>&1; then
        log_error "Docker Compose not available (neither docker-compose nor docker compose)."
        exit 1
    fi
    log_success "Docker and Compose available"
}

# Create directories
create_directories() {
    log_info "Creating directories..."
    mkdir -p logs/nginx
    mkdir -p nginx/ssl
    mkdir -p temp
    log_success "Directories ready"
}

# Generate .env
generate_env_file() {
    if [ ! -f .env ]; then
        if [ -f .env.template ]; then
            log_info "Creating .env from .env.template..."
            cp .env.template .env
            
            # Generate a secure password if placeholder exists
            if grep -q "cambia_questa_subito" .env; then
                BASIC_PASS=$(openssl rand -base64 24 | tr -d '=+/')
                sed -i.bak "s|cambia_questa_subito|${BASIC_PASS}|" .env && rm -f .env.bak
                log_info "Generated secure password for BASIC_AUTH_PASSWORD"
            fi
            
            log_success ".env created from template"
            log_warning "IMPORTANT: review .env and update IPs if needed (OPNSENSE_WEB_HOST, WRAPPER_HOST, PUBLIC_FQDN)."
        else
            log_info "No .env.template found, generating default .env..."
            BASIC_PASS=$(openssl rand -base64 24 | tr -d '=+/')
            cat > .env << 'EOF'
# === Environment variables for OPNsense Reverse Proxy ===

# Backend OPNsense (GUI/API)
OPNSENSE_WEB_SCHEME=https
OPNSENSE_WEB_HOST=192.168.216.1:443

# Your wrapper backend
WRAPPER_SCHEME=http
WRAPPER_HOST=192.168.216.50:3000

# Public endpoint (certificate CN)
PUBLIC_FQDN=localhost

# Nginx settings
NGINX_CLIENT_MAX_BODY_SIZE=10m

# Basic auth at the proxy edge
BASIC_AUTH_USER=opnsense-api
BASIC_AUTH_PASSWORD=__AUTOFILL__
EOF
            # inject random password
            sed -i.bak "s|BASIC_AUTH_PASSWORD=__AUTOFILL__|BASIC_AUTH_PASSWORD=${BASIC_PASS}|" .env && rm -f .env.bak
            log_success ".env created"
            log_warning "IMPORTANT: review .env (OPNSENSE_WEB_HOST, WRAPPER_HOST, PUBLIC_FQDN)."
        fi
    else
        log_info ".env already exists; leaving as is"
    fi

    # shellcheck disable=SC1091
    source .env
}

# Generate self-signed TLS
generate_ssl_certificates() {
    local fqdn="${PUBLIC_FQDN:-localhost}"
    if [ ! -f nginx/ssl/server.crt ] || [ ! -f nginx/ssl/server.key ]; then
        log_info "Generating self-signed TLS cert for ${fqdn}..."
        if ! command -v openssl >/dev/null 2>&1; then
            log_error "OpenSSL not installed (needed to mint self-signed certs)."
            exit 1
        fi
        openssl req -x509 -newkey rsa:4096 -nodes -days 365 \
            -keyout nginx/ssl/server.key -out nginx/ssl/server.crt \
            -subj "/CN=${fqdn}" \
            -addext "subjectAltName=DNS:${fqdn},DNS:localhost,IP:127.0.0.1,IP:192.168.216.1,IP:192.168.216.50"
        chmod 600 nginx/ssl/server.key
        chmod 644 nginx/ssl/server.crt
        log_success "TLS certs generated"
    else
        log_info "TLS certs already present"
    fi
}

# Check backend connectivity
check_backends() {
    log_info "Checking backend connectivity..."
    local opn_host="${OPNSENSE_WEB_HOST%:*}"
    local opn_port="${OPNSENSE_WEB_HOST##*:}"
    local wrp_host="${WRAPPER_HOST%:*}"
    local wrp_port="${WRAPPER_HOST##*:}"

    if command -v curl >/dev/null 2>&1; then
        if curl -skf --connect-timeout 5 "https://${opn_host}:${opn_port}" >/dev/null; then
            log_success "OPNsense reachable at ${opn_host}:${opn_port}"
        else
            log_warning "OPNsense NOT reachable at ${opn_host}:${opn_port} (check routing/firewall)"
        fi
        # Try common health paths
        if curl -sf --connect-timeout 5 "http://${wrp_host}:${wrp_port}/health" >/dev/null \
        || curl -sf --connect-timeout 5 "http://${wrp_host}:${wrp_port}/api/v1/health" >/dev/null; then
            log_success "Wrapper reachable at ${wrp_host}:${wrp_port}"
        else
            log_warning "Wrapper NOT reachable at ${wrp_host}:${wrp_port} (ensure it's running)"
        fi
    else
        log_info "curl not available, skipping connectivity tests"
    fi
}

# Render and verify nginx config from template
verify_nginx_config() {
    log_info "Verifying nginx template -> config..."
    if [ ! -f nginx/nginx.conf.template ]; then
        log_error "Missing nginx/nginx.conf.template"
        exit 1
    fi

    # Use a tiny container to envsubst the template safely (no local deps)
    docker run --rm -i \
        -e OPNSENSE_WEB_SCHEME -e OPNSENSE_WEB_HOST \
        -e WRAPPER_SCHEME -e WRAPPER_HOST \
        -e NGINX_CLIENT_MAX_BODY_SIZE \
        -v "$(pwd)/nginx/nginx.conf.template:/tmp/nginx.conf.template:ro" \
        alpine:3.20 sh -c 'apk add --no-cache gettext >/dev/null && envsubst \
            "${OPNSENSE_WEB_SCHEME} ${OPNSENSE_WEB_HOST} ${WRAPPER_SCHEME} ${WRAPPER_HOST} ${NGINX_CLIENT_MAX_BODY_SIZE}" \
            < /tmp/nginx.conf.template' > temp/nginx.conf 2>/dev/null || true

    if [ ! -s temp/nginx.conf ]; then
        log_warning "Failed to render config via envsubst; proceeding without syntax test"
        return
    fi

    # Validate with nginx
    if docker run --rm -v "$(pwd)/temp/nginx.conf:/etc/nginx/nginx.conf:ro" nginx:1.25-alpine nginx -t >/dev/null 2>&1; then
        log_success "nginx configuration syntax is valid"
    else
        log_warning "nginx reported issues in generated config (check nginx.conf.template)"
    fi
}

# Start services
start_services() {
    log_info "Starting services (build + up)..."
    compose down >/dev/null 2>&1 || true
    compose up -d --build
    log_success "Services up"
}

# Health checks (edge)
check_edge_health() {
    log_info "Checking published endpoints..."
    sleep 8

    local host="https://${PUBLIC_FQDN:-localhost}"
    local user="${BASIC_AUTH_USER:-opnsense-api}"
    local pass="${BASIC_AUTH_PASSWORD:-changeme}"

    if command -v curl >/dev/null 2>&1; then
        if curl -skf "${host}/health" >/dev/null; then
            log_success "Edge /health OK"
        else
            log_warning "Edge /health not responding yet"
        fi

        if curl -skI -u "$user:$pass" "${host}/opnsense/" >/dev/null; then
            log_success "Edge /opnsense/ reachable (auth ok)"
        else
            log_warning "Edge /opnsense/ check failed (auth/route?)"
        fi

        if curl -skI -u "$user:$pass" "${host}/api/" >/dev/null; then
            log_success "Edge /api/ reachable (auth ok)"
        else
            log_warning "Edge /api/ check failed (auth/route?)"
        fi
    else
        log_info "curl not available, skipping edge checks"
    fi
}

# Show final info
show_final_info() {
    echo
    echo -e "${GREEN}Setup completed successfully!${NC}"
    echo
    echo -e "${BLUE}Public endpoints (through the reverse proxy):${NC}"
    echo -e "  Health:   https://${PUBLIC_FQDN:-localhost}/health"
    echo -e "  OPNsense: https://${PUBLIC_FQDN:-localhost}/opnsense/"
    echo -e "  Wrapper:  https://${PUBLIC_FQDN:-localhost}/api/"
    echo
    echo -e "${BLUE}Basic Auth (edge):${NC}"
    echo -e "  User: ${BASIC_AUTH_USER:-opnsense-api}"
    echo -e "  Pass: ${BASIC_AUTH_PASSWORD:-<from .env>}"
    echo
    echo -e "${YELLOW}WAN exposure reminder:${NC}"
    echo -e "  - If Docker host has PUBLIC IP: add a WAN rule allowing TCP 80/443 to the host (better: restrict by source IPs)."
    echo -e "  - If Docker host is in LAN: create NAT Port Forward WAN:443->HOST:443 (and 80->80 for redirect), with associated filter rule."
    echo
    echo -e "${BLUE}Logs & control:${NC}"
    echo -e "  compose logs -f       # live logs"
    echo -e "  compose ps            # status"
    echo -e "  compose restart       # restart"
    echo -e "  compose down          # stop"
}

# Help
show_help() {
    cat << EOF
Usage: $0 [OPTIONS]

Setup script for Nginx-based OPNsense Reverse Proxy

OPTIONS:
  --help, -h              Show this help
  --skip-docker-check     Skip Docker checks
  --skip-connectivity     Skip backend connectivity tests
  --force-regenerate      Regenerate .env and TLS certs

EXAMPLES:
  $0                          # Full setup
  $0 --skip-connectivity      # Skip backend checks
  $0 --force-regenerate       # Recreate .env and certs

REQUIREMENTS:
  - Docker + Docker Compose (plugin or classic)
  - OpenSSL (for self-signed certs)
  - curl (optional tests)
EOF
}

# Args
SKIP_DOCKER_CHECK=false
SKIP_CONNECTIVITY=false
FORCE_REGENERATE=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --help|-h) show_help; exit 0 ;;
        --skip-docker-check) SKIP_DOCKER_CHECK=true; shift ;;
        --skip-connectivity) SKIP_CONNECTIVITY=true; shift ;;
        --force-regenerate)  FORCE_REGENERATE=true; shift ;;
        *) log_error "Unknown option: $1"; echo "Use --help for usage"; exit 1 ;;
    esac
done

# Main
main() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                 OPNsense Reverse Proxy Setup                 ║"
    echo "║            (Nginx edge, OPNsense + wrapper backends)        ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    [ "$SKIP_DOCKER_CHECK" = true ] || check_docker
    create_directories
    if [ "$FORCE_REGENERATE" = true ]; then
        log_info "Force regeneration requested"
        rm -f .env nginx/ssl/server.* 2>/dev/null || true
    fi
    generate_env_file
    generate_ssl_certificates
    [ "$SKIP_CONNECTIVITY" = true ] || check_backends
    verify_nginx_config
    start_services
    check_edge_health
    show_final_info
    log_info "All done."
}

main "$@"