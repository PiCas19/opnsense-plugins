#!/bin/bash

# Setup script for OPNsense Reverse Proxy
# Configures nginx and grafana to communicate with OPNsense wrapper API

set -e

echo "Starting OPNsense Reverse Proxy Setup..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Docker is installed
check_docker() {
    log_info "Checking Docker installation..."
    
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed. Please install Docker before continuing."
        exit 1
    fi
    
    if ! command -v docker-compose &> /dev/null; then
        log_error "Docker Compose is not installed. Please install Docker Compose before continuing."
        exit 1
    fi
    
    # Check if Docker is running
    if ! docker info &> /dev/null; then
        log_error "Docker is not running. Please start Docker service."
        exit 1
    fi
    
    log_success "Docker and Docker Compose are installed and running"
}

# Create necessary directories
create_directories() {
    log_info "Creating necessary directories..."
    
    mkdir -p logs/nginx
    mkdir -p logs/grafana
    mkdir -p nginx/ssl
    mkdir -p temp
    mkdir -p grafana/dashboards
    mkdir -p grafana/provisioning/dashboards
    mkdir -p grafana/provisioning/datasources
    
    log_success "Directories created successfully"
}

# Check connection to OPNsense wrapper
check_wrapper_connection() {
    log_info "Checking connection to OPNsense wrapper..."
    
    WRAPPER_HOST="${OPNSENSE_API_HOST:-192.168.216.50}"
    WRAPPER_PORT="${OPNSENSE_API_PORT:-3000}"
    
    if command -v curl &> /dev/null; then
        if curl -f -s --connect-timeout 5 "http://${WRAPPER_HOST}:${WRAPPER_PORT}/api/v1/health" &> /dev/null; then
            log_success "OPNsense wrapper reachable at ${WRAPPER_HOST}:${WRAPPER_PORT}"
        else
            log_warning "OPNsense wrapper not reachable. Make sure it's running."
        fi
    else
        log_info "curl not available, skipping connection test"
    fi
}

# Generate .env file if it doesn't exist
generate_env_file() {
    if [ ! -f .env ]; then
        log_info "Generating .env configuration file..."
        
        # Generate secure passwords
        GRAFANA_PASSWORD=$(openssl rand -base64 32 | tr -d =+/)
        BASIC_AUTH_PASSWORD=$(openssl rand -base64 16 | tr -d =+/)
        
        cat > .env << EOF
# Environment variables for OPNsense Reverse Proxy

# Grafana Configuration
GF_ADMIN_USER=admin
GF_ADMIN_PASSWORD=${GRAFANA_PASSWORD}
GF_SERVER_ROOT_URL=https://localhost/grafana/
GF_LOG_LEVEL=info

# Database Configuration (points to wrapper database)
POSTGRES_HOST=192.168.216.50
POSTGRES_PORT=5432
POSTGRES_USER=opnsense
POSTGRES_PASSWORD=CHANGE_ME_WRAPPER_DB_PASSWORD
POSTGRES_DB=opnsense_mgmt
GRAFANA_DB=grafana

# OPNsense API Configuration (points to wrapper on LAN)
OPNSENSE_API_HOST=192.168.216.50
OPNSENSE_API_PORT=3000
OPNSENSE_API_URL=http://192.168.216.50:3000

# JWT Token for authentication with wrapper
# Get this token from wrapper after login
JWT_TOKEN=CHANGE_ME_GET_FROM_WRAPPER_LOGIN

# Nginx Configuration
NGINX_CLIENT_MAX_BODY_SIZE=10m

# Security
BASIC_AUTH_USER=admin
BASIC_AUTH_PASSWORD=${BASIC_AUTH_PASSWORD}
EOF
        
        log_success ".env file generated with secure passwords"
        log_warning "IMPORTANT: Update .env with correct wrapper credentials!"
        echo -e "${YELLOW}You need to update:${NC}"
        echo -e "  - POSTGRES_PASSWORD: wrapper database password"
        echo -e "  - JWT_TOKEN: token obtained from wrapper login"
    else
        log_info ".env file already exists"
    fi
}

# Generate self-signed SSL certificates
generate_ssl_certificates() {
    if [ ! -f nginx/ssl/server.crt ] || [ ! -f nginx/ssl/server.key ]; then
        log_info "Generating self-signed SSL certificates..."
        
        # Check if openssl is available
        if ! command -v openssl &> /dev/null; then
            log_error "OpenSSL is not installed. Please install OpenSSL to generate certificates."
            exit 1
        fi
        
        openssl req -x509 -newkey rsa:4096 -keyout nginx/ssl/server.key -out nginx/ssl/server.crt \
            -days 365 -nodes \
            -subj "/C=CH/ST=Ticino/L=Massagno/O=OPNsense Management/OU=IT/CN=opnsense-proxy" \
            -addext "subjectAltName=DNS:localhost,DNS:opnsense-proxy,IP:127.0.0.1,IP:192.168.216.50"
        
        chmod 600 nginx/ssl/server.key
        chmod 644 nginx/ssl/server.crt
        
        log_success "SSL certificates generated successfully"
    else
        log_info "SSL certificates already exist"
    fi
}

# Generate htpasswd file for basic auth
generate_htpasswd() {
    if [ ! -f nginx/htpasswd ]; then
        log_info "Generating htpasswd file for authentication..."
        
        # Get username and password from .env if it exists
        if [ -f .env ]; then
            source .env
            USERNAME=${BASIC_AUTH_USER:-admin}
            PASSWORD=${BASIC_AUTH_PASSWORD:-admin123}
        else
            USERNAME="admin"
            PASSWORD="admin123"
        fi
        
        # Generate password hash using Python (more portable)
        if command -v python3 &> /dev/null; then
            HASH=$(python3 -c "import crypt; print(crypt.crypt('$PASSWORD', crypt.mksalt(crypt.METHOD_SHA512)))")
            echo "$USERNAME:$HASH" > nginx/htpasswd
        elif command -v htpasswd &> /dev/null; then
            htpasswd -bc nginx/htpasswd "$USERNAME" "$PASSWORD"
        else
            # Fallback with fixed bcrypt hash for admin/admin123
            echo "admin:\$2y\$10\$rQ8QhkAOGKjQaKLXMzMwluzPh/vBVHhQ8fLkLNjLQ9IG0dvM6MfXe" > nginx/htpasswd
            log_warning "Using default hash. Username: admin, Password: admin123"
        fi
        
        chmod 644 nginx/htpasswd
        log_success "htpasswd file generated successfully"
    else
        log_info "htpasswd file already exists"
    fi
}

# Verify Nginx configuration
verify_nginx_config() {
    log_info "Verifying Nginx configuration..."
    
    if [ -f nginx/nginx.conf ]; then
        # Test configuration using temporary container
        if docker run --rm -v "$(pwd)/nginx/nginx.conf:/etc/nginx/nginx.conf:ro" nginx:1.25-alpine nginx -t &> /dev/null; then
            log_success "Nginx configuration is valid"
        else
            log_warning "Nginx configuration may have issues"
        fi
    else
        log_error "nginx/nginx.conf file not found"
        exit 1
    fi
}

# Start services
start_services() {
    log_info "Starting services..."
    
    # Stop any existing containers
    docker-compose down 2>/dev/null || true
    
    # Build and start
    docker-compose up -d --build
    
    log_success "Services started successfully"
}

# Check services health
check_services_health() {
    log_info "Checking services health..."
    
    # Wait for services to start
    sleep 10
    
    # Check Nginx
    if docker-compose ps nginx | grep -q "Up"; then
        log_success "Nginx: Running"
    else
        log_error "Nginx: Not running"
    fi
    
    # Check Grafana
    if docker-compose ps grafana | grep -q "Up"; then
        log_success "Grafana: Running"
    else
        log_error "Grafana: Not running"
    fi
    
    # Test HTTPS connection
    sleep 5
    if curl -k -f -s https://localhost/health &> /dev/null; then
        log_success "HTTPS endpoint: Accessible"
    else
        log_warning "HTTPS endpoint: Not accessible yet (may need more time)"
    fi
}

# Show final information
show_final_info() {
    echo
    echo -e "${GREEN}Setup completed successfully!${NC}"
    echo
    echo -e "${BLUE}Service access:${NC}"
    echo -e "Grafana: https://localhost/grafana/"
    echo -e "API Docs: https://localhost/docs/"
    echo -e "Health Check: https://localhost/health"
    echo
    echo -e "${BLUE}Credentials:${NC}"
    
    if [ -f .env ]; then
        source .env
        echo -e "Grafana Admin: ${GF_ADMIN_USER:-admin}"
        echo -e "Grafana Password: ${GF_ADMIN_PASSWORD}"
        echo -e "Basic Auth: ${BASIC_AUTH_USER:-admin} / ${BASIC_AUTH_PASSWORD}"
    fi
    
    echo
    echo -e "${YELLOW}Remember to:${NC}"
    echo -e "  1. Update passwords in .env file"
    echo -e "  2. Configure JWT_TOKEN from wrapper"
    echo -e "  3. Verify connection to wrapper database"
    echo
    echo -e "${BLUE}View service logs:${NC}"
    echo -e "  docker-compose logs -f"
    echo
    echo -e "${BLUE}Useful commands:${NC}"
    echo -e "  docker-compose ps        # Check service status"
    echo -e "  docker-compose restart   # Restart services"
    echo -e "  docker-compose down      # Stop services"
    echo -e "  ./scripts/backup.sh      # Create backup"
    echo -e "  ./scripts/monitor.sh     # Run health check"
}

# Show help
show_help() {
    cat << EOF
Usage: $0 [OPTIONS]

Setup script for OPNsense Reverse Proxy

OPTIONS:
    --help, -h              Show this help message
    --skip-docker-check     Skip Docker installation check
    --skip-wrapper-check    Skip OPNsense wrapper connection test
    --force-regenerate      Force regeneration of certificates and config

EXAMPLES:
    $0                      # Run full setup
    $0 --help              # Show this help
    $0 --skip-wrapper-check # Setup without testing wrapper connection

REQUIREMENTS:
    - Docker and Docker Compose installed
    - OpenSSL for certificate generation
    - curl for connection testing (optional)

DESCRIPTION:
    This script sets up a reverse proxy with Nginx and Grafana to manage
    OPNsense firewall rules through a wrapper API. It will:
    
    1. Check system requirements
    2. Create necessary directories
    3. Generate secure configuration files
    4. Create SSL certificates
    5. Set up authentication
    6. Start and verify services

CONFIGURATION:
    After setup, update the .env file with:
    - POSTGRES_PASSWORD: Password for the wrapper database
    - JWT_TOKEN: Authentication token from wrapper login

EOF
}

# Parse command line arguments
SKIP_DOCKER_CHECK=false
SKIP_WRAPPER_CHECK=false
FORCE_REGENERATE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --help|-h)
            show_help
            exit 0
            ;;
        --skip-docker-check)
            SKIP_DOCKER_CHECK=true
            shift
            ;;
        --skip-wrapper-check)
            SKIP_WRAPPER_CHECK=true
            shift
            ;;
        --force-regenerate)
            FORCE_REGENERATE=true
            shift
            ;;
        *)
            log_error "Unknown option: $1"
            echo "Use --help to see available options"
            exit 1
            ;;
    esac
done

# Main function
main() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                 OPNsense Reverse Proxy Setup                ║"
    echo "║                                                              ║"
    echo "║  This script configures Nginx + Grafana to manage           ║"
    echo "║  OPNsense firewall rules through the wrapper API            ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    log_info "Starting setup process..."
    
    # Run setup steps
    if [ "$SKIP_DOCKER_CHECK" = false ]; then
        check_docker
    else
        log_info "Skipping Docker check (--skip-docker-check)"
    fi
    
    create_directories
    
    # Force regenerate files if requested
    if [ "$FORCE_REGENERATE" = true ]; then
        log_info "Force regenerating configuration files..."
        rm -f .env nginx/ssl/server.* nginx/htpasswd 2>/dev/null || true
    fi
    
    generate_env_file
    generate_ssl_certificates
    generate_htpasswd
    verify_nginx_config
    
    if [ "$SKIP_WRAPPER_CHECK" = false ]; then
        check_wrapper_connection
    else
        log_info "Skipping wrapper connection check (--skip-wrapper-check)"
    fi
    
    start_services
    check_services_health
    show_final_info
    
    log_info "Setup process completed successfully"
}

# Run the main function
main "$@"