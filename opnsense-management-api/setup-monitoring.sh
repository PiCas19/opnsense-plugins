#!/bin/bash

# Complete setup script for OPNsense Monitoring
# Author: OPNsense Management Team
# Version: 1.0

set -euo pipefail

# Output colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Banner
echo -e "${CYAN}"
cat << 'EOF'
  ____  _____  _   _                      
 / __ \|  __ \| \ | |                     
| |  | | |__) |  \| |___  ___ _ __  ___  ___
| |  | |  ___/|     / __|/ _ \ '_ \/ __|/ _ \
| |__| | |    | |\  \__ \  __/ | | \__ \  __/
 \____/|_|    |_| \_|___/\___|_| |_|___/\___|

    Management API - Monitoring Setup
EOF
echo -e "${NC}"

echo -e "${GREEN} Complete OPNsense Monitoring System Setup${NC}"
echo ""

# Utility functions
log_info() {
    echo -e "${BLUE}  $1${NC}"
}

log_success() {
    echo -e "${GREEN}  $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}  $1${NC}"
}

log_error() {
    echo -e "${RED} $1${NC}"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    local missing_tools=()
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        missing_tools+=("docker")
    fi
    
    # Check Docker Compose
    if ! command -v docker &> /dev/null || ! docker compose version &> /dev/null; then
        missing_tools+=("docker-compose")
    fi
    
    # Check OpenSSL
    if ! command -v openssl &> /dev/null; then
        missing_tools+=("openssl")
    fi
    
    # Check curl
    if ! command -v curl &> /dev/null; then
        missing_tools+=("curl")
    fi
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        log_error "Missing tools: ${missing_tools[*]}"
        log_info "Install the prerequisites and try again:"
        log_info "  Ubuntu/Debian: sudo apt update && sudo apt install docker.io docker-compose openssl curl"
        log_info "  CentOS/RHEL:   sudo yum install docker docker-compose openssl curl"
        exit 1
    fi
    
    log_success "All prerequisites are met"
}

# Create directory structure
create_directory_structure() {
    log_info "Creating directory structure..."
    
    mkdir -p monitoring/{grafana,nagios,nginx,prometheus}
    mkdir -p monitoring/grafana/{dashboards,provisioning/{dashboards,datasources}}
    mkdir -p monitoring/nagios/plugins
    mkdir -p monitoring/nginx/ssl
    mkdir -p scripts
    mkdir -p logs
    mkdir -p temp
    
    log_success "Directory structure created"
}

# Generate SSL certificates
generate_ssl_certificates() {
    log_info "Generating SSL certificates..."
    
    if [[ -f monitoring/nginx/ssl/nginx.crt ]] && [[ -f monitoring/nginx/ssl/nginx.key ]]; then
        log_warning "SSL certificates already exist, skipping..."
        return
    fi
    
    openssl genrsa -out monitoring/nginx/ssl/nginx.key 2048
    
    openssl req -new -x509 -key monitoring/nginx/ssl/nginx.key \
        -out monitoring/nginx/ssl/nginx.crt \
        -days 365 \
        -subj "/C=CH/ST=Ticino/L=Massagno/O=OPNsense-Monitoring/CN=localhost"
    
    cp monitoring/nginx/ssl/nginx.crt monitoring/nginx/ssl/fullchain.pem
    cp monitoring/nginx/ssl/nginx.key monitoring/nginx/ssl/privkey.pem
    
    chmod 600 monitoring/nginx/ssl/*.key monitoring/nginx/ssl/*.pem
    chmod 644 monitoring/nginx/ssl/*.crt
    
    log_success "SSL certificates generated"
}

# Create configuration files
create_config_files() {
    log_info "Creating configuration files..."
    
    if [[ ! -f monitoring/nginx/htpasswd ]]; then
        printf "admin:$(openssl passwd -apr1 'SuperPassword!')\n" > monitoring/nginx/htpasswd
        log_success "htpasswd file created (admin/SuperPassword!)"
    fi
    
    if [[ -f monitoring/nagios/docker-entrypoint.sh ]]; then
        chmod +x monitoring/nagios/docker-entrypoint.sh
    fi
    
    if [[ -f monitoring/nagios/plugins/check_opnsense.sh ]]; then
        chmod +x monitoring/nagios/plugins/check_opnsense.sh
    fi
    
    log_success "Configuration files created"
}

# Check .env file
check_env_file() {
    log_info "Checking .env file..."
    
    if [[ ! -f .env ]]; then
        log_warning ".env file not found, creating template..."
        cat > .env << 'EOF'
# Database
POSTGRES_USER=opnsense
POSTGRES_PASSWORD=change_me_postgres_password
POSTGRES_DB=opnsense_mgmt

# Redis
REDIS_PASSWORD=change_me_redis_password

# OPNsense API
OPNSENSE_BASE_URL=https://your-opnsense-ip
OPNSENSE_API_KEY=your_api_key_here
OPNSENSE_API_SECRET=your_api_secret_here

# JWT Security
JWT_SECRET=change_me_to_very_long_random_string_at_least_64_characters_long
JWT_EXPIRES_IN=24h
JWT_REFRESH_EXPIRES_IN=7d
JWT_ISSUER=opnsense-api
JWT_AUDIENCE=opnsense-users

# Monitoring
GRAFANA_ADMIN_PASSWORD=change_me_grafana_password
NAGIOS_USER=nagiosadmin
NAGIOS_PASS=change_me_nagios_password

# Network IPs
LAN_HOST_IP=192.168.216.50
DMZ_HOST_IP=172.16.216.20

# Security
CORS_ORIGIN=*
HELMET_ENABLED=true
CSRF_ENABLED=true
METRICS_ENABLED=true
EOF
        log_warning "IMPORTANT: Edit the .env file with your actual values!"
    else
        log_success ".env file found"
    fi
}

# Test Docker configuration
test_docker_config() {
    log_info "Testing Docker configuration..."
    
    if docker compose config > /dev/null 2>&1; then
        log_success "docker-compose configuration is valid"
    else
        log_error "docker-compose configuration error"
        log_info "Run: docker compose config"
        exit 1
    fi
}

# Create management scripts
create_management_scripts() {
    log_info "Creating management scripts..."
    
    # Start LAN
    cat > scripts/start-lan.sh << 'EOF'
#!/bin/bash
echo "Starting LAN services (API + Database)..."
docker compose --profile lan up -d
echo "LAN services started"
docker compose --profile lan ps
EOF
    
    # Start DMZ
    cat > scripts/start-dmz.sh << 'EOF'
#!/bin/bash
echo "Starting DMZ services (Monitoring)..."
docker compose --profile dmz up -d
echo "DMZ services started"
docker compose --profile dmz ps
EOF
    
    # Stop all
    cat > scripts/stop-all.sh << 'EOF'
#!/bin/bash
echo "Stopping all services..."
docker compose --profile lan down
docker compose --profile dmz down
echo "All services stopped"
EOF
    
    # Backup
    cat > scripts/backup.sh << 'EOF'
#!/bin/bash
BACKUP_DIR="./backups/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

echo "Backing up Docker volumes..."
docker run --rm -v opnsense_postgres_data:/data -v "$PWD/$BACKUP_DIR":/backup alpine tar czf /backup/postgres_data.tar.gz -C /data .
docker run --rm -v opnsense_grafana_data:/data -v "$PWD/$BACKUP_DIR":/backup alpine tar czf /backup/grafana_data.tar.gz -C /data .

echo "Backing up configurations..."
cp -r monitoring "$BACKUP_DIR/"
cp .env "$BACKUP_DIR/" 2>/dev/null || true

echo "Backup completed at: $BACKUP_DIR"
EOF
    
    # Logs
    cat > scripts/logs.sh << 'EOF'
#!/bin/bash
if [[ "$1" == "lan" ]]; then
    docker compose --profile lan logs -f
elif [[ "$1" == "dmz" ]]; then
    docker compose --profile dmz logs -f
else
    echo "Usage: $0 [lan|dmz]"
    echo "  lan - Show LAN service logs"
    echo "  dmz - Show DMZ service logs"
fi
EOF
    
    chmod +x scripts/*.sh
    
    log_success "Management scripts created in ./scripts/"
}

# Final information
show_final_info() {
    echo ""
    echo -e "${CYAN}  Setup completed successfully!${NC}"
    echo ""
    echo -e "${BLUE}  Next steps:${NC}"
    echo "1. Edit the .env file with your actual values"
    echo "2. Start services:"
    echo "   - LAN:  ./scripts/start-lan.sh"
    echo "   - DMZ:  ./scripts/start-dmz.sh"
    echo ""
    echo -e "${BLUE}  Access URLs (after startup):${NC}"
    echo "- Grafana:    https://[DMZ_HOST_IP]/grafana/"
    echo "- Prometheus: https://[DMZ_HOST_IP]/prometheus/"
    echo "- Nagios:     https://[DMZ_HOST_IP]/nagios/"
    echo ""
    echo -e "${BLUE}  Default credentials:${NC}"
    echo "- Nginx:   admin / SuperPassword!"
    echo "- Grafana: admin / [GRAFANA_ADMIN_PASSWORD]"
    echo "- Nagios:  [NAGIOS_USER] / [NAGIOS_PASS]"
    echo ""
    echo -e "${BLUE}  Management scripts:${NC}"
    echo "- ./scripts/start-lan.sh        - Start LAN services"
    echo "- ./scripts/start-dmz.sh        - Start DMZ services"
    echo "- ./scripts/stop-all.sh         - Stop all services"
    echo "- ./scripts/logs.sh [lan|dmz]   - Show logs"
    echo "- ./scripts/backup.sh           - Backup data"
    echo ""
    echo -e "${YELLOW} IMPORTANT:${NC}"
    echo "- Change all passwords in the .env file"
    echo "- SSL certificates are self-signed (browser warning expected)"
    echo "- Verify network IPs (LAN_HOST_IP and DMZ_HOST_IP)"
    echo ""
    echo -e "${GREEN} Happy monitoring!${NC}"
}

# Main execution
main() {
    echo -e "${YELLOW}This script will configure the complete monitoring environment.${NC}"
    echo -e "${YELLOW}Continue? (y/N)${NC}"
    read -r response
    
    if [[ ! "$response" =~ ^[Yy]$ ]]; then
        echo "Setup cancelled."
        exit 0
    fi
    
    check_prerequisites
    create_directory_structure
    generate_ssl_certificates
    create_config_files
    check_env_file
    test_docker_config
    create_management_scripts
    show_final_info
}

# Run main if script is called directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi