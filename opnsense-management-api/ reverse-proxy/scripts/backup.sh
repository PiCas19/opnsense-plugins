#!/bin/bash

# Backup script for OPNsense Reverse Proxy
# Performs backup of configurations, database and logs

set -e

# Configuration
BACKUP_DIR="${BACKUP_DIR:-/tmp/opnsense-backup}"
RETENTION_DAYS="${RETENTION_DAYS:-30}"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_NAME="opnsense-proxy-backup_${TIMESTAMP}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

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

# Check if Docker is available
check_docker() {
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not available"
        exit 1
    fi
    
    if ! command -v docker-compose &> /dev/null; then
        log_error "Docker Compose is not available"
        exit 1
    fi
}

# Create backup directory
create_backup_dir() {
    log_info "Creating backup directory: ${BACKUP_DIR}/${BACKUP_NAME}"
    mkdir -p "${BACKUP_DIR}/${BACKUP_NAME}"
}

# Backup configurations
backup_configs() {
    log_info "Backing up configurations..."
    
    local config_dir="${BACKUP_DIR}/${BACKUP_NAME}/configs"
    mkdir -p "$config_dir"
    
    # Backup configuration files
    if [ -f .env ]; then
        cp .env "$config_dir/" || log_warning "Could not copy .env"
    fi
    
    if [ -f docker-compose.yml ]; then
        cp docker-compose.yml "$config_dir/" || log_warning "Could not copy docker-compose.yml"
    fi
    
    # Backup Nginx configurations
    if [ -d nginx ]; then
        cp -r nginx "$config_dir/" || log_warning "Could not copy Nginx configurations"
    fi
    
    # Backup Grafana configurations
    if [ -d grafana ]; then
        cp -r grafana "$config_dir/" || log_warning "Could not copy Grafana configurations"
    fi
    
    # Backup scripts
    if [ -d scripts ]; then
        cp -r scripts "$config_dir/" || log_warning "Could not copy scripts"
    fi
    
    log_success "Configuration backup completed"
}

# Backup Docker volumes
backup_volumes() {
    log_info "Backing up Docker volumes..."
    
    local volumes_dir="${BACKUP_DIR}/${BACKUP_NAME}/volumes"
    mkdir -p "$volumes_dir"
    
    # Backup Grafana volume
    if docker volume ls | grep -q grafana_data; then
        log_info "Backing up Grafana volume..."
        docker run --rm \
            -v "$(pwd)_grafana_data:/source:ro" \
            -v "${volumes_dir}:/backup" \
            alpine:latest \
            tar czf /backup/grafana_data.tar.gz -C /source . \
            || log_warning "Error backing up Grafana volume"
    fi
    
    log_success "Volume backup completed"
}

# Backup database (if accessible)
backup_database() {
    log_info "Backing up database..."
    
    local db_dir="${BACKUP_DIR}/${BACKUP_NAME}/database"
    mkdir -p "$db_dir"
    
    # Check if .env file exists and load variables
    if [ -f .env ]; then
        source .env
        
        # Backup PostgreSQL database from wrapper
        if [ -n "$POSTGRES_HOST" ] && [ -n "$POSTGRES_PASSWORD" ]; then
            log_info "Attempting PostgreSQL database backup..."
            
            # Use temporary container for pg_dump
            docker run --rm \
                -e PGPASSWORD="$POSTGRES_PASSWORD" \
                postgres:15-alpine \
                pg_dump -h "$POSTGRES_HOST" -p "${POSTGRES_PORT:-5432}" \
                -U "${POSTGRES_USER:-opnsense}" \
                -d "${POSTGRES_DB:-opnsense_mgmt}" \
                --no-owner --no-privileges > "${db_dir}/opnsense_mgmt.sql" \
                2>/dev/null || log_warning "Could not backup database (normal if not accessible)"
        fi
    fi
    
    log_success "Database backup completed"
}

# Backup logs
backup_logs() {
    log_info "Backing up logs..."
    
    local logs_dir="${BACKUP_DIR}/${BACKUP_NAME}/logs"
    mkdir -p "$logs_dir"
    
    # Backup local logs
    if [ -d logs ]; then
        cp -r logs "$logs_dir/local_logs" || log_warning "Could not copy local logs"
    fi
    
    # Backup Docker container logs
    log_info "Exporting container logs..."
    
    # Nginx logs
    if docker-compose ps nginx | grep -q "Up"; then
        docker-compose logs --no-color nginx > "$logs_dir/nginx.log" 2>/dev/null || true
    fi
    
    # Grafana logs
    if docker-compose ps grafana | grep -q "Up"; then
        docker-compose logs --no-color grafana > "$logs_dir/grafana.log" 2>/dev/null || true
    fi
    
    log_success "Log backup completed"
}

# Export container state
export_container_state() {
    log_info "Exporting container state..."
    
    local state_dir="${BACKUP_DIR}/${BACKUP_NAME}/state"
    mkdir -p "$state_dir"
    
    # Docker Compose state
    docker-compose ps > "$state_dir/docker-compose-ps.txt" 2>/dev/null || true
    docker-compose config > "$state_dir/docker-compose-config.yml" 2>/dev/null || true
    
    # Container info
    docker ps -a --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" > "$state_dir/docker-ps.txt" 2>/dev/null || true
    
    # Volume info
    docker volume ls > "$state_dir/docker-volumes.txt" 2>/dev/null || true
    
    # Network info
    docker network ls > "$state_dir/docker-networks.txt" 2>/dev/null || true
    
    log_success "Container state export completed"
}

# Create compressed archive
create_archive() {
    log_info "Creating compressed archive..."
    
    cd "$BACKUP_DIR"
    tar czf "${BACKUP_NAME}.tar.gz" "$BACKUP_NAME" || {
        log_error "Error creating archive"
        exit 1
    }
    
    # Remove temporary directory
    rm -rf "$BACKUP_NAME"
    
    local archive_path="${BACKUP_DIR}/${BACKUP_NAME}.tar.gz"
    local archive_size=$(du -h "$archive_path" | cut -f1)
    
    log_success "Archive created: $archive_path (${archive_size})"
}

# Cleanup old backups
cleanup_old_backups() {
    log_info "Removing backups older than $RETENTION_DAYS days..."
    
    find "$BACKUP_DIR" -name "opnsense-proxy-backup_*.tar.gz" -type f -mtime +$RETENTION_DAYS -delete 2>/dev/null || true
    
    local remaining_backups=$(find "$BACKUP_DIR" -name "opnsense-proxy-backup_*.tar.gz" -type f | wc -l)
    log_success "Cleanup completed. Remaining backups: $remaining_backups"
}

# Generate backup report
generate_report() {
    local report_file="${BACKUP_DIR}/${BACKUP_NAME}.report"
    
    cat > "$report_file" << EOF
# OPNsense Reverse Proxy - Backup Report
Generated: $(date)
Backup: ${BACKUP_NAME}.tar.gz

## System Information
Hostname: $(hostname)
OS: $(uname -s)
Kernel: $(uname -r)
Docker Version: $(docker --version 2>/dev/null || echo "N/A")
Docker Compose Version: $(docker-compose --version 2>/dev/null || echo "N/A")

## Backup Contents
- Configurations (nginx, grafana, .env, docker-compose.yml)
- Docker volumes (grafana_data)
- Database dump (if accessible)
- Application logs
- Container states and info

## Files Included
$(cd "${BACKUP_DIR}" && tar -tzf "${BACKUP_NAME}.tar.gz" | head -20)
$([ $(cd "${BACKUP_DIR}" && tar -tzf "${BACKUP_NAME}.tar.gz" | wc -l) -gt 20 ] && echo "... and $(($(cd "${BACKUP_DIR}" && tar -tzf "${BACKUP_NAME}.tar.gz" | wc -l) - 20)) more files")

## Archive Information
Size: $(du -h "${BACKUP_DIR}/${BACKUP_NAME}.tar.gz" | cut -f1)
Location: ${BACKUP_DIR}/${BACKUP_NAME}.tar.gz

## Restoration Instructions
1. Extract archive: tar xzf ${BACKUP_NAME}.tar.gz
2. Copy configurations to project directory
3. Restore volumes: docker run --rm -v \$(pwd)_grafana_data:/target -v \$(pwd)/volumes:/backup alpine tar xzf /backup/grafana_data.tar.gz -C /target
4. Import database: psql -h <host> -U <user> -d <db> < database/opnsense_mgmt.sql
5. Start services: docker-compose up -d

EOF

    log_success "Backup report generated: $report_file"
}

# Main function
main() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║              OPNsense Reverse Proxy - Backup                ║"
    echo "║                                                              ║"
    echo "║  Complete backup of configurations, volumes and database    ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    check_docker
    create_backup_dir
    backup_configs
    backup_volumes
    backup_database
    backup_logs
    export_container_state
    create_archive
    generate_report
    cleanup_old_backups
    
    echo
    log_success "🎉 Backup completed successfully!"
    echo -e "${BLUE}Archive:${NC} ${BACKUP_DIR}/${BACKUP_NAME}.tar.gz"
    echo -e "${BLUE}Report:${NC} ${BACKUP_DIR}/${BACKUP_NAME}.report"
    echo
}

# Parameter handling
case "${1:-}" in
    --help|-h)
        echo "Usage: $0 [options]"
        echo
        echo "Options:"
        echo "  --help, -h          Show this help"
        echo "  --retention DAYS    Retention days (default: 30)"
        echo "  --backup-dir DIR    Backup directory (default: /tmp/opnsense-backup)"
        echo
        echo "Environment variables:"
        echo "  BACKUP_DIR          Backup directory"
        echo "  RETENTION_DAYS      Retention days"
        echo
        exit 0
        ;;
    --retention)
        RETENTION_DAYS="$2"
        shift 2
        ;;
    --backup-dir)
        BACKUP_DIR="$2"
        shift 2
        ;;
    "")
        # No parameters, run backup
        ;;
    *)
        log_error "Unknown parameter: $1"
        exit 1
        ;;
esac

# Run backup
main "$@"#!/bin/bash

# Backup script per OPNsense Reverse Proxy
# Esegue backup di configurazioni, database e log

set -e

# Configurazione
BACKUP_DIR="${BACKUP_DIR:-/tmp/opnsense-backup}"
RETENTION_DAYS="${RETENTION_DAYS:-30}"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_NAME="opnsense-proxy-backup_${TIMESTAMP}"

# Colori per output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Funzioni di logging
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

# Verifica che Docker sia disponibile
check_docker() {
    if ! command -v docker &> /dev/null; then
        log_error "Docker non è disponibile"
        exit 1
    fi
    
    if ! command -v docker-compose &> /dev/null; then
        log_error "Docker Compose non è disponibile"
        exit 1
    fi
}

# Crea directory di backup
create_backup_dir() {
    log_info "Creando directory di backup: ${BACKUP_DIR}/${BACKUP_NAME}"
    mkdir -p "${BACKUP_DIR}/${BACKUP_NAME}"
}

# Backup configurazioni
backup_configs() {
    log_info "Backup configurazioni..."
    
    local config_dir="${BACKUP_DIR}/${BACKUP_NAME}/configs"
    mkdir -p "$config_dir"
    
    # Backup file di configurazione
    if [ -f .env ]; then
        cp .env "$config_dir/" || log_warning "Impossibile copiare .env"
    fi
    
    if [ -f docker-compose.yml ]; then
        cp docker-compose.yml "$config_dir/" || log_warning "Impossibile copiare docker-compose.yml"
    fi
    
    # Backup configurazioni Nginx
    if [ -d nginx ]; then
        cp -r nginx "$config_dir/" || log_warning "Impossibile copiare configurazioni Nginx"
    fi
    
    # Backup configurazioni Grafana
    if [ -d grafana ]; then
        cp -r grafana "$config_dir/" || log_warning "Impossibile copiare configurazioni Grafana"
    fi
    
    # Backup script
    if [ -d scripts ]; then
        cp -r scripts "$config_dir/" || log_warning "Impossibile copiare script"
    fi
    
    log_success "Backup configurazioni completato"
}

# Backup volumi Docker
backup_volumes() {
    log_info "Backup volumi Docker..."
    
    local volumes_dir="${BACKUP_DIR}/${BACKUP_NAME}/volumes"
    mkdir -p "$volumes_dir"
    
    # Backup volume Grafana
    if docker volume ls | grep -q grafana_data; then
        log_info "Backup volume Grafana..."
        docker run --rm \
            -v "$(pwd)_grafana_data:/source:ro" \
            -v "${volumes_dir}:/backup" \
            alpine:latest \
            tar czf /backup/grafana_data.tar.gz -C /source . \
            || log_warning "Errore backup volume Grafana"
    fi
    
    log_success "Backup volumi completato"
}

# Backup database (se accessibile)
backup_database() {
    log_info "Backup database..."
    
    local db_dir="${BACKUP_DIR}/${BACKUP_NAME}/database"
    mkdir -p "$db_dir"
    
    # Verifica se il file .env esiste e carica le variabili
    if [ -f .env ]; then
        source .env
        
        # Backup database PostgreSQL del wrapper
        if [ -n "$POSTGRES_HOST" ] && [ -n "$POSTGRES_PASSWORD" ]; then
            log_info "Tentativo backup database PostgreSQL..."
            
            # Usa container temporaneo per pg_dump
            docker run --rm \
                -e PGPASSWORD="$POSTGRES_PASSWORD" \
                postgres:15-alpine \
                pg_dump -h "$POSTGRES_HOST" -p "${POSTGRES_PORT:-5432}" \
                -U "${POSTGRES_USER:-opnsense}" \
                -d "${POSTGRES_DB:-opnsense_mgmt}" \
                --no-owner --no-privileges > "${db_dir}/opnsense_mgmt.sql" \
                2>/dev/null || log_warning "Impossibile eseguire backup database (normale se non accessibile)"
        fi
    fi
    
    log_success "Backup database completato"
}

# Backup log
backup_logs() {
    log_info "Backup log..."
    
    local logs_dir="${BACKUP_DIR}/${BACKUP_NAME}/logs"
    mkdir -p "$logs_dir"
    
    # Backup log locali
    if [ -d logs ]; then
        cp -r logs "$logs_dir/local_logs" || log_warning "Impossibile copiare log locali"
    fi
    
    # Backup log dei container Docker
    log_info "Esportando log dei container..."
    
    # Log Nginx
    if docker-compose ps nginx | grep -q "Up"; then
        docker-compose logs --no-color nginx > "$logs_dir/nginx.log" 2>/dev/null || true
    fi
    
    # Log Grafana
    if docker-compose ps grafana | grep -q "Up"; then
        docker-compose logs --no-color grafana > "$logs_dir/grafana.log" 2>/dev/null || true
    fi
    
    log_success "Backup log completato"
}

# Esporta stato dei container
export_container_state() {
    log_info "Esportando stato container..."
    
    local state_dir="${BACKUP_DIR}/${BACKUP_NAME}/state"
    mkdir -p "$state_dir"
    
    # Stato Docker Compose
    docker-compose ps > "$state_dir/docker-compose-ps.txt" 2>/dev/null || true
    docker-compose config > "$state_dir/docker-compose-config.yml" 2>/dev/null || true
    
    # Info container
    docker ps -a --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" > "$state_dir/docker-ps.txt" 2>/dev/null || true
    
    # Info volumi
    docker volume ls > "$state_dir/docker-volumes.txt" 2>/dev/null || true
    
    # Info network
    docker network ls > "$state_dir/docker-networks.txt" 2>/dev/null || true
    
    log_success "Esportazione stato container completata"
}

# Crea archivio compresso
create_archive() {
    log_info "Creando archivio compresso..."
    
    cd "$BACKUP_DIR"
    tar czf "${BACKUP_NAME}.tar.gz" "$BACKUP_NAME" || {
        log_error "Errore durante la creazione dell'archivio"
        exit 1
    }
    
    # Rimuovi directory temporanea
    rm -rf "$BACKUP_NAME"
    
    local archive_path="${BACKUP_DIR}/${BACKUP_NAME}.tar.gz"
    local archive_size=$(du -h "$archive_path" | cut -f1)
    
    log_success "Archivio creato: $archive_path (${archive_size})"
}

# Cleanup vecchi backup
cleanup_old_backups() {
    log_info "Rimozione backup più vecchi di $RETENTION_DAYS giorni..."
    
    find "$BACKUP_DIR" -name "opnsense-proxy-backup_*.tar.gz" -type f -mtime +$RETENTION_DAYS -delete 2>/dev/null || true
    
    local remaining_backups=$(find "$BACKUP_DIR" -name "opnsense-proxy-backup_*.tar.gz" -type f | wc -l)
    log_success "Cleanup completato. Backup rimanenti: $remaining_backups"
}

# Genera report di backup
generate_report() {
    local report_file="${BACKUP_DIR}/${BACKUP_NAME}.report"
    
    cat > "$report_file" << EOF
# OPNsense Reverse Proxy - Backup Report
Generated: $(date)
Backup: ${BACKUP_NAME}.tar.gz

## System Information
Hostname: $(hostname)
OS: $(uname -s)
Kernel: $(uname -r)
Docker Version: $(docker --version 2>/dev/null || echo "N/A")
Docker Compose Version: $(docker-compose --version 2>/dev/null || echo "N/A")

## Backup Contents
- Configurations (nginx, grafana, .env, docker-compose.yml)
- Docker volumes (grafana_data)
- Database dump (if accessible)
- Application logs
- Container states and info

## Files Included
$(cd "${BACKUP_DIR}" && tar -tzf "${BACKUP_NAME}.tar.gz" | head -20)
$([ $(cd "${BACKUP_DIR}" && tar -tzf "${BACKUP_NAME}.tar.gz" | wc -l) -gt 20 ] && echo "... and $(($(cd "${BACKUP_DIR}" && tar -tzf "${BACKUP_NAME}.tar.gz" | wc -l) - 20)) more files")

## Archive Information
Size: $(du -h "${BACKUP_DIR}/${BACKUP_NAME}.tar.gz" | cut -f1)
Location: ${BACKUP_DIR}/${BACKUP_NAME}.tar.gz

## Restoration Instructions
1. Extract archive: tar xzf ${BACKUP_NAME}.tar.gz
2. Copy configurations to project directory
3. Restore volumes: docker run --rm -v \$(pwd)_grafana_data:/target -v \$(pwd)/volumes:/backup alpine tar xzf /backup/grafana_data.tar.gz -C /target
4. Import database: psql -h <host> -U <user> -d <db> < database/opnsense_mgmt.sql
5. Start services: docker-compose up -d

EOF

    log_success "Report di backup generato: $report_file"
}

# Funzione principale
main() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║              OPNsense Reverse Proxy - Backup                ║"
    echo "║                                                              ║"
    echo "║  Backup completo di configurazioni, volumi e database       ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    check_docker
    create_backup_dir
    backup_configs
    backup_volumes
    backup_database
    backup_logs
    export_container_state
    create_archive
    generate_report
    cleanup_old_backups
    
    echo
    log_success "🎉 Backup completato con successo!"
    echo -e "${BLUE}Archivio:${NC} ${BACKUP_DIR}/${BACKUP_NAME}.tar.gz"
    echo -e "${BLUE}Report:${NC} ${BACKUP_DIR}/${BACKUP_NAME}.report"
    echo
}

# Gestione parametri
case "${1:-}" in
    --help|-h)
        echo "Usage: $0 [options]"
        echo
        echo "Options:"
        echo "  --help, -h          Mostra questo help"
        echo "  --retention DAYS    Giorni di retention (default: 30)"
        echo "  --backup-dir DIR    Directory di backup (default: /tmp/opnsense-backup)"
        echo
        echo "Environment variables:"
        echo "  BACKUP_DIR          Directory di backup"
        echo "  RETENTION_DAYS      Giorni di retention"
        echo
        exit 0
        ;;
    --retention)
        RETENTION_DAYS="$2"
        shift 2
        ;;
    --backup-dir)
        BACKUP_DIR="$2"
        shift 2
        ;;
    "")
        # Nessun parametro, esegui backup
        ;;
    *)
        log_error "Parametro sconosciuto: $1"
        exit 1
        ;;
esac

# Esegui backup
main "$@"