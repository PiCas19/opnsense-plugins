#!/bin/bash

# Monitoring script for OPNsense Reverse Proxy
# Monitors service health and sends alerting notifications

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
LOG_FILE="${LOG_FILE:-${PROJECT_DIR}/logs/monitor.log}"
WEBHOOK_URL="${WEBHOOK_URL:-}"
EMAIL_TO="${EMAIL_TO:-}"
SMTP_SERVER="${SMTP_SERVER:-}"
CHECK_INTERVAL="${CHECK_INTERVAL:-60}"
MAX_RETRIES="${MAX_RETRIES:-3}"
RETRY_DELAY="${RETRY_DELAY:-10}"

# Alerting thresholds
CPU_THRESHOLD="${CPU_THRESHOLD:-80}"
MEMORY_THRESHOLD="${MEMORY_THRESHOLD:-80}"
DISK_THRESHOLD="${DISK_THRESHOLD:-85}"
RESPONSE_TIME_THRESHOLD="${RESPONSE_TIME_THRESHOLD:-5000}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Global state arrays
ALERTS=()
WARNINGS=()
SERVICES_OK=()
SERVICES_FAILED=()

# Logging functions
log_message() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
    log_message "INFO" "$1"
}

log_success() {
    echo -e "${GREEN}[OK]${NC} $1"
    log_message "OK" "$1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
    log_message "WARNING" "$1"
    WARNINGS+=("$1")
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
    log_message "ERROR" "$1"
    ALERTS+=("$1")
}

# Create log directory if it doesn't exist
setup_logging() {
    mkdir -p "$(dirname "$LOG_FILE")"
    
    # Log rotation if too large (>10MB)
    if [ -f "$LOG_FILE" ] && [ $(stat -f%z "$LOG_FILE" 2>/dev/null || stat -c%s "$LOG_FILE" 2>/dev/null || echo 0) -gt 10485760 ]; then
        mv "$LOG_FILE" "${LOG_FILE}.old"
        touch "$LOG_FILE"
        log_info "Log file rotated due to size"
    fi
}

# Check Docker container status
check_containers() {
    log_info "Checking Docker container status..."
    
    cd "$PROJECT_DIR"
    
    # List of services defined in docker-compose
    local services=(nginx grafana)
    
    for service in "${services[@]}"; do
        if docker-compose ps "$service" | grep -q "Up"; then
            log_success "Container $service: Running"
            SERVICES_OK+=("$service")
        else
            log_error "Container $service: Not running or unhealthy"
            SERVICES_FAILED+=("$service")
            
            # Automatic restart attempt
            log_info "Attempting to restart container $service..."
            if docker-compose restart "$service" >/dev/null 2>&1; then
                sleep 5
                if docker-compose ps "$service" | grep -q "Up"; then
                    log_success "Container $service restarted successfully"
                    SERVICES_OK+=("$service (restarted)")
                else
                    log_error "Failed to restart container $service"
                fi
            else
                log_error "Error during restart of container $service"
            fi
        fi
    done
}

# Check network connectivity
check_network_connectivity() {
    log_info "Checking network connectivity..."
    
    # Test connection to OPNsense wrapper
    local wrapper_host="${OPNSENSE_API_HOST:-192.168.216.50}"
    local wrapper_port="${OPNSENSE_API_PORT:-3000}"
    
    if timeout 10 nc -z "$wrapper_host" "$wrapper_port" 2>/dev/null; then
        log_success "Connection to OPNsense wrapper: OK ($wrapper_host:$wrapper_port)"
    else
        log_error "OPNsense wrapper not reachable: $wrapper_host:$wrapper_port"
    fi
    
    # Test DNS resolution
    if nslookup google.com >/dev/null 2>&1; then
        log_success "DNS resolution: OK"
    else
        log_warning "DNS resolution: Issues detected"
    fi
    
    # Test internet connection
    if curl -s --connect-timeout 10 --max-time 15 http://httpbin.org/ip >/dev/null 2>&1; then
        log_success "Internet connection: OK"
    else
        log_warning "Internet connection: Limited or unavailable"
    fi
}

# Check HTTP endpoints
check_http_endpoints() {
    log_info "Checking HTTP endpoints..."
    
    local endpoints=(
        "https://localhost/health:Health Check"
        "https://localhost/grafana/api/health:Grafana API"
    )
    
    for endpoint_info in "${endpoints[@]}"; do
        local url=$(echo "$endpoint_info" | cut -d: -f1)
        local name=$(echo "$endpoint_info" | cut -d: -f2)
        
        local start_time=$(date +%s%3N)
        local http_code=$(curl -k -s -o /dev/null -w "%{http_code}" --connect-timeout 10 --max-time 15 "$url" 2>/dev/null || echo "000")
        local end_time=$(date +%s%3N)
        local response_time=$((end_time - start_time))
        
        if [[ "$http_code" =~ ^[23] ]]; then
            if [ "$response_time" -lt "$RESPONSE_TIME_THRESHOLD" ]; then
                log_success "$name: OK (${response_time}ms, HTTP $http_code)"
            else
                log_warning "$name: Slow response (${response_time}ms, HTTP $http_code)"
            fi
        else
            log_error "$name: Error (HTTP $http_code, ${response_time}ms)"
        fi
    done
}

# Check system resource usage
check_system_resources() {
    log_info "Checking system resource usage..."
    
    # CPU Usage
    local cpu_usage
    if command -v top >/dev/null 2>&1; then
        cpu_usage=$(top -l 1 | grep "CPU usage" | awk '{print $3}' | sed 's/%//' 2>/dev/null || echo "0")
    elif command -v vmstat >/dev/null 2>&1; then
        cpu_usage=$(vmstat 1 2 | tail -1 | awk '{print 100-$15}' 2>/dev/null || echo "0")
    else
        cpu_usage="N/A"
    fi
    
    if [[ "$cpu_usage" != "N/A" ]] && (( $(echo "$cpu_usage > $CPU_THRESHOLD" | bc -l 2>/dev/null || echo 0) )); then
        log_warning "High CPU usage detected: ${cpu_usage}%"
    else
        log_success "CPU usage: ${cpu_usage}%"
    fi
    
    # Memory Usage
    local memory_usage
    if command -v free >/dev/null 2>&1; then
        memory_usage=$(free | grep Mem | awk '{printf("%.1f", $3/$2 * 100.0)}' 2>/dev/null || echo "0")
    elif command -v vm_stat >/dev/null 2>&1; then
        # macOS
        local total_mem=$(sysctl -n hw.memsize)
        local used_mem=$(vm_stat | grep "Pages active:" | awk '{print $3}' | sed 's/\.//')
        memory_usage=$(echo "scale=1; $used_mem * 4096 / $total_mem * 100" | bc 2>/dev/null || echo "N/A")
    else
        memory_usage="N/A"
    fi
    
    if [[ "$memory_usage" != "N/A" ]] && (( $(echo "$memory_usage > $MEMORY_THRESHOLD" | bc -l 2>/dev/null || echo 0) )); then
        log_warning "High memory usage detected: ${memory_usage}%"
    else
        log_success "Memory usage: ${memory_usage}%"
    fi
    
    # Disk Usage
    local disk_usage=$(df / | awk 'NR==2 {print $5}' | sed 's/%//' 2>/dev/null || echo "0")
    
    if (( disk_usage > DISK_THRESHOLD )); then
        log_warning "High disk usage detected: ${disk_usage}%"
    else
        log_success "Disk usage: ${disk_usage}%"
    fi
}

# Check logs for errors
check_logs_for_errors() {
    log_info "Checking logs for recent errors..."
    
    cd "$PROJECT_DIR"
    
    # Check Nginx logs
    local nginx_errors=$(docker-compose logs --since=10m nginx 2>/dev/null | grep -i error | wc -l)
    if [ "$nginx_errors" -gt 0 ]; then
        log_warning "Found $nginx_errors error(s) in Nginx logs (last 10 minutes)"
    else
        log_success "Nginx logs: No recent errors found"
    fi
    
    # Check Grafana logs
    local grafana_errors=$(docker-compose logs --since=10m grafana 2>/dev/null | grep -i "error\|fatal" | wc -l)
    if [ "$grafana_errors" -gt 0 ]; then
        log_warning "Found $grafana_errors error(s) in Grafana logs (last 10 minutes)"
    else
        log_success "Grafana logs: No recent errors found"
    fi
}

# Check Docker volumes space
check_docker_volumes() {
    log_info "Checking Docker volumes..."
    
    # Volume space usage
    local volumes_size=$(docker system df -v 2>/dev/null | grep "Local Volumes space usage" | awk '{print $4}' || echo "N/A")
    log_success "Docker volumes space usage: $volumes_size"
    
    # Check orphaned volumes
    local orphan_volumes=$(docker volume ls -qf dangling=true | wc -l)
    if [ "$orphan_volumes" -gt 0 ]; then
        log_warning "Found $orphan_volumes orphaned volume(s)"
    else
        log_success "No orphaned volumes found"
    fi
}

# Check SSL certificates
check_ssl_certificates() {
    log_info "Checking SSL certificates..."
    
    local cert_file="$PROJECT_DIR/nginx/ssl/server.crt"
    
    if [ -f "$cert_file" ]; then
        local expiry_date=$(openssl x509 -in "$cert_file" -noout -enddate 2>/dev/null | cut -d= -f2)
        local expiry_timestamp=$(date -d "$expiry_date" +%s 2>/dev/null || date -j -f "%b %d %H:%M:%S %Y %Z" "$expiry_date" +%s 2>/dev/null || echo 0)
        local current_timestamp=$(date +%s)
        local days_until_expiry=$(( (expiry_timestamp - current_timestamp) / 86400 ))
        
        if [ "$days_until_expiry" -lt 7 ]; then
            log_error "SSL certificate expires in $days_until_expiry days - URGENT RENEWAL NEEDED"
        elif [ "$days_until_expiry" -lt 30 ]; then
            log_warning "SSL certificate expires in $days_until_expiry days"
        else
            log_success "SSL certificate valid for $days_until_expiry days"
        fi
    else
        log_warning "SSL certificate file not found"
    fi
}

# Send webhook notification
send_webhook_notification() {
    local title="$1"
    local message="$2"
    local level="$3"
    
    if [ -z "$WEBHOOK_URL" ]; then
        return 0
    fi
    
    local color
    case "$level" in
        "error") color="#FF0000" ;;
        "warning") color="#FFA500" ;;
        *) color="#00FF00" ;;
    esac
    
    local payload=$(cat <<EOF
{
    "embeds": [{
        "title": "$title",
        "description": "$message",
        "color": $(printf "%d" "$color"),
        "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%S.000Z)",
        "footer": {
            "text": "OPNsense Reverse Proxy Monitor"
        }
    }]
}
EOF
)
    
    curl -s -H "Content-Type: application/json" -d "$payload" "$WEBHOOK_URL" >/dev/null 2>&1 || true
}

# Send email notification
send_email_notification() {
    local subject="$1"
    local body="$2"
    
    if [ -z "$EMAIL_TO" ] || [ -z "$SMTP_SERVER" ]; then
        return 0
    fi
    
    # Basic email implementation (requires SMTP configuration)
    echo "Subject: $subject" > /tmp/email_body.txt
    echo >> /tmp/email_body.txt
    echo "$body" >> /tmp/email_body.txt
    
    # Use sendmail, postfix or similar if configured
    # sendmail "$EMAIL_TO" < /tmp/email_body.txt 2>/dev/null || true
    
    rm -f /tmp/email_body.txt
}

# Send alerts
send_alerts() {
    if [ ${#ALERTS[@]} -gt 0 ] || [ ${#WARNINGS[@]} -gt 0 ]; then
        local title="OPNsense Proxy - System Alert"
        local message=""
        
        if [ ${#ALERTS[@]} -gt 0 ]; then
            message+="🚨 CRITICAL ERRORS:\n"
            for alert in "${ALERTS[@]}"; do
                message+="• $alert\n"
            done
            message+="\n"
        fi
        
        if [ ${#WARNINGS[@]} -gt 0 ]; then
            message+="⚠️ WARNINGS:\n"
            for warning in "${WARNINGS[@]}"; do
                message+="• $warning\n"
            done
            message+="\n"
        fi
        
        message+="✅ SERVICES OK: ${#SERVICES_OK[@]}\n"
        message+="❌ SERVICES FAILED: ${#SERVICES_FAILED[@]}\n"
        message+="\nTimestamp: $(date)\n"
        message+="Host: $(hostname)"
        
        local level="info"
        [ ${#ALERTS[@]} -gt 0 ] && level="error"
        [ ${#WARNINGS[@]} -gt 0 ] && [ "$level" != "error" ] && level="warning"
        
        send_webhook_notification "$title" "$message" "$level"
        send_email_notification "$title" "$message"
        
        log_info "Notifications sent: ${#ALERTS[@]} errors, ${#WARNINGS[@]} warnings"
    fi
}

# Generate status report
generate_status_report() {
    local report_file="$PROJECT_DIR/logs/status_report.txt"
    
    cat > "$report_file" << EOF
# OPNsense Reverse Proxy - Status Report
Generated: $(date)
Host: $(hostname)

## Service Status
Services OK: ${#SERVICES_OK[@]}
Services Failed: ${#SERVICES_FAILED[@]}

Services OK: $(IFS=', '; echo "${SERVICES_OK[*]}")
Services Failed: $(IFS=', '; echo "${SERVICES_FAILED[*]}")

## Alerts Summary
Critical Errors: ${#ALERTS[@]}
Warnings: ${#WARNINGS[@]}

## Recent Log Entries (last 10)
$(tail -10 "$LOG_FILE" 2>/dev/null || echo "No log entries found")

## System Information
$(df -h / 2>/dev/null | tail -1 || echo "Disk info N/A")
$(free -h 2>/dev/null | grep Mem || echo "Memory info N/A")
$(uptime 2>/dev/null || echo "Uptime N/A")

## Docker Status
$(docker --version 2>/dev/null || echo "Docker version N/A")
$(docker-compose --version 2>/dev/null || echo "Docker Compose version N/A")

EOF
    
    log_success "Status report generated: $report_file"
}

# Continuous monitoring mode
run_continuous_monitoring() {
    log_info "Starting continuous monitoring (interval: ${CHECK_INTERVAL}s)"
    
    while true; do
        echo
        log_info "=== Monitoring check started at $(date) ==="
        
        # Reset arrays for each check
        ALERTS=()
        WARNINGS=()
        SERVICES_OK=()
        SERVICES_FAILED=()
        
        # Execute all monitoring checks
        check_containers
        check_network_connectivity
        check_http_endpoints
        check_system_resources
        check_logs_for_errors
        check_docker_volumes
        check_ssl_certificates
        
        # Send alerts if necessary
        send_alerts
        
        # Generate report every hour (when minute is 00)
        local current_minute=$(date +%M)
        if [ "$current_minute" = "00" ]; then
            generate_status_report
        fi
        
        log_info "Monitoring check completed. Next check in ${CHECK_INTERVAL} seconds"
        
        # Wait for next check
        sleep "$CHECK_INTERVAL"
    done
}

# Single check mode
run_single_check() {
    log_info "Running single monitoring check"
    
    # Reset arrays
    ALERTS=()
    WARNINGS=()
    SERVICES_OK=()
    SERVICES_FAILED=()
    
    # Execute all monitoring checks
    check_containers
    check_network_connectivity
    check_http_endpoints
    check_system_resources
    check_logs_for_errors
    check_docker_volumes
    check_ssl_certificates
    
    # Send alerts if necessary
    send_alerts
    
    # Generate report
    generate_status_report
    
    # Final summary
    echo
    if [ ${#ALERTS[@]} -eq 0 ] && [ ${#WARNINGS[@]} -eq 0 ]; then
        log_success "🎉 All checks completed successfully - System is healthy!"
    else
        log_warning "⚠️ Checks completed with ${#ALERTS[@]} error(s) and ${#WARNINGS[@]} warning(s)"
    fi
    
    echo -e "${BLUE}Services OK:${NC} ${#SERVICES_OK[@]}"
    echo -e "${BLUE}Services Failed:${NC} ${#SERVICES_FAILED[@]}"
    echo -e "${BLUE}Full log:${NC} $LOG_FILE"
    echo -e "${BLUE}Status report:${NC} $PROJECT_DIR/logs/status_report.txt"
}

# Test notification configuration
test_notifications() {
    log_info "Testing notification configuration..."
    
    ALERTS=("Test critical alert message")
    WARNINGS=("Test warning message")
    SERVICES_OK=("nginx" "grafana")
    SERVICES_FAILED=()
    
    send_alerts
    
    log_success "Notification test completed"
}

# Cleanup function
cleanup() {
    log_info "Performing cleanup..."
    
    # Cleanup temporary files
    rm -f /tmp/email_body.txt
    
    # Log rotation if necessary (>50MB)
    if [ -f "$LOG_FILE" ] && [ $(stat -f%z "$LOG_FILE" 2>/dev/null || stat -c%s "$LOG_FILE" 2>/dev/null || echo 0) -gt 52428800 ]; then
        mv "$LOG_FILE" "${LOG_FILE}.$(date +%Y%m%d_%H%M%S)"
        touch "$LOG_FILE"
        log_info "Log file rotated due to excessive size"
    fi
}

# Signal handling
trap cleanup EXIT
trap 'log_info "Received interrupt signal - shutting down"; exit 0' INT TERM

# Show help
show_help() {
    cat << EOF
Usage: $0 [COMMAND] [OPTIONS]

COMMANDS:
    monitor     Run single monitoring check (default)
    continuous  Start continuous monitoring
    test        Test notification configuration
    help        Show this help message

OPTIONS:
    --check-interval SECONDS      Check interval in continuous mode (default: 60)
    --webhook-url URL            Webhook URL for Discord/Slack notifications
    --email EMAIL                Recipient email for notifications
    --smtp-server SERVER         SMTP server for email notifications
    --cpu-threshold PERCENT      CPU threshold for warnings (default: 80)
    --memory-threshold PERCENT   Memory threshold for warnings (default: 80)
    --disk-threshold PERCENT     Disk threshold for warnings (default: 85)
    --response-time-threshold MS Response time threshold for warnings (default: 5000)
    --log-file PATH              Log file path (default: logs/monitor.log)

EXAMPLES:
    # Single monitoring check
    $0

    # Continuous monitoring
    $0 continuous

    # With Discord notifications
    $0 continuous --webhook-url "https://discord.com/api/webhooks/..."

    # With email notifications
    $0 continuous --email "admin@example.com" --smtp-server "localhost"

    # Test notification configuration
    $0 test --webhook-url "https://discord.com/api/webhooks/..."

    # Custom thresholds
    $0 continuous --cpu-threshold 90 --memory-threshold 85

ENVIRONMENT VARIABLES:
    WEBHOOK_URL                  Webhook URL for notifications
    EMAIL_TO                     Recipient email address
    SMTP_SERVER                  SMTP server hostname
    CHECK_INTERVAL               Check interval in seconds
    CPU_THRESHOLD                CPU usage threshold percentage
    MEMORY_THRESHOLD             Memory usage threshold percentage
    DISK_THRESHOLD               Disk usage threshold percentage
    RESPONSE_TIME_THRESHOLD      HTTP response time threshold in milliseconds
    LOG_FILE                     Log file path

SYSTEMD SERVICE:
To run monitoring as a systemd service:

1. Create service file: /etc/systemd/system/opnsense-monitor.service
2. Add content:
   [Unit]
   Description=OPNsense Reverse Proxy Monitor
   After=docker.service
   Requires=docker.service
   
   [Service]
   Type=simple
   User=root
   WorkingDirectory=$(pwd)
   ExecStart=$(pwd)/scripts/monitor.sh continuous
   Restart=always
   RestartSec=10
   
   [Install]
   WantedBy=multi-user.target

3. Enable and start:
   systemctl enable opnsense-monitor.service
   systemctl start opnsense-monitor.service

MONITORING CHECKS:
    ✓ Docker container status
    ✓ Network connectivity (wrapper, DNS, internet)
    ✓ HTTP endpoint health
    ✓ System resource usage (CPU, memory, disk)
    ✓ Application log errors
    ✓ Docker volume status
    ✓ SSL certificate expiration

EOF
}

# Parse command line arguments
COMMAND="monitor"

while [[ $# -gt 0 ]]; do
    case $1 in
        monitor|continuous|test|help)
            COMMAND=$1
            shift
            ;;
        --check-interval)
            CHECK_INTERVAL="$2"
            shift 2
            ;;
        --webhook-url)
            WEBHOOK_URL="$2"
            shift 2
            ;;
        --email)
            EMAIL_TO="$2"
            shift 2
            ;;
        --smtp-server)
            SMTP_SERVER="$2"
            shift 2
            ;;
        --cpu-threshold)
            CPU_THRESHOLD="$2"
            shift 2
            ;;
        --memory-threshold)
            MEMORY_THRESHOLD="$2"
            shift 2
            ;;
        --disk-threshold)
            DISK_THRESHOLD="$2"
            shift 2
            ;;
        --response-time-threshold)
            RESPONSE_TIME_THRESHOLD="$2"
            shift 2
            ;;
        --log-file)
            LOG_FILE="$2"
            shift 2
            ;;
        --help|-h)
            show_help
            exit 0
            ;;
        *)
            log_error "Unknown parameter: $1"
            echo "Use --help to see available options"
            exit 1
            ;;
    esac
done

# Main function
main() {
    setup_logging
    
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║            OPNsense Reverse Proxy - Monitor                 ║"
    echo "║                                                              ║"
    echo "║  Automated monitoring of services, resources and connectivity   ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    log_info "Starting monitor - Command: $COMMAND"
    log_info "Configuration:"
    log_info "  - Log file: $LOG_FILE"
    log_info "  - Check interval: ${CHECK_INTERVAL}s"
    log_info "  - CPU threshold: ${CPU_THRESHOLD}%"
    log_info "  - Memory threshold: ${MEMORY_THRESHOLD}%"
    log_info "  - Disk threshold: ${DISK_THRESHOLD}%"
    log_info "  - Response time threshold: ${RESPONSE_TIME_THRESHOLD}ms"
    [ -n "$WEBHOOK_URL" ] && log_info "  - Webhook notifications: ✓"
    [ -n "$EMAIL_TO" ] && log_info "  - Email notifications: ✓"
    
    case $COMMAND in
        monitor)
            run_single_check
            ;;
        continuous)
            run_continuous_monitoring
            ;;
        test)
            test_notifications
            ;;
        help)
            show_help
            ;;
        *)
            log_error "Unrecognized command: $COMMAND"
            exit 1
            ;;
    esac
}

# Execute main function
main "$@"