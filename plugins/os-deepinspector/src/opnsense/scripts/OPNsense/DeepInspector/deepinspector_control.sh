#!/bin/sh

# DeepInspector Control Script - JSON Version
# /usr/local/bin/deepinspector_control.sh
# Manages IP blocking, whitelisting, and logs for the DeepInspector DPI engine.
# Enhanced to integrate with ThreatInfo and ThreatSeverity from detections.log.

PATH="/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin:$PATH"
export PATH

# Configuration paths
BLOCKED_IPS_FILE="/usr/local/etc/deepinspector/blocked_ips.json"
WHITELIST_IPS_FILE="/usr/local/etc/deepinspector/whitelist_ips.json"
LOG_DIR="/var/log/deepinspector"
DETECTIONS_LOG="$LOG_DIR/detections.log"
PFCTL_TABLE="deepinspector_blocked"

# Ensure directories exist with proper permissions
mkdir -p /usr/local/etc/deepinspector
chmod 755 /usr/local/etc/deepinspector
mkdir -p "$LOG_DIR"
chmod 755 "$LOG_DIR"

# Check for root privileges
check_root() {
    if [ "$(id -u)" != "0" ]; then
        echo "ERROR: This script must be run as root" >&2
        exit 1
    fi
}

# Initialize JSON files if they don't exist
init_json_files() {
    if [ ! -f "$BLOCKED_IPS_FILE" ]; then
        echo '{"blocked_ips": [], "last_updated": ""}' > "$BLOCKED_IPS_FILE"
        chmod 644 "$BLOCKED_IPS_FILE"
    fi
    if [ ! -f "$WHITELIST_IPS_FILE" ]; then
        echo '{"whitelisted_ips": [], "last_updated": ""}' > "$WHITELIST_IPS_FILE"
        chmod 644 "$WHITELIST_IPS_FILE"
    fi
    # Ensure control.log exists
    if [ ! -f "$LOG_DIR/control.log" ]; then
        touch "$LOG_DIR/control.log"
        chmod 644 "$LOG_DIR/control.log"
    fi
}

# Function to log actions
log_action() {
    echo "$(date '+%Y-%m-%d %H:%M:%S'): $1" >> "$LOG_DIR/control.log"
}

# Function to validate IP address (improved for IPv4 octet range)
validate_ip() {
    local ip="$1"
    # Check IPv4 format and valid octet range (0-255)
    echo "$ip" | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' >/dev/null 2>&1 || return 1
    # Split IP into octets and validate each is between 0 and 255
    IFS='.' read -r oct1 oct2 oct3 oct4 <<EOF
$ip
EOF
    for oct in "$oct1" "$oct2" "$oct3" "$oct4"; do
        if [ "$oct" -gt 255 ] || [ "$oct" -lt 0 ]; then
            return 1
        fi
    done
    return 0
}

# Function to get current timestamp
get_timestamp() {
    date '+%Y-%m-%d %H:%M:%S'
}

# Function to add IP to JSON file
add_ip_to_json() {
    local file="$1"
    local ip="$2"
    local key="$3"
    local timestamp=$(get_timestamp)
    local temp_file=$(mktemp)
    
    if command -v jq >/dev/null 2>&1; then
        jq --arg ip "$ip" --arg ts "$timestamp" \
           ".${key} |= (. + [\$ip] | unique) | .last_updated = \$ts" \
           "$file" > "$temp_file" && mv "$temp_file" "$file" || {
            echo "ERROR: Failed to update $file with jq" >&2
            rm -f "$temp_file"
            return 1
        }
    else
        # Safer fallback: read current IPs, append new one, and rewrite JSON
        local current_ips
        current_ips=$(grep -o '"[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}"' "$file" | tr -d '"' | sort | uniq)
        local new_ips="$current_ips"
        if ! echo "$current_ips" | grep -q "^$ip$"; then
            new_ips="$current_ips\n$ip"
        fi
        local ip_array
        ip_array=$(echo "$new_ips" | sed 's/^/"/; s/$/"/' | tr '\n' ',' | sed 's/,$//')
        echo "{\"${key}\": [${ip_array}], \"last_updated\": \"$timestamp\"}" > "$temp_file" && mv "$temp_file" "$file" || {
            echo "ERROR: Failed to update $file with fallback method" >&2
            rm -f "$temp_file"
            return 1
        }
    fi
    rm -f "$temp_file"
    return 0
}

# Function to remove IP from JSON file
remove_ip_from_json() {
    local file="$1"
    local ip="$2"
    local key="$3"
    local timestamp=$(get_timestamp)
    local temp_file=$(mktemp)
    
    if command -v jq >/dev/null 2>&1; then
        jq --arg ip "$ip" --arg ts "$timestamp" \
           ".${key} |= (. - [\$ip]) | .last_updated = \$ts" \
           "$file" > "$temp_file" && mv "$temp_file" "$file" || {
            echo "ERROR: Failed to update $file with jq" >&2
            rm -f "$temp_file"
            return 1
        }
    else
        # Safer fallback: read current IPs, remove specified IP, and rewrite JSON
        local current_ips
        current_ips=$(grep -o '"[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}"' "$file" | tr -d '"' | grep -v "^$ip$" | sort | uniq)
        local ip_array
        ip_array=$(echo "$current_ips" | sed 's/^/"/; s/$/"/' | tr '\n' ',' | sed 's/,$//')
        echo "{\"${key}\": [${ip_array}], \"last_updated\": \"$timestamp\"}" > "$temp_file" && mv "$temp_file" "$file" || {
            echo "ERROR: Failed to update $file with fallback method" >&2
            rm -f "$temp_file"
            return 1
        }
    fi
    rm -f "$temp_file"
    return 0
}

# Function to check if IP exists in JSON file
ip_exists_in_json() {
    local file="$1"
    local ip="$2"
    local key="$3"
    
    if command -v jq >/dev/null 2>&1; then
        jq -r ".${key}[] | select(. == \"$ip\")" "$file" 2>/dev/null | grep -q "^$ip$"
    else
        grep -q "\"$ip\"" "$file" 2>/dev/null
    fi
}

# Function to list IPs from JSON file
list_ips_from_json() {
    local file="$1"
    local key="$2"
    
    if [ ! -f "$file" ]; then
        echo ""
        return
    fi
    
    if command -v jq >/dev/null 2>&1; then
        jq -r ".${key}[]?" "$file" 2>/dev/null | sort
    else
        grep -o '"[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}"' "$file" 2>/dev/null | tr -d '"' | sort | uniq
    fi
}

# Function to list recent threats from detections.log, filtered by severity
list_threats() {
    local severity="$1"
    local limit="$2"
    local count=0
    
    if [ ! -f "$DETECTIONS_LOG" ]; then
        echo "No detections log found"
        return
    fi
    
    if command -v jq >/dev/null 2>&1; then
        # Use jq to parse detections.log and filter by severity
        while IFS= read -r line && [ "$count" -lt "$limit" ]; do
            if echo "$line" | jq -e ".severity == \"$severity\"" >/dev/null 2>&1; then
                echo "$line" | jq -r '[.timestamp, .source_ip, .threat_type, .severity, .description] | @tsv'
                count=$((count + 1))
            fi
        done < "$DETECTIONS_LOG" | sort -r
    else
        # Fallback: grep-based parsing
        grep "\"severity\": \"$severity\"" "$DETECTIONS_LOG" 2>/dev/null | tail -n "$limit" | while IFS= read -r line; do
            timestamp=$(echo "$line" | grep -o '"timestamp": "[^"]*"' | cut -d'"' -f4)
            source_ip=$(echo "$line" | grep -o '"source_ip": "[^"]*"' | cut -d'"' -f4)
            threat_type=$(echo "$line" | grep -o '"threat_type": "[^"]*"' | cut -d'"' -f4)
            description=$(echo "$line" | grep -o '"description": "[^"]*"' | cut -d'"' -f4)
            echo "$timestamp\t$source_ip\t$threat_type\t$severity\t$description"
            count=$((count + 1))
        done | sort -r
    fi
}

# Initialize JSON files and check root privileges
check_root
init_json_files

case "$1" in
    block_ip)
        if [ -z "$2" ]; then
            echo "ERROR: IP address required" >&2
            exit 1
        fi
        
        IP="$2"
        if ! validate_ip "$IP"; then
            echo "ERROR: Invalid IP address format" >&2
            exit 1
        fi
        
        # Add to pfctl table
        if command -v /sbin/pfctl >/dev/null 2>&1; then
            /sbin/pfctl -t "$PFCTL_TABLE" -T add "$IP" 2>/dev/null || {
                echo "table <$PFCTL_TABLE> persist" | /sbin/pfctl -f - 2>/dev/null
                /sbin/pfctl -t "$PFCTL_TABLE" -T add "$IP" 2>/dev/null || {
                    echo "ERROR: Failed to add IP $IP to pfctl table" >&2
                    log_action "Failed to add IP $IP to pfctl table"
                    exit 1
                }
            }
            log_action "Added IP $IP to pfctl table"
        else
            echo "WARNING: pfctl not found, only logging block" >&2
            log_action "pfctl not found, only logging block"
        fi
        
        # Add to blocked IPs JSON
        if ! ip_exists_in_json "$BLOCKED_IPS_FILE" "$IP" "blocked_ips"; then
            add_ip_to_json "$BLOCKED_IPS_FILE" "$IP" "blocked_ips" || {
                echo "ERROR: Failed to add IP $IP to blocked IPs JSON" >&2
                exit 1
            }
        fi
        
        log_action "Blocked IP: $IP"
        echo "OK"
        exit 0
        ;;
        
    unblock_ip)
        if [ -z "$2" ]; then
            echo "ERROR: IP address required" >&2
            exit 1
        fi
        
        IP="$2"
        if ! validate_ip "$IP"; then
            echo "ERROR: Invalid IP address format" >&2
            exit 1
        fi
        
        # Remove from pfctl
        if command -v /sbin/pfctl >/dev/null 2>&1; then
            /sbin/pfctl -t "$PFCTL_TABLE" -T delete "$IP" 2>/dev/null || {
                echo "WARNING: Failed to remove IP $IP from pfctl table" >&2
                log_action "Failed to remove IP $IP from pfctl table"
            }
            log_action "Removed IP $IP from pfctl table"
        fi
        
        # Remove from blocked IPs JSON
        remove_ip_from_json "$BLOCKED_IPS_FILE" "$IP" "blocked_ips" || {
            echo "ERROR: Failed to remove IP $IP from blocked IPs JSON" >&2
            exit 1
        }
        
        log_action "Unblocked IP: $IP"
        echo "OK"
        exit 0
        ;;
        
    whitelist_ip)
        if [ -z "$2" ]; then
            echo "ERROR: IP address required" >&2
            exit 1
        fi
        
        IP="$2"
        if ! validate_ip "$IP"; then
            echo "ERROR: Invalid IP address format" >&2
            exit 1
        fi
        
        # Add to whitelist JSON
        if ! ip_exists_in_json "$WHITELIST_IPS_FILE" "$IP" "whitelisted_ips"; then
            add_ip_to_json "$WHITELIST_IPS_FILE" "$IP" "whitelisted_ips" || {
                echo "ERROR: Failed to add IP $IP to whitelist JSON" >&2
                exit 1
            }
        fi
        
        # Remove from blocked IPs JSON and pfctl
        if ip_exists_in_json "$BLOCKED_IPS_FILE" "$IP" "blocked_ips"; then
            remove_ip_from_json "$BLOCKED_IPS_FILE" "$IP" "blocked_ips" || {
                echo "ERROR: Failed to remove IP $IP from blocked IPs JSON" >&2
                exit 1
            }
            if command -v /sbin/pfctl >/dev/null 2>&1; then
                /sbin/pfctl -t "$PFCTL_TABLE" -T delete "$IP" 2>/dev/null || {
                    echo "WARNING: Failed to remove IP $IP from pfctl table" >&2
                    log_action "Failed to remove IP $IP from pfctl table"
                }
            fi
        fi
        
        log_action "Whitelisted IP: $IP"
        echo "OK"
        exit 0
        ;;
        
    clear_logs)
        for logfile in alerts.log threats.log detections.log engine.log stats.json control.log; do
            if [ -f "$LOG_DIR/$logfile" ]; then
                : > "$LOG_DIR/$logfile"
                log_action "Cleared log file: $logfile"
            fi
        done
        echo "OK"
        exit 0
        ;;
        
    list_blocked)
        list_ips_from_json "$BLOCKED_IPS_FILE" "blocked_ips"
        exit 0
        ;;
        
    list_whitelist)
        list_ips_from_json "$WHITELIST_IPS_FILE" "whitelisted_ips"
        exit 0
        ;;
        
    show_json)
        case "$2" in
            blocked)
                if [ -f "$BLOCKED_IPS_FILE" ]; then
                    cat "$BLOCKED_IPS_FILE"
                else
                    echo '{"blocked_ips": [], "last_updated": ""}'
                fi
                ;;
            whitelist)
                if [ -f "$WHITELIST_IPS_FILE" ]; then
                    cat "$WHITELIST_IPS_FILE"
                else
                    echo '{"whitelisted_ips": [], "last_updated": ""}'
                fi
                ;;
            *)
                echo "Usage: $0 show_json {blocked|whitelist}" >&2
                exit 1
                ;;
        esac
        exit 0
        ;;
        
    list_threats)
        severity="$2"
        limit="${3:-10}"  # Default to 10 threats if limit not specified
        case "$severity" in
            low|medium|high|critical)
                list_threats "$severity" "$limit"
                log_action "Listed recent threats with severity $severity (limit: $limit)"
                ;;
            *)
                echo "Usage: $0 list_threats {low|medium|high|critical} [limit]" >&2
                exit 1
                ;;
        esac
        exit 0
        ;;
        
    test)
        echo "Testing DeepInspector control script..."
        echo "PATH: $PATH"
        echo "pfctl location:"
        if command -v pfctl >/dev/null 2>&1; then
            which pfctl
        else
            echo "pfctl not in PATH"
        fi
        ls -la /sbin/pfctl 2>/dev/null || echo "/sbin/pfctl not found"
        echo "jq availability:"
        if command -v jq >/dev/null 2>&1; then
            which jq
        else
            echo "jq not available - using fallback methods"
        fi
        echo "JSON files:"
        echo "  Blocked IPs: $BLOCKED_IPS_FILE"
        [ -f "$BLOCKED_IPS_FILE" ] && echo "  Blocked IPs content: $(cat "$BLOCKED_IPS_FILE")" || echo "  Blocked IPs file not found"
        echo "  Whitelist IPs: $WHITELIST_IPS_FILE"
        [ -f "$WHITELIST_IPS_FILE" ] && echo "  Whitelist IPs content: $(cat "$WHITELIST_IPS_FILE")" || echo "  Whitelist IPs file not found"
        echo "Detections log:"
        [ -f "$DETECTIONS_LOG" ] && echo "  Last 5 detections: $(tail -n 5 "$DETECTIONS_LOG")" || echo "  Detections log not found"
        echo "Engine running:"
        if [ -f "/var/run/deepinspector.pid" ]; then
            pid=$(cat "/var/run/deepinspector.pid")
            if ps -p "$pid" >/dev/null 2>&1; then
                echo "  DeepInspector engine running (PID: $pid)"
            else
                echo "  DeepInspector engine not running (stale PID file)"
            fi
        else
            echo "  DeepInspector engine not running (no PID file)"
        fi
        echo "Test complete"
        log_action "Ran test command"
        exit 0
        ;;
        
    *)
        echo "Usage: $0 {block_ip|unblock_ip|whitelist_ip|clear_logs|list_blocked|list_whitelist|show_json|list_threats|test} [args]" >&2
        echo "" >&2
        echo "Commands:" >&2
        echo "  block_ip <IP>         - Block an IP address" >&2
        echo "  unblock_ip <IP>       - Unblock an IP address" >&2
        echo "  whitelist_ip <IP>     - Add IP to whitelist" >&2
        echo "  list_blocked          - List all blocked IPs" >&2
        echo "  list_whitelist        - List all whitelisted IPs" >&2
        echo "  show_json blocked     - Show blocked IPs JSON" >&2
        echo "  show_json whitelist   - Show whitelist IPs JSON" >&2
        echo "  clear_logs            - Clear all log files" >&2
        echo "  list_threats {low|medium|high|critical} [limit] - List recent threats by severity" >&2
        echo "  test                  - Test script functionality" >&2
        exit 1
        ;;
esac

exit 0