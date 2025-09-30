#!/bin/sh
#
# deepinspector_control.sh - Control Script for DeepInspector DPI Engine
#
# This script provides a command-line interface to manage IP blocking, whitelisting,
# and log operations for the DeepInspector DPI engine on OPNsense. It maintains
# blocked and whitelisted IP lists in JSON format and interacts with the pfctl
# firewall to enforce blocking rules.
#
# Author: Pierpaolo Casati
# Version: 1.0.0
#

# Check if running as root
if [ "$(id -u)" != "0" ]; then
    echo "ERROR: This script must be run as root"
    exit 1
fi

# Environment setup
PATH="/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin:$PATH"
export PATH

BLOCKED_IPS_FILE="/usr/local/etc/deepinspector/blocked_ips.json"
WHITELIST_IPS_FILE="/usr/local/etc/deepinspector/whitelist_ips.json"
LOG_DIR="/var/log/deepinspector"
PFCTL_TABLE="deepinspector_blocked"

# Check required dependencies
if ! command -v /sbin/pfctl >/dev/null 2>&1; then
    echo "ERROR: pfctl is required for firewall operations"
    exit 1
fi

# Ensure directories exist
mkdir -p /usr/local/etc/deepinspector
mkdir -p "$LOG_DIR"

# Validate JSON file format
validate_json() {
    local file="$1"
    if [ -s "$file" ] && ! grep -q '^{.*}$' "$file" 2>/dev/null; then
        echo "ERROR: Invalid JSON format in $file"
        return 1
    fi
    return 0
}

# Initialize JSON files if they don't exist
init_json_files() {
    if [ ! -f "$BLOCKED_IPS_FILE" ]; then
        echo '{"blocked_ips": [], "last_updated": ""}' > "$BLOCKED_IPS_FILE"
        chmod 600 "$BLOCKED_IPS_FILE"
    elif [ ! -r "$BLOCKED_IPS_FILE" ] || [ ! -w "$BLOCKED_IPS_FILE" ]; then
        echo "ERROR: $BLOCKED_IPS_FILE is not readable or writable"
        exit 1
    fi
    if [ ! -f "$WHITELIST_IPS_FILE" ]; then
        echo '{"whitelisted_ips": [], "last_updated": ""}' > "$WHITELIST_IPS_FILE"
        chmod 600 "$WHITELIST_IPS_FILE"
    elif [ ! -r "$WHITELIST_IPS_FILE" ] || [ ! -w "$WHITELIST_IPS_FILE" ]; then
        echo "ERROR: $WHITELIST_IPS_FILE is not readable or writable"
        exit 1
    fi
}

# Function to log actions
log_action() {
    echo "$(date): $1" >> "$LOG_DIR/control.log"
}

# Validate IP address (IPv4 or IPv6, including abbreviated formats)
validate_ip() {
    local ip="$1"
    # Validate IPv4
    if echo "$ip" | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' >/dev/null 2>&1; then
        if [ "$ip" = "0.0.0.0" ] || [ "$ip" = "255.255.255.255" ]; then
            return 1
        fi
        IFS='.' read -r a b c d <<< "$ip"
        if [ "$a" -gt 255 ] || [ "$b" -gt 255 ] || [ "$c" -gt 255 ] || [ "$d" -gt 255 ]; then
            return 1
        fi
        return 0
    # Validate IPv6 (full and abbreviated formats)
    elif echo "$ip" | grep -E '^([0-9a-fA-F]{1,4}:){0,7}([0-9a-fA-F]{1,4})?::([0-9a-fA-F]{1,4}:){0,7}([0-9a-fA-F]{1,4})?$|^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$' >/dev/null 2>&1; then
        return 0
    fi
    return 1
}

# Function to get current timestamp
get_timestamp() {
    date '+%Y-%m-%d %H:%M:%S'
}

# Check if pfctl table exists and create it if missing
check_pfctl_table() {
    if ! /sbin/pfctl -s Tables | grep -q "^$PFCTL_TABLE$"; then
        echo "table <$PFCTL_TABLE> persist" | /sbin/pfctl -f - 2>/dev/null
        log_action "Created pfctl table $PFCTL_TABLE"
    fi
}

# Add an IP to a JSON file, updating the timestamp
add_ip_to_json() {
    local file="$1"
    local ip="$2"
    local key="$3"
    local timestamp=$(get_timestamp)
    local temp_file=$(mktemp)
    
    if ! validate_json "$file"; then
        echo "ERROR: Invalid JSON in $file"
        exit 1
    fi
    
    if command -v jq >/dev/null 2>&1; then
        jq --arg ip "$ip" --arg ts "$timestamp" \
           ".${key} += [\$ip] | .${key} = (.${key} | unique) | .last_updated = \$ts" \
           "$file" > "$temp_file" && mv "$temp_file" "$file"
    else
        if [ -s "$file" ]; then
            current_ips=$(grep -o '"[^"]*"' "$file" | grep -v "last_updated" | tr -d '"' | tr '\n' ',' | sed 's/,$//')
            if [ -n "$current_ips" ]; then
                new_ips="$current_ips,$ip"
            else
                new_ips="$ip"
            fi
            echo "{\"${key}\": [\"${new_ips//,/\",\"}\"], \"last_updated\": \"$timestamp\"}" > "$temp_file"
            mv "$temp_file" "$file"
        else
            echo "{\"${key}\": [\"$ip\"], \"last_updated\": \"$timestamp\"}" > "$file"
        fi
    fi
    
    rm -f "$temp_file"
}

# Remove an IP from a JSON file, updating the timestamp
remove_ip_from_json() {
    local file="$1"
    local ip="$2"
    local key="$3"
    local timestamp=$(get_timestamp)
    local temp_file=$(mktemp)
    
    if ! validate_json "$file"; then
        echo "ERROR: Invalid JSON in $file"
        exit 1
    fi
    
    if command -v jq >/dev/null 2>&1; then
        jq --arg ip "$ip" --arg ts "$timestamp" \
           ".${key} = (.${key} - [\$ip]) | .last_updated = \$ts" \
           "$file" > "$temp_file" && mv "$temp_file" "$file"
    else
        if [ -s "$file" ]; then
            current_ips=$(grep -o '"[^"]*"' "$file" | grep -v "last_updated" | grep -v "^\"$ip\"$" | tr -d '"' | tr '\n' ',' | sed 's/,$//')
            if [ -n "$current_ips" ]; then
                echo "{\"${key}\": [\"${current_ips//,/\",\"}\"], \"last_updated\": \"$timestamp\"}" > "$temp_file"
            else
                echo "{\"${key}\": [], \"last_updated\": \"$timestamp\"}" > "$temp_file"
            fi
            mv "$temp_file" "$file"
        fi
    fi
    
    rm -f "$temp_file"
}

# Check if an IP exists in a JSON file (with cache for performance)
ip_exists_in_json() {
    local file="$1"
    local ip="$2"
    local key="$3"
    local cache_file="/tmp/deepinspector_${key}_cache_$(basename "$file")"
    
    if [ -f "$cache_file" ] && grep -q "^$ip$" "$cache_file" 2>/dev/null; then
        return 0
    fi
    
    if command -v jq >/dev/null 2>&1; then
        jq -r ".${key}[]" "$file" 2>/dev/null | grep -q "^$ip$"
    else
        grep -q "\"$ip\"" "$file" 2>/dev/null
    fi
    
    if [ $? -eq 0 ]; then
        echo "$ip" >> "$cache_file"
        return 0
    fi
    return 1
}

# List IPs from a JSON file
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
        grep -o '"[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}"' "$file" 2>/dev/null | tr -d '"' | sort | uniq || \
        grep -o '"[0-9a-fA-F:]\+"' "$file" 2>/dev/null | tr -d '"' | sort | uniq
    fi
}

# Check if log files are in use
check_logs_in_use() {
    local log_file="$1"
    if command -v lsof >/dev/null 2>&1; then
        lsof "$log_file" >/dev/null 2>&1
        return $?
    fi
    return 0
}

# Initialize JSON files
init_json_files

case "$1" in
    block_ip)
        if [ -z "$2" ]; then
            echo "ERROR: IP address required"
            exit 1
        fi
        
        IP="$2"
        if ! validate_ip "$IP"; then
            echo "ERROR: Invalid IP address format"
            exit 1
        fi
        
        # Add to pfctl table
        check_pfctl_table
        if /sbin/pfctl -t "$PFCTL_TABLE" -T add "$IP" 2>/dev/null; then
            log_action "Added IP $IP to pfctl table"
        else
            log_action "Failed to add IP $IP to pfctl table"
            echo "ERROR: Failed to add IP to pfctl"
            exit 1
        fi
        
        # Add to blocked IPs JSON file
        if ! ip_exists_in_json "$BLOCKED_IPS_FILE" "$IP" "blocked_ips"; then
            add_ip_to_json "$BLOCKED_IPS_FILE" "$IP" "blocked_ips"
        fi
        
        log_action "Blocked IP: $IP"
        echo "OK"
        exit 0
        ;;
        
    unblock_ip)
        if [ -z "$2" ]; then
            echo "ERROR: IP address required"
            exit 1
        fi
        
        IP="$2"
        if ! validate_ip "$IP"; then
            echo "ERROR: Invalid IP address format"
            exit 1
        fi
        
        # Remove from pfctl
        check_pfctl_table
        if /sbin/pfctl -t "$PFCTL_TABLE" -T delete "$IP" 2>/dev/null; then
            log_action "Removed IP $IP from pfctl table"
        else
            log_action "Failed to remove IP $IP from pfctl table (may not exist)"
        fi
        
        # Remove from blocked IPs JSON file
        remove_ip_from_json "$BLOCKED_IPS_FILE" "$IP" "blocked_ips"
        
        log_action "Unblocked IP: $IP"
        echo "OK"
        exit 0
        ;;
        
    whitelist_ip)
        if [ -z "$2" ]; then
            echo "ERROR: IP address required"
            exit 1
        fi
        
        IP="$2"
        if ! validate_ip "$IP"; then
            echo "ERROR: Invalid IP address format"
            exit 1
        fi
        
        # Add to whitelist JSON
        if ! ip_exists_in_json "$WHITELIST_IPS_FILE" "$IP" "whitelisted_ips"; then
            add_ip_to_json "$WHITELIST_IPS_FILE" "$IP" "whitelisted_ips"
        fi
        
        # Remove from blocked list JSON
        remove_ip_from_json "$BLOCKED_IPS_FILE" "$IP" "blocked_ips"
        
        # Remove from pfctl
        check_pfctl_table
        if /sbin/pfctl -t "$PFCTL_TABLE" -T delete "$IP" 2>/dev/null; then
            log_action "Removed IP $IP from pfctl table (whitelist)"
        else
            log_action "Failed to remove IP $IP from pfctl table (may not exist)"
        fi
        
        log_action "Whitelisted IP: $IP"
        echo "OK"
        exit 0
        ;;
        
    clear_logs)
        for logfile in alerts.log threats.log detections.log engine.log stats.json control.log; do
            local log_file="$LOG_DIR/$logfile"
            if [ -f "$log_file" ]; then
                if ! check_logs_in_use "$log_file"; then
                    mv "$log_file" "${log_file}.$(date +%Y%m%d%H%M%S).bak"
                    touch "$log_file"
                    log_action "Archived $log_file"
                    # Limit backups to last 10
                    ls -t "$LOG_DIR/$logfile."*.bak | tail -n +11 | xargs -I {} rm -f {}
                else
                    echo "WARNING: Log file $log_file is in use, skipping"
                    log_action "Skipped clearing $log_file (in use)"
                fi
            fi
        done
        log_action "Logs archived and cleared"
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
                echo "Usage: $0 show_json {blocked|whitelist}"
                exit 1
                ;;
        esac
        exit 0
        ;;
        
    test)
        echo "Testing script..."
        echo "PATH: $PATH"
        echo "pfctl location:"
        which pfctl 2>/dev/null || echo "pfctl not in PATH"
        ls -la /sbin/pfctl 2>/dev/null || echo "/sbin/pfctl not found"
        echo "pfctl table status:"
        if /sbin/pfctl -s Tables | grep -q "^$PFCTL_TABLE$"; then
            echo "  Table $PFCTL_TABLE exists"
        else
            echo "  Table $PFCTL_TABLE does not exist"
        fi
        echo "jq availability:"
        which jq 2>/dev/null || echo "jq not available - using fallback methods"
        echo "JSON files:"
        echo "  Blocked IPs: $BLOCKED_IPS_FILE"
        if [ -f "$BLOCKED_IPS_FILE" ]; then
            if validate_json "$BLOCKED_IPS_FILE"; then
                echo "  Blocked IPs content: $(cat "$BLOCKED_IPS_FILE")"
            else
                echo "  Blocked IPs content: Invalid JSON"
            fi
        fi
        echo "  Whitelist IPs: $WHITELIST_IPS_FILE"
        if [ -f "$WHITELIST_IPS_FILE" ]; then
            if validate_json "$WHITELIST_IPS_FILE"; then
                echo "  Whitelist IPs content: $(cat "$WHITELIST_IPS_FILE")"
            else
                echo "  Whitelist Ips content: Invalid JSON"
            fi
        fi
        echo "Test complete"
        exit 0
        ;;
        
    *)
        echo "Usage: $0 {block_ip|unblock_ip|whitelist_ip|clear_logs|list_blocked|list_whitelist|show_json|test} [IP|type]"
        echo ""
        echo "Commands:"
        echo "  block_ip <IP>       - Block an IP address"
        echo "  unblock_ip <IP>     - Unblock an IP address"
        echo "  whitelist_ip <IP>   - Add IP to whitelist"
        echo "  list_blocked        - List all blocked IPs"
        echo "  list_whitelist      - List all whitelisted IPs"
        echo "  show_json blocked   - Show blocked IPs JSON"
        echo "  show_json whitelist - Show whitelist IPs JSON"
        echo "  clear_logs          - Clear all log files"
        echo "  test                - Test script functionality"
        exit 1
        ;;
esac

exit 0