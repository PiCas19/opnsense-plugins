#!/bin/sh

# DeepInspector Control Script - JSON Version
# /usr/local/bin/deepinspector_control.sh

PATH="/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin:$PATH"
export PATH

BLOCKED_IPS_FILE="/usr/local/etc/deepinspector/blocked_ips.json"
WHITELIST_IPS_FILE="/usr/local/etc/deepinspector/whitelist_ips.json"
LOG_DIR="/var/log/deepinspector"
PFCTL_TABLE="deepinspector_blocked"

# Ensure directories exist
mkdir -p /usr/local/etc/deepinspector
mkdir -p $LOG_DIR

# Initialize JSON files if they don't exist
init_json_files() {
    if [ ! -f "$BLOCKED_IPS_FILE" ]; then
        echo '{"blocked_ips": [], "last_updated": ""}' > "$BLOCKED_IPS_FILE"
    fi
    if [ ! -f "$WHITELIST_IPS_FILE" ]; then
        echo '{"whitelisted_ips": [], "last_updated": ""}' > "$WHITELIST_IPS_FILE"
    fi
}

# Function to log actions
log_action() {
    echo "$(date): $1" >> $LOG_DIR/control.log
}

# Function to validate IP address
validate_ip() {
    echo "$1" | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' >/dev/null 2>&1
    return $?
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
    
    # Create temp file for jq processing
    local temp_file=$(mktemp)
    
    # Use jq if available, otherwise use simple sed approach
    if command -v jq >/dev/null 2>&1; then
        jq --arg ip "$ip" --arg ts "$timestamp" \
           ".${key} += [\$ip] | .${key} = (.${key} | unique) | .last_updated = \$ts" \
           "$file" > "$temp_file" && mv "$temp_file" "$file"
    else
        # Fallback: manual JSON manipulation
        sed -i.bak "s/\"${key}\": \[\([^]]*\)\]/\"${key}\": [\1\"$ip\",]/g; s/,]/]/g; s/\[\"/[/g; s/\",\]/]/g" "$file"
        sed -i.bak "s/\"last_updated\": \"[^\"]*\"/\"last_updated\": \"$timestamp\"/" "$file"
        rm -f "${file}.bak"
    fi
    
    rm -f "$temp_file"
}

# Function to remove IP from JSON file
remove_ip_from_json() {
    local file="$1"
    local ip="$2"
    local key="$3"
    local timestamp=$(get_timestamp)
    
    # Create temp file for jq processing
    local temp_file=$(mktemp)
    
    # Use jq if available, otherwise use simple sed approach
    if command -v jq >/dev/null 2>&1; then
        jq --arg ip "$ip" --arg ts "$timestamp" \
           ".${key} = (.${key} - [\$ip]) | .last_updated = \$ts" \
           "$file" > "$temp_file" && mv "$temp_file" "$file"
    else
        # Fallback: manual JSON manipulation (basic)
        sed -i.bak "s/\"$ip\",//g; s/,\"$ip\"//g; s/\"$ip\"//g" "$file"
        sed -i.bak "s/\"last_updated\": \"[^\"]*\"/\"last_updated\": \"$timestamp\"/" "$file"
        rm -f "${file}.bak"
    fi
    
    rm -f "$temp_file"
}

# Function to check if IP exists in JSON file
ip_exists_in_json() {
    local file="$1"
    local ip="$2"
    local key="$3"
    
    if command -v jq >/dev/null 2>&1; then
        jq -r ".${key}[]" "$file" 2>/dev/null | grep -q "^$ip$"
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
        # Fallback: extract IPs manually
        grep -o '"[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}"' "$file" 2>/dev/null | tr -d '"' | sort | uniq
    fi
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
        
        # Try pfctl with full path
        if command -v /sbin/pfctl >/dev/null 2>&1; then
            /sbin/pfctl -t "$PFCTL_TABLE" -T add "$IP" 2>/dev/null || {
                echo "table <$PFCTL_TABLE> persist" | /sbin/pfctl -f - 2>/dev/null
                /sbin/pfctl -t "$PFCTL_TABLE" -T add "$IP" 2>/dev/null
            }
            log_action "Added IP $IP to pfctl table"
        else
            log_action "pfctl not found, only logging block"
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
        if command -v /sbin/pfctl >/dev/null 2>&1; then
            /sbin/pfctl -t "$PFCTL_TABLE" -T delete "$IP" 2>/dev/null
            log_action "Removed IP $IP from pfctl table"
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
        if command -v /sbin/pfctl >/dev/null 2>&1; then
            /sbin/pfctl -t "$PFCTL_TABLE" -T delete "$IP" 2>/dev/null
        fi
        
        log_action "Whitelisted IP: $IP"
        echo "OK"
        exit 0
        ;;
        
    clear_logs)
        for logfile in alerts.log threats.log detections.log engine.log stats.json control.log; do
            if [ -f "$LOG_DIR/$logfile" ]; then
                > "$LOG_DIR/$logfile"
            fi
        done
        log_action "Logs cleared"
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
        echo "jq availability:"
        which jq 2>/dev/null || echo "jq not available - using fallback methods"
        echo "JSON files:"
        echo "  Blocked IPs: $BLOCKED_IPS_FILE"
        echo "  Whitelist IPs: $WHITELIST_IPS_FILE"
        if [ -f "$BLOCKED_IPS_FILE" ]; then
            echo "  Blocked IPs content: $(cat "$BLOCKED_IPS_FILE")"
        fi
        if [ -f "$WHITELIST_IPS_FILE" ]; then
            echo "  Whitelist IPs content: $(cat "$WHITELIST_IPS_FILE")"
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