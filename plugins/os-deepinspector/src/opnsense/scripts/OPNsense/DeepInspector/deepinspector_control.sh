#!/bin/sh

# DeepInspector Control Script - Simple Version
# /usr/local/bin/deepinspector_control.sh

PATH="/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin:$PATH"
export PATH

BLOCKED_IPS_FILE="/usr/local/etc/deepinspector/blocked_ips.txt"
WHITELIST_IPS_FILE="/usr/local/etc/deepinspector/whitelist_ips.txt"
LOG_DIR="/var/log/deepinspector"
PFCTL_TABLE="deepinspector_blocked"

# Ensure directories exist
mkdir -p /usr/local/etc/deepinspector
mkdir -p $LOG_DIR

# Function to log actions
log_action() {
    echo "$(date): $1" >> $LOG_DIR/control.log
}

# Function to validate IP address
validate_ip() {
    echo "$1" | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3} > /dev/null
    return $?
}

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
        
        # Add to blocked IPs file (simple text format)
        if ! grep -q "^$IP$" "$BLOCKED_IPS_FILE" 2>/dev/null; then
            echo "$IP" >> "$BLOCKED_IPS_FILE"
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
        
        # Remove from blocked IPs file
        if [ -f "$BLOCKED_IPS_FILE" ]; then
            grep -v "^$IP$" "$BLOCKED_IPS_FILE" > "$BLOCKED_IPS_FILE.tmp" 2>/dev/null || touch "$BLOCKED_IPS_FILE.tmp"
            mv "$BLOCKED_IPS_FILE.tmp" "$BLOCKED_IPS_FILE" 2>/dev/null
        fi
        
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
        
        # Add to whitelist
        if ! grep -q "^$IP$" "$WHITELIST_IPS_FILE" 2>/dev/null; then
            echo "$IP" >> "$WHITELIST_IPS_FILE"
        fi
        
        # Remove from blocked list
        if [ -f "$BLOCKED_IPS_FILE" ]; then
            grep -v "^$IP$" "$BLOCKED_IPS_FILE" > "$BLOCKED_IPS_FILE.tmp" 2>/dev/null || touch "$BLOCKED_IPS_FILE.tmp"
            mv "$BLOCKED_IPS_FILE.tmp" "$BLOCKED_IPS_FILE" 2>/dev/null
        fi
        
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
        if [ -f "$BLOCKED_IPS_FILE" ]; then
            cat "$BLOCKED_IPS_FILE"
        else
            echo ""
        fi
        exit 0
        ;;
        
    list_whitelist)
        if [ -f "$WHITELIST_IPS_FILE" ]; then
            cat "$WHITELIST_IPS_FILE"
        else
            echo ""
        fi
        exit 0
        ;;
        
    test)
        echo "Testing script..."
        echo "PATH: $PATH"
        echo "pfctl location:"
        which pfctl 2>/dev/null || echo "pfctl not in PATH"
        ls -la /sbin/pfctl 2>/dev/null || echo "/sbin/pfctl not found"
        echo "Test complete"
        exit 0
        ;;
        
    *)
        echo "Usage: $0 {block_ip|unblock_ip|whitelist_ip|clear_logs|list_blocked|list_whitelist|test} [IP]"
        exit 1
        ;;
esac

exit 0