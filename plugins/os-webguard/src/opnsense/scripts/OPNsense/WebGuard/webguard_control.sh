#!/bin/sh

# WebGuard Control Script - Database Version
# /usr/local/opnsense/scripts/OPNsense/WebGuard/webguard_control.sh

PATH="/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin:$PATH"
export PATH

PYTHON_BIN="/usr/local/bin/python3.11"
SCRIPTS_DIR="/usr/local/opnsense/scripts/OPNsense/WebGuard"
LOG_DIR="/var/log/webguard"

# Ensure directories exist
mkdir -p $LOG_DIR

# Function to log actions
log_action() {
    echo "$(date): $1" >> $LOG_DIR/control.log
}

# Function to validate IP address
validate_ip() {
    echo "$1" | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' >/dev/null 2>&1
    return $?
}

case "$1" in
    block_ip)
        if [ -z "$2" ]; then
            echo "ERROR: IP address required"
            exit 1
        fi
        
        IP="$2"
        DURATION="${3:-3600}"
        REASON="${4:-Manual block}"
        BLOCK_TYPE="${5:-manual}"
        
        if ! validate_ip "$IP"; then
            echo "ERROR: Invalid IP address format"
            exit 1
        fi
        
        # Use the Python script
        result=$($PYTHON_BIN "$SCRIPTS_DIR/manage_blocking.py" block "$IP" "$DURATION" "$REASON" "$BLOCK_TYPE" 2>&1)
        if [ $? -eq 0 ]; then
            log_action "Blocked IP: $IP (duration: $DURATION, reason: $REASON)"
            echo "OK: $IP blocked"
        else
            log_action "Failed to block IP: $IP - $result"
            echo "ERROR: $result"
            exit 1
        fi
        ;;
        
    unblock_ip)
        if [ -z "$2" ]; then
            echo "ERROR: IP address required"
            exit 1
        fi
        
        IP="$2"
        REASON="${3:-Manual unblock}"
        
        if ! validate_ip "$IP"; then
            echo "ERROR: Invalid IP address format"
            exit 1
        fi
        
        # Use the Python script
        result=$($PYTHON_BIN "$SCRIPTS_DIR/manage_blocking.py" unblock "$IP" "$REASON" 2>&1)
        if [ $? -eq 0 ]; then
            log_action "Unblocked IP: $IP (reason: $REASON)"
            echo "OK: $IP unblocked"
        else
            log_action "Failed to unblock IP: $IP - $result"
            echo "ERROR: $result"
            exit 1
        fi
        ;;
        
    whitelist_ip)
        if [ -z "$2" ]; then
            echo "ERROR: IP address required"
            exit 1
        fi
        
        IP="$2"
        DESCRIPTION="${3:-Manual whitelist}"
        PERMANENT="${4:-1}"
        EXPIRY="${5:-}"
        
        if ! validate_ip "$IP"; then
            echo "ERROR: Invalid IP address format"
            exit 1
        fi
        
        # Use the Python script
        result=$($PYTHON_BIN "$SCRIPTS_DIR/manage_whitelist.py" add "$IP" "$DESCRIPTION" "$PERMANENT" "$EXPIRY" 2>&1)
        if [ $? -eq 0 ]; then
            log_action "Whitelisted IP: $IP (description: $DESCRIPTION)"
            echo "OK: $IP whitelisted"
        else
            log_action "Failed to whitelist IP: $IP - $result"
            echo "ERROR: $result"
            exit 1
        fi
        ;;
        
    remove_whitelist)
        if [ -z "$2" ]; then
            echo "ERROR: IP address required"
            exit 1
        fi
        
        IP="$2"
        REASON="${3:-Manual removal}"
        
        if ! validate_ip "$IP"; then
            echo "ERROR: Invalid IP address format"
            exit 1
        fi
        
        # Use the Python script
        result=$($PYTHON_BIN "$SCRIPTS_DIR/manage_whitelist.py" remove "$IP" "$REASON" 2>&1)
        if [ $? -eq 0 ]; then
            log_action "Removed from whitelist: $IP (reason: $REASON)"
            echo "OK: $IP removed from whitelist"
        else
            log_action "Failed to remove from whitelist: $IP - $result"
            echo "ERROR: $result"
            exit 1
        fi
        ;;
        
    list_blocked)
        PAGE="${2:-1}"
        LIMIT="${3:-50}"
        
        # Use the Python script and extract just the IPs for simple output
        result=$($PYTHON_BIN "$SCRIPTS_DIR/manage_blocking.py" list "$PAGE" "$LIMIT" 2>&1)
        if [ $? -eq 0 ]; then
            # Extract IP addresses from JSON output for simple listing
            echo "$result" | grep -o '"ip_address": "[^"]*"' | cut -d'"' -f4 | sort
        else
            echo "ERROR: Failed to list blocked IPs"
            exit 1
        fi
        ;;
        
    list_whitelist)
        PAGE="${2:-1}"
        LIMIT="${3:-50}"
        
        # Use the Python script and extract just the IPs for simple output
        result=$($PYTHON_BIN "$SCRIPTS_DIR/manage_whitelist.py" list "$PAGE" "$LIMIT" 2>&1)
        if [ $? -eq 0 ]; then
            # Extract IP addresses from JSON output for simple listing
            echo "$result" | grep -o '"ip_address": "[^"]*"' | cut -d'"' -f4 | sort
        else
            echo "ERROR: Failed to list whitelist"
            exit 1
        fi
        ;;
        
    show_json)
        case "$2" in
            blocked)
                PAGE="${3:-1}"
                LIMIT="${4:-50}"
                $PYTHON_BIN "$SCRIPTS_DIR/manage_blocking.py" list "$PAGE" "$LIMIT"
                ;;
            whitelist)
                PAGE="${3:-1}"
                LIMIT="${4:-50}"
                $PYTHON_BIN "$SCRIPTS_DIR/manage_whitelist.py" list "$PAGE" "$LIMIT"
                ;;
            threats)
                # If you have a get_threats.py script
                if [ -f "$SCRIPTS_DIR/get_threats.py" ]; then
                    $PYTHON_BIN "$SCRIPTS_DIR/get_threats.py" "${3:-}"
                else
                    echo '{"error": "Threats module not available"}'
                fi
                ;;
            *)
                echo "Usage: $0 show_json {blocked|whitelist|threats} [page] [limit]"
                exit 1
                ;;
        esac
        ;;
        
    check_whitelist)
        if [ -z "$2" ]; then
            echo "ERROR: IP address required"
            exit 1
        fi
        
        IP="$2"
        if ! validate_ip "$IP"; then
            echo "ERROR: Invalid IP address format"
            exit 1
        fi
        
        # Use the Python script
        result=$($PYTHON_BIN "$SCRIPTS_DIR/manage_whitelist.py" check "$IP" 2>&1)
        if [ $? -eq 0 ]; then
            echo "$result"
        else
            echo "ERROR: Failed to check whitelist"
            exit 1
        fi
        ;;
        
    clear_expired)
        # Clear expired blocks
        result_blocks=$($PYTHON_BIN "$SCRIPTS_DIR/manage_blocking.py" clear_expired 2>&1)
        blocks_status=$?
        
        # Clear expired whitelist entries
        result_whitelist=$($PYTHON_BIN "$SCRIPTS_DIR/manage_whitelist.py" cleanup 2>&1)
        whitelist_status=$?
        
        if [ $blocks_status -eq 0 ] && [ $whitelist_status -eq 0 ]; then
            log_action "Cleared expired entries"
            echo "OK: Cleared expired entries"
        else
            log_action "Failed to clear expired entries: blocks=$result_blocks, whitelist=$result_whitelist"
            echo "ERROR: Failed to clear some expired entries"
            exit 1
        fi
        ;;
        
    bulk_block)
        if [ -z "$2" ]; then
            echo "ERROR: IP list required"
            exit 1
        fi
        
        IP_LIST="$2"
        DURATION="${3:-3600}"
        REASON="${4:-Bulk block}"
        BLOCK_TYPE="${5:-manual}"
        
        # Use the Python script
        result=$($PYTHON_BIN "$SCRIPTS_DIR/manage_blocking.py" bulk_block "$IP_LIST" "$DURATION" "$REASON" "$BLOCK_TYPE" 2>&1)
        if [ $? -eq 0 ]; then
            log_action "Bulk blocked IPs: $result"
            echo "$result"
        else
            log_action "Failed to bulk block IPs: $result"
            echo "ERROR: $result"
            exit 1
        fi
        ;;
        
    clear_logs)
        for logfile in alerts.log threats.log detections.log engine.log stats.json control.log; do
            if [ -f "$LOG_DIR/$logfile" ]; then
                > "$LOG_DIR/$logfile"
            fi
        done
        log_action "Logs cleared"
        echo "OK: Logs cleared"
        ;;
        
    export_blocked)
        FORMAT="${2:-json}"
        INCLUDE_EXPIRED="${3:-false}"
        
        result=$($PYTHON_BIN "$SCRIPTS_DIR/manage_blocking.py" export "$FORMAT" "$INCLUDE_EXPIRED" 2>&1)
        if [ $? -eq 0 ]; then
            echo "$result"
        else
            echo "ERROR: Failed to export blocked IPs"
            exit 1
        fi
        ;;
        
    export_whitelist)
        FORMAT="${2:-json}"
        
        result=$($PYTHON_BIN "$SCRIPTS_DIR/manage_whitelist.py" export "$FORMAT" 2>&1)
        if [ $? -eq 0 ]; then
            echo "$result"
        else
            echo "ERROR: Failed to export whitelist"
            exit 1
        fi
        ;;
        
    mark_false_positive)
        if [ -z "$2" ]; then
            echo "ERROR: Threat ID required"
            exit 1
        fi
        
        THREAT_ID="$2"
        REASON="${3:-Manual false positive}"
        
        # Use the Python script
        result=$($PYTHON_BIN "$SCRIPTS_DIR/manage_threats.py" false_positive "$THREAT_ID" "$REASON" 2>&1)
        if [ $? -eq 0 ]; then
            log_action "Marked threat $THREAT_ID as false positive: $REASON"
            echo "OK: Threat $THREAT_ID marked as false positive"
        else
            log_action "Failed to mark false positive: $result"
            echo "ERROR: $result"
            exit 1
        fi
        ;;

    whitelist_from_threat)
        if [ -z "$2" ]; then
            echo "ERROR: Threat ID required"
            exit 1
        fi
        
        THREAT_ID="$2"
        DESCRIPTION="${3:-Added from threat}"
        PERMANENT="${4:-1}"
        
        result=$($PYTHON_BIN "$SCRIPTS_DIR/manage_threats.py" whitelist_ip "$THREAT_ID" "$DESCRIPTION" "$PERMANENT" 2>&1)
        if [ $? -eq 0 ]; then
            log_action "Whitelisted IP from threat $THREAT_ID"
            echo "$result"
        else
            log_action "Failed to whitelist from threat: $result"
            echo "ERROR: $result"
            exit 1
        fi
        ;;

    block_from_threat)
        if [ -z "$2" ]; then
            echo "ERROR: Threat ID required"
            exit 1
        fi
        
        THREAT_ID="$2"
        DURATION="${3:-3600}"
        REASON="${4:-Blocked from threat}"
        
        result=$($PYTHON_BIN "$SCRIPTS_DIR/manage_threats.py" block_ip "$THREAT_ID" "$DURATION" "$REASON" 2>&1)
        if [ $? -eq 0 ]; then
            log_action "Blocked IP from threat $THREAT_ID"
            echo "$result"
        else
            log_action "Failed to block from threat: $result"
            echo "ERROR: $result"
            exit 1
        fi
        ;;

    create_rule_from_threat)
        if [ -z "$2" ] || [ -z "$3" ]; then
            echo "ERROR: Threat ID and rule name required"
            exit 1
        fi
        
        THREAT_ID="$2"
        RULE_NAME="$3"
        RULE_TYPE="${4:-custom}"
        ENABLED="${5:-1}"
        
        result=$($PYTHON_BIN "$SCRIPTS_DIR/manage_threats.py" create_rule "$THREAT_ID" "$RULE_NAME" "$RULE_TYPE" "$ENABLED" 2>&1)
        if [ $? -eq 0 ]; then
            log_action "Created rule from threat $THREAT_ID"
            echo "$result"
        else
            log_action "Failed to create rule from threat: $result"
            echo "ERROR: $result"
            exit 1
        fi
        ;;

    clear_old_threats)
        if [ -z "$2" ]; then
            echo "ERROR: Days parameter required"
            exit 1
        fi
        
        DAYS="$2"
        SEVERITY="${3:-low}"
        
        result=$($PYTHON_BIN "$SCRIPTS_DIR/manage_threats.py" clear_old "$DAYS" "$SEVERITY" 2>&1)
        if [ $? -eq 0 ]; then
            log_action "Cleared old threats: $result"
            echo "$result"
        else
            log_action "Failed to clear old threats: $result"
            echo "ERROR: $result"
            exit 1
        fi
        ;;
        
    add_sample_threats)
        # Use the Python script to add sample data
        result=$($PYTHON_BIN "$SCRIPTS_DIR/manage_threats.py" add_samples 2>&1)
        if [ $? -eq 0 ]; then
            log_action "Added sample threats for testing"
            echo "OK: Sample threats added"
        else
            log_action "Failed to add sample threats: $result"
            echo "ERROR: $result"
            exit 1
        fi
        ;;
        
    get_stats)
        # If you have a get_stats.py script
        if [ -f "$SCRIPTS_DIR/get_stats.py" ]; then
            $PYTHON_BIN "$SCRIPTS_DIR/get_stats.py" "${2:-}"
        else
            echo '{"message": "WebGuard statistics module not available", "status": "ok"}'
        fi
        ;;
        
    test)
        echo "Testing WebGuard control script..."
        echo "PATH: $PATH"
        echo "Python: $PYTHON_BIN"
        echo "Scripts directory: $SCRIPTS_DIR"
        echo "Log directory: $LOG_DIR"
        echo ""
        echo "Available Python scripts:"
        ls -la "$SCRIPTS_DIR"/*.py 2>/dev/null || echo "No Python scripts found"
        echo ""
        echo "Testing database connection..."
        result=$($PYTHON_BIN "$SCRIPTS_DIR/manage_blocking.py" list 1 1 2>&1)
        if [ $? -eq 0 ]; then
            echo "Database connection: OK"
        else
            echo "Database connection: ERROR - $result"
        fi
        echo "Test complete"
        ;;
        
    *)
        echo "Usage: $0 {command} [parameters...]"
        echo ""
        echo "IP Blocking Commands:"
        echo "  block_ip <IP> [duration] [reason] [block_type]"
        echo "  unblock_ip <IP> [reason]"
        echo "  list_blocked [page] [limit]"
        echo "  bulk_block <ip_list> [duration] [reason] [block_type]"
        echo "  clear_expired"
        echo "  export_blocked [format] [include_expired]"
        echo ""
        echo "Whitelist Commands:"
        echo "  whitelist_ip <IP> [description] [permanent] [expiry]"
        echo "  remove_whitelist <IP> [reason]"
        echo "  list_whitelist [page] [limit]"
        echo "  check_whitelist <IP>"
        echo "  export_whitelist [format]"
        echo ""
        echo "Threat Management:"
        echo "  mark_false_positive <threat_id> [reason]"
        echo "  whitelist_from_threat <threat_id> [description] [permanent]"
        echo "  block_from_threat <threat_id> [duration] [reason]"
        echo "  create_rule_from_threat <threat_id> <rule_name> [rule_type] [enabled]"
        echo "  clear_old_threats <days> [severity]"
        echo "  add_sample_threats"
        echo ""
        echo "JSON Output:"
        echo "  show_json {blocked|whitelist|threats} [page] [limit]"
        echo ""
        echo "Utility:"
        echo "  clear_logs"
        echo "  get_stats [type]"
        echo "  test"
        echo ""
        exit 1
        ;;
esac

exit 0