#!/bin/sh

# WebGuard Control Script - Database Version
# /usr/local/opnsense/scripts/OPNsense/WebGuard/webguard_control.sh

PATH="/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin:$PATH"
export PATH

PYTHON_BIN="python3.11"
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
        
    add_to_whitelist)
        if [ -z "$2" ]; then
            echo "ERROR: IP address required"
            exit 1
        fi
        
        IP="$2"
        DESCRIPTION="${3:-Manual whitelist}"
        PERMANENT="${4:-1}"
        
        if ! validate_ip "$IP"; then
            echo "ERROR: Invalid IP address format"
            exit 1
        fi
        
        # Use the Python script
        result=$($PYTHON_BIN "$SCRIPTS_DIR/manage_whitelist.py" add "$IP" "$DESCRIPTION" "$PERMANENT" 2>&1)
        if [ $? -eq 0 ]; then
            log_action "Whitelisted IP: $IP (description: $DESCRIPTION)"
            echo "OK: $IP whitelisted"
        else
            log_action "Failed to whitelist IP: $IP - $result"
            echo "ERROR: $result"
            exit 1
        fi
        ;;
        
    remove_from_whitelist)
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
        
    get_blocked_ips)
        PAGE="${2:-1}"
        
        # Use the Python script to get blocked IPs in JSON format
        result=$($PYTHON_BIN "$SCRIPTS_DIR/manage_blocking.py" list "$PAGE" 2>&1)
        if [ $? -eq 0 ]; then
            echo "$result"
        else
            echo '{"status": "error", "message": "Failed to retrieve blocked IPs", "data": []}'
            exit 1
        fi
        ;;
        
    get_whitelist)
        PAGE="${2:-1}"
        LIMIT="${3:-100}"
        
        # Use the Python script to get whitelist in JSON format
        result=$($PYTHON_BIN "$SCRIPTS_DIR/manage_whitelist.py" list "$PAGE" "$LIMIT" 2>&1)
        if [ $? -eq 0 ]; then
            echo "$result"
        else
            echo '{"status": "error", "message": "Failed to retrieve whitelist", "data": []}'
            exit 1
        fi
        ;;

    get_threats)
        PAGE="${2:-1}"
        
        # Use the Python script to get threats
        if [ -f "$SCRIPTS_DIR/manage_threats.py" ]; then
            result=$($PYTHON_BIN "$SCRIPTS_DIR/manage_threats.py" get_threats "$PAGE" 2>&1)
            if [ $? -eq 0 ]; then
                echo "$result"
            else
                echo '{"status": "error", "message": "Failed to retrieve threats", "data": {"threats": []}}'
            fi
        else
            # Return empty threats data if script doesn't exist
            echo '{"status": "ok", "data": {"threats": [], "total": 0, "page": 1}}'
        fi
        ;;

    get_threat_all)
        PAGE="${2:-1}"
        
        # Use the Python script to get all threats
        if [ -f "$SCRIPTS_DIR/manage_threats.py" ]; then
            result=$($PYTHON_BIN "$SCRIPTS_DIR/manage_threats.py" get_threat_all "$PAGE" 2>&1)
            if [ $? -eq 0 ]; then
                echo "$result"
            else
                echo '{"status": "error", "message": "Failed to retrieve all threats", "data": {"threats": []}}'
            fi
        else
            echo '{"status": "ok", "data": {"threats": [], "total": 0, "page": 1}}'
        fi
        ;;

    get_threat_false_positive)
        PAGE="${2:-1}"
        
        # Use the Python script to get false positive threats
        if [ -f "$SCRIPTS_DIR/manage_threats.py" ]; then
            result=$($PYTHON_BIN "$SCRIPTS_DIR/manage_threats.py" get_threat_false_positive "$PAGE" 2>&1)
            if [ $? -eq 0 ]; then
                echo "$result"
            else
                echo '{"status": "error", "message": "Failed to retrieve false positive threats", "data": {"threats": []}}'
            fi
        else
            echo '{"status": "ok", "data": {"threats": [], "total": 0, "page": 1}}'
        fi
        ;;

    get_recent_threats)
        LIMIT="${2:-10}"
        
        # Use the Python script to get recent threats
        if [ -f "$SCRIPTS_DIR/manage_threats.py" ]; then
            result=$($PYTHON_BIN "$SCRIPTS_DIR/manage_threats.py" get_recent "$LIMIT" 2>&1)
            if [ $? -eq 0 ]; then
                echo "$result"
            else
                echo '{"status": "ok", "recent": []}'
            fi
        else
            echo '{"status": "ok", "recent": []}'
        fi
        ;;

    get_threat_feed)
        SINCE_ID="${2:-0}"
        LIMIT="${3:-50}"
        
        # Use the Python script to get threat feed
        if [ -f "$SCRIPTS_DIR/manage_threats.py" ]; then
            result=$($PYTHON_BIN "$SCRIPTS_DIR/manage_threats.py" get_feed "$SINCE_ID" "$LIMIT" 2>&1)
            if [ $? -eq 0 ]; then
                echo "$result"
            else
                echo '{"status": "ok", "feed": [], "lastId": 0}'
            fi
        else
            echo '{"status": "ok", "feed": [], "lastId": 0}'
        fi
        ;;

    get_threat_timeline)
        PERIOD="${2:-24h}"
        
        # Use the Python script to get threat timeline
        if [ -f "$SCRIPTS_DIR/manage_threats.py" ]; then
            result=$($PYTHON_BIN "$SCRIPTS_DIR/manage_threats.py" get_timeline "$PERIOD" 2>&1)
            if [ $? -eq 0 ]; then
                echo "$result"
            else
                echo '{"status": "ok", "timeline": {"labels": [], "threats": [], "requests": []}, "period": "'$PERIOD'"}'
            fi
        else
            echo '{"status": "ok", "timeline": {"labels": [], "threats": [], "requests": []}, "period": "'$PERIOD'"}'
        fi
        ;;
        
    bulk_block_ips)
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
        result=$($PYTHON_BIN "$SCRIPTS_DIR/manage_blocking.py" clear_expired 2>&1)
        if [ $? -eq 0 ]; then
            log_action "Cleared expired entries"
            echo "OK: Cleared expired entries"
        else
            log_action "Failed to clear expired entries: $result"
            echo "ERROR: Failed to clear expired entries"
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
        
        result=$($PYTHON_BIN "$SCRIPTS_DIR/manage_blocking.py" export "$FORMAT" 2>&1)
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

    unmark_false_positive)
        if [ -z "$2" ]; then
            echo "ERROR: Threat ID required"
            exit 1
        fi
        
        THREAT_ID="$2"
        REASON="${3:-Manual unmark false positive}"
        
        # Use the Python script
        result=$($PYTHON_BIN "$SCRIPTS_DIR/manage_threats.py" unmark_false_positive "$THREAT_ID" "$REASON" 2>&1)
        if [ $? -eq 0 ]; then
            log_action "Unmarked threat $THREAT_ID as false positive: $REASON"
            echo "OK: Threat $THREAT_ID unmarked as false positive"
        else
            log_action "Failed to unmark false positive: $result"
            echo "ERROR: $result"
            exit 1
        fi
        ;;

    whitelist_ip_from_threat)
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

    block_ip_from_threat)
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
        
    get_stats)
        # Return basic stats - if you have a get_stats.py script, use it
        if [ -f "$SCRIPTS_DIR/get_stats.py" ]; then
            $PYTHON_BIN "$SCRIPTS_DIR/get_stats.py" "${2:-}"
        else
            echo '{"message": "WebGuard statistics", "status": "ok", "blocked_count": 0, "whitelist_count": 0, "active_blocks": 0, "temp_blocks": 0}'
        fi
        ;;

    # Add these cases to the existing switch statement
block_country)
    if [ -z "$2" ]; then
        echo "ERROR: Country name required"
        exit 1
    fi
    
    COUNTRY="$2"
    DURATION="${3:-3600}"
    REASON="${4:-Geographic blocking}"
    
    # Use the Python script
    result=$($PYTHON_BIN "$SCRIPTS_DIR/manage_geo_blocking.py" block "$COUNTRY" "$DURATION" "$REASON" 2>&1)
    if [ $? -eq 0 ]; then
        log_action "Blocked country: $COUNTRY (duration: $DURATION, reason: $REASON)"
        echo "OK: $COUNTRY blocked"
    else
        log_action "Failed to block country: $COUNTRY - $result"
        echo "ERROR: $result"
        exit 1
    fi
    ;;
    
    unblock_country)
        if [ -z "$2" ]; then
            echo "ERROR: Country name required"
            exit 1
        fi
        
        COUNTRY="$2"
        REASON="${3:-Manual unblock}"
        
        # Use the Python script
        result=$($PYTHON_BIN "$SCRIPTS_DIR/manage_geo_blocking.py" unblock "$COUNTRY" "$REASON" 2>&1)
        if [ $? -eq 0 ]; then
            log_action "Unblocked country: $COUNTRY (reason: $REASON)"
            echo "OK: $COUNTRY unblocked"
        else
            log_action "Failed to unblock country: $COUNTRY - $result"
            echo "ERROR: $result"
            exit 1
        fi
        ;;
        
    get_blocked_countries)
        # Use the Python script to get blocked countries in JSON format
        result=$($PYTHON_BIN "$SCRIPTS_DIR/manage_geo_blocking.py" list 2>&1)
        if [ $? -eq 0 ]; then
            echo "$result"
        else
            echo '{"status": "error", "message": "Failed to retrieve blocked countries", "data": []}'
            exit 1
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
        if [ -f "$SCRIPTS_DIR/manage_blocking.py" ]; then
            result=$($PYTHON_BIN "$SCRIPTS_DIR/manage_blocking.py" list 1 2>&1)
            if [ $? -eq 0 ]; then
                echo "Database connection: OK"
            else
                echo "Database connection: ERROR - $result"
            fi
        else
            echo "Database connection: SKIP - manage_blocking.py not found"
        fi
        echo "Test complete"
        ;;
        
    *)
        echo "Usage: $0 {command} [parameters...]"
        echo ""
        echo "IP Blocking Commands:"
        echo "  block_ip <IP> [duration] [reason] [block_type]"
        echo "  unblock_ip <IP> [reason]"
        echo "  get_blocked_ips [page]"
        echo "  bulk_block_ips <ip_list> [duration] [reason] [block_type]"
        echo "  clear_expired"
        echo "  export_blocked [format]"
        echo ""
        echo "Whitelist Commands:"
        echo "  add_to_whitelist <IP> [description] [permanent]"
        echo "  remove_from_whitelist <IP> [reason]"
        echo "  get_whitelist [page] [limit]"
        echo "  check_whitelist <IP>"
        echo "  export_whitelist [format]"
        echo ""
        echo "Threat Management:"
        echo "  get_threats [page]"
        echo "  get_threat_all [page]"
        echo "  get_threat_false_positive [page]"
        echo "  get_recent_threats [limit]"
        echo "  get_threat_feed <since_id> [limit]"
        echo "  get_threat_timeline [period]"
        echo "  mark_false_positive <threat_id> [reason]"
        echo "  unmark_false_positive <threat_id> [reason]"
        echo "  whitelist_ip_from_threat <threat_id> [description] [permanent]"
        echo "  block_ip_from_threat <threat_id> [duration] [reason]"
        echo "  create_rule_from_threat <threat_id> <rule_name> [rule_type] [enabled]"
        echo "  clear_old_threats <days> [severity]"
        echo "  add_sample_threats"
        echo ""
        echo "Country Management Commands:"
        echo "  block_country <country_name> [duration] [reason]"
        echo "  unblock_country <country_name> [reason]"
        echo "  get_blocked_countries"
        echo "Utility:"
        echo "  clear_logs"
        echo "  get_stats [type]"
        echo "  test"
        echo ""
        exit 1
        ;;
esac

exit 0