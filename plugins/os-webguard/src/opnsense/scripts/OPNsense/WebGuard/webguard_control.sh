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
    get_threat_stats)
        PERIOD="${2:-24h}"
        
        result=$($PYTHON_BIN "$SCRIPTS_DIR/get_threats.py" stats "$PERIOD" 2>&1)
        if [ $? -eq 0 ]; then
            echo "$result"
        else
            log_action "Failed to get threat stats: $result"
            echo '{"total_threats": 0, "threats_24h": 0, "blocked_today": 0, "threats_by_type": {}, "threats_by_severity": {}, "top_source_ips": {}}'
            exit 1
        fi
        ;;

    get_attack_patterns)
        PERIOD="${2:-24h}"
        PATTERN_TYPE="${3:-all}"
        
        result=$($PYTHON_BIN "$SCRIPTS_DIR/get_threats.py" patterns "$PERIOD" "$PATTERN_TYPE" 2>&1)
        if [ $? -eq 0 ]; then
            echo "$result"
        else
            log_action "Failed to get attack patterns: $result"
            echo '{"patterns": [], "trending_attacks": [], "attack_sequences": []}'
            exit 1
        fi
        ;;

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
        
        result=$($PYTHON_BIN "$SCRIPTS_DIR/manage_blocking.py" list "$PAGE" 2>&1)
        if [ $? -eq 0 ]; then
            echo "$result"
        else
            log_action "Failed to get blocked IPs: $result"
            echo '{"status": "error", "message": "Failed to retrieve blocked IPs", "data": []}'
            exit 1
        fi
        ;;
        
    get_whitelist)
        PAGE="${2:-1}"
        LIMIT="${3:-100}"
        
        result=$($PYTHON_BIN "$SCRIPTS_DIR/manage_whitelist.py" list "$PAGE" "$LIMIT" 2>&1)
        if [ $? -eq 0 ]; then
            echo "$result"
        else
            log_action "Failed to get whitelist: $result"
            echo '{"status": "error", "message": "Failed to retrieve whitelist", "data": []}'
            exit 1
        fi
        ;;

    get_threats)
        PAGE="${2:-1}"
        
        result=$($PYTHON_BIN "$SCRIPTS_DIR/get_threats.py" list "24h" "100" "0" 2>&1)
        if [ $? -eq 0 ]; then
            echo "$result"
        else
            log_action "Failed to get threats: $result"
            echo '{"status": "error", "message": "Failed to retrieve threats", "threats": [], "total": 0}'
            exit 1
        fi
        ;;

    get_threat_all)
        PAGE="${2:-1}"
        
        result=$($PYTHON_BIN "$SCRIPTS_DIR/get_threats.py" list "30d" "1000" "0" 2>&1)
        if [ $? -eq 0 ]; then
            echo "$result"
        else
            log_action "Failed to get all threats: $result"
            echo '{"status": "error", "message": "Failed to retrieve all threats", "threats": [], "total": 0}'
            exit 1
        fi
        ;;

    get_threat_false_positive)
        PAGE="${2:-1}"
        
        result=$($PYTHON_BIN "$SCRIPTS_DIR/get_threats.py" list_false_positives "30d" "100" "$(( ($PAGE - 1) * 100 ))" 2>&1)
        if [ $? -eq 0 ]; then
            echo "$result"
        else
            log_action "Failed to get false positive threats: $result"
            echo '{"status": "error", "message": "Failed to retrieve false positive threats", "threats": [], "total": 0}'
            exit 1
        fi
        ;;

    get_recent_threats)
        LIMIT="${2:-10}"
        PERIOD="${3:-1h}"  # Allow configurable period, default to 1h
        
        result=$($PYTHON_BIN "$SCRIPTS_DIR/get_threats.py" list "$PERIOD" "$LIMIT" "0" 2>&1)
        if [ $? -eq 0 ]; then
            echo "{\"status\": \"ok\", \"recent\": $(echo "$result" | $PYTHON_BIN -c "import sys, json; data=json.load(sys.stdin); print(json.dumps(data.get('threats', [])))"), \"total\": $(echo "$result" | $PYTHON_BIN -c "import sys, json; data=json.load(sys.stdin); print(data.get('total', 0))"), \"period\": \"$PERIOD\"}"
            log_action "Retrieved recent threats (period: $PERIOD, limit: $LIMIT, total: $(echo "$result" | $PYTHON_BIN -c "import sys, json; data=json.load(sys.stdin); print(data.get('total', 0))"))"
        else
            log_action "Failed to get recent threats: $result"
            echo "{\"status\": \"error\", \"message\": \"Failed to retrieve recent threats\", \"recent\": [], \"total\": 0, \"period\": \"$PERIOD\"}"
            exit 1
        fi
        ;;

    get_threat_feed)
        SINCE_ID="${2:-0}"
        LIMIT="${3:-50}"
        
        result=$($PYTHON_BIN "$SCRIPTS_DIR/get_threats.py" feed "recent" "$LIMIT" 2>&1)
        if [ $? -eq 0 ]; then
            echo "$result"
        else
            log_action "Failed to get threat feed: $result"
            echo '{"status": "ok", "feed": [], "lastId": 0}'
            exit 1
        fi
        ;;

    get_threat_timeline)
        PERIOD="${2:-24h}"
        
        result=$($PYTHON_BIN "$SCRIPTS_DIR/get_threats.py" timeline "$PERIOD" 2>&1)
        if [ $? -eq 0 ]; then
            echo "$result"
        else
            log_action "Failed to get threat timeline: $result"
            echo "{\"status\": \"ok\", \"timeline\": {\"labels\": [], \"threats\": [], \"requests\": []}, \"period\": \"$PERIOD\"}"
            exit 1
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
        
        result=$($PYTHON_BIN "$SCRIPTS_DIR/manage_whitelist.py" check "$IP" 2>&1)
        if [ $? -eq 0 ]; then
            echo "$result"
        else
            log_action "Failed to check whitelist: $result"
            echo "ERROR: Failed to check whitelist"
            exit 1
        fi
        ;;
        
    clear_expired)
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
            log_action "Failed to export blocked IPs: $result"
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
            log_action "Failed to export whitelist: $result"
            echo "ERROR: Failed to export whitelist"
            exit 1
        fi
        ;;
        
    add_sample_threats)
        COUNT="${2:-5}"
        result=$($PYTHON_BIN "$SCRIPTS_DIR/get_threats.py" add_sample_threats "$COUNT" 2>&1)
        if [ $? -eq 0 ]; then
            log_action "Added $COUNT sample threats"
            echo "$result"
        else
            log_action "Failed to add sample threats: $result"
            echo "{\"status\": \"error\", \"message\": \"Failed to add sample threats\"}"
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
        
        result=$($PYTHON_BIN "$SCRIPTS_DIR/get_threats.py" mark_false_positive "$THREAT_ID" "$REASON" 2>&1)
        if [ $? -eq 0 ]; then
            log_action "Marked threat $THREAT_ID as false positive: $REASON"
            echo "$result"
        else
            log_action "Failed to mark threat $THREAT_ID as false positive: $result"
            echo "ERROR: Failed to mark false positive"
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
        
        result=$($PYTHON_BIN "$SCRIPTS_DIR/get_threats.py" unmark_false_positive "$THREAT_ID" "$REASON" 2>&1)
        if [ $? -eq 0 ]; then
            log_action "Unmarked threat $THREAT_ID as false positive: $REASON"
            echo "$result"
        else
            log_action "Failed to unmark threat $THREAT_ID as false positive: $result"
            echo "ERROR: Failed to unmark false positive"
            exit 1
        fi
        ;;

    whitelist_ip_from_threat)
        if [ -z "$2" ]; then
            echo "ERROR: Threat ID required"
            exit 1
        fi
        
        THREAT_ID="$2"
        DESCRIPTION="${3:-Whitelisted from threat}"
        
        result=$($PYTHON_BIN "$SCRIPTS_DIR/get_threats.py" whitelist_ip_from_threat "$THREAT_ID" "$DESCRIPTION" 2>&1)
        if [ $? -eq 0 ]; then
            log_action "Whitelisted IP from threat $THREAT_ID: $DESCRIPTION"
            echo "$result"
        else
            log_action "Failed to whitelist IP from threat $THREAT_ID: $result"
            echo "ERROR: Failed to whitelist IP from threat"
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
        
        result=$($PYTHON_BIN "$SCRIPTS_DIR/get_threats.py" block_ip_from_threat "$THREAT_ID" "$DURATION" "$REASON" 2>&1)
        if [ $? -eq 0 ]; then
            log_action "Blocked IP from threat $THREAT_ID (duration: $DURATION, reason: $REASON)"
            echo "$result"
        else
            log_action "Failed to block IP from threat $THREAT_ID: $result"
            echo "ERROR: Failed to block IP from threat"
            exit 1
        fi
        ;;

    create_rule_from_threat)
        if [ -z "$2" ]; then
            echo "ERROR: Threat ID required"
            exit 1
        fi
        
        THREAT_ID="$2"
        result=$($PYTHON_BIN "$SCRIPTS_DIR/get_threats.py" create_rule_from_threat "$THREAT_ID" 2>&1)
        if [ $? -eq 0 ]; then
            log_action "Created rule from threat $THREAT_ID"
            echo "$result"
        else
            log_action "Failed to create rule from threat $THREAT_ID: $result"
            echo "ERROR: Failed to create rule from threat"
            exit 1
        fi
        ;;

    clear_old_threats)
        if [ -z "$2" ]; then
            echo "ERROR: Days parameter required"
            exit 1
        fi
        
        DAYS="$2"
        CUTOFF_TIME=$(($(date +%s) - ($DAYS * 86400)))
        
        result=$(sqlite3 /var/db/webguard/webguard.db "DELETE FROM threats WHERE timestamp < $CUTOFF_TIME;" 2>&1)
        if [ $? -eq 0 ]; then
            log_action "Cleared old threats older than $DAYS days"
            echo "OK: Cleared old threats"
        else
            log_action "Failed to clear old threats: $result"
            echo "ERROR: Failed to clear old threats"
            exit 1
        fi
        ;;
        
    get_stats)
        BLOCKED_COUNT=$(sqlite3 /var/db/webguard/webguard.db "SELECT COUNT(*) FROM blocked_ips;" 2>/dev/null || echo "0")
        WHITELIST_COUNT=$(sqlite3 /var/db/webguard/webguard.db "SELECT COUNT(*) FROM whitelist;" 2>/dev/null || echo "0")
        THREATS_COUNT=$(sqlite3 /var/db/webguard/webguard.db "SELECT COUNT(*) FROM threats;" 2>/dev/null || echo "0")
        
        echo '{"message": "WebGuard statistics", "status": "ok", "blocked_count": '$BLOCKED_COUNT', "whitelist_count": '$WHITELIST_COUNT', "total_threats": '$THREATS_COUNT', "active_blocks": '$BLOCKED_COUNT'}'
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
        THREATS_COUNT=$(sqlite3 /var/db/webguard/webguard.db "SELECT COUNT(*) FROM threats;" 2>/dev/null || echo "ERROR")
        if [ "$THREATS_COUNT" != "ERROR" ]; then
            echo "Database connection: OK ($THREATS_COUNT threats)"
        else
            echo "Database connection: ERROR"
        fi
        echo ""
        echo "Testing get_threats.py..."
        result=$($PYTHON_BIN "$SCRIPTS_DIR/get_threats.py" stats "24h" 2>&1)
        if [ $? -eq 0 ]; then
            echo "get_threats.py: OK"
        else
            echo "get_threats.py: ERROR - $result"
        fi
        echo "Test complete"
        ;;
        
    *)
        echo "Usage: $0 {command} [parameters...]"
        echo ""
        echo "API Commands:"
        echo "  get_threat_stats [period]           - Get threat statistics"
        echo "  get_attack_patterns [period] [type] - Get attack patterns"
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
        echo "  get_recent_threats [limit] [period]"
        echo "  get_threat_feed <since_id> [limit]"
        echo "  get_threat_timeline [period]"
        echo "  mark_false_positive <threat_id> [reason]"
        echo "  unmark_false_positive <threat_id> [reason]"
        echo "  whitelist_ip_from_threat <threat_id> [description]"
        echo "  block_ip_from_threat <threat_id> [duration] [reason]"
        echo "  create_rule_from_threat <threat_id>"
        echo "  clear_old_threats <days>"
        echo "  add_sample_threats [count]"
        echo ""
        echo "Utility:"
        echo "  clear_logs"
        echo "  get_stats"
        echo "  test"
        echo ""
        exit 1
        ;;
esac

exit 0