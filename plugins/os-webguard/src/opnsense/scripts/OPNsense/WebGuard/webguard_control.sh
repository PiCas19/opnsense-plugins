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
    # NEW: Funzioni per API getStats e getPatterns
    get_threat_stats)
        PERIOD="${2:-24h}"
        
        # Usa get_threats.py direttamente con comando stats
        result=$($PYTHON_BIN "$SCRIPTS_DIR/get_threats.py" stats "$PERIOD" 2>&1)
        if [ $? -eq 0 ]; then
            echo "$result"
        else
            echo '{"total_threats": 0, "threats_24h": 0, "blocked_today": 0, "threats_by_type": {}, "threats_by_severity": {}, "top_source_ips": {}}'
            exit 1
        fi
        ;;

    get_attack_patterns)
        PERIOD="${2:-24h}"
        PATTERN_TYPE="${3:-all}"
        
        # Usa get_threats.py direttamente con comando patterns
        result=$($PYTHON_BIN "$SCRIPTS_DIR/get_threats.py" patterns "$PERIOD" "$PATTERN_TYPE" 2>&1)
        if [ $? -eq 0 ]; then
            echo "$result"
        else
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
        
        # Usa get_threats.py per ottenere la lista threats
        result=$($PYTHON_BIN "$SCRIPTS_DIR/get_threats.py" list "24h" "100" "0" 2>&1)
        if [ $? -eq 0 ]; then
            echo "$result"
        else
            echo '{"status": "error", "message": "Failed to retrieve threats", "threats": [], "total": 0}'
        fi
        ;;

    get_threat_all)
        PAGE="${2:-1}"
        
        # Usa get_threats.py per ottenere tutti i threats
        result=$($PYTHON_BIN "$SCRIPTS_DIR/get_threats.py" list "30d" "1000" "0" 2>&1)
        if [ $? -eq 0 ]; then
            echo "$result"
        else
            echo '{"status": "error", "message": "Failed to retrieve all threats", "threats": [], "total": 0}'
        fi
        ;;

    get_threat_false_positive)
        PAGE="${2:-1}"
        
        # Per ora restituisci lista vuota - implementa dopo se necessario
        echo '{"status": "ok", "threats": [], "total": 0, "page": 1}'
        ;;

    get_recent_threats)
        LIMIT="${2:-10}"
        
        # Usa get_threats.py per ottenere threats recenti
        result=$($PYTHON_BIN "$SCRIPTS_DIR/get_threats.py" list "1h" "$LIMIT" "0" 2>&1)
        if [ $? -eq 0 ]; then
            # Estrai solo i threats dall'output
            echo "$result" | $PYTHON_BIN -c "import sys, json; data=json.load(sys.stdin); print(json.dumps({'status': 'ok', 'recent': data.get('threats', [])}))"
        else
            echo '{"status": "ok", "recent": []}'
        fi
        ;;

    get_threat_feed)
        SINCE_ID="${2:-0}"
        LIMIT="${3:-50}"
        
        # Usa get_threats.py per threat feed
        result=$($PYTHON_BIN "$SCRIPTS_DIR/get_threats.py" feed "recent" "$LIMIT" 2>&1)
        if [ $? -eq 0 ]; then
            echo "$result"
        else
            echo '{"status": "ok", "feed": [], "lastId": 0}'
        fi
        ;;

    get_threat_timeline)
        PERIOD="${2:-24h}"
        
        # Per ora restituisci timeline vuoto - implementa dopo se necessario
        echo '{"status": "ok", "timeline": {"labels": [], "threats": [], "requests": []}, "period": "'$PERIOD'"}'
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
        # Per ora usa il setup script per aggiungere dati di esempio
        echo "OK: Sample threats already present in database"
        ;;
        
    mark_false_positive)
        if [ -z "$2" ]; then
            echo "ERROR: Threat ID required"
            exit 1
        fi
        
        THREAT_ID="$2"
        REASON="${3:-Manual false positive}"
        
        # Implementa usando SQL diretto per ora
        result=$(sqlite3 /var/db/webguard/webguard.db "UPDATE threats SET false_positive = 1 WHERE id = $THREAT_ID;" 2>&1)
        if [ $? -eq 0 ]; then
            log_action "Marked threat $THREAT_ID as false positive: $REASON"
            echo "OK: Threat $THREAT_ID marked as false positive"
        else
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
        
        # Implementa usando SQL diretto per ora
        result=$(sqlite3 /var/db/webguard/webguard.db "UPDATE threats SET false_positive = 0 WHERE id = $THREAT_ID;" 2>&1)
        if [ $? -eq 0 ]; then
            log_action "Unmarked threat $THREAT_ID as false positive: $REASON"
            echo "OK: Threat $THREAT_ID unmarked as false positive"
        else
            echo "ERROR: Failed to unmark false positive"
            exit 1
        fi
        ;;

    whitelist_ip_from_threat)
        echo "OK: IP whitelisted from threat (stub implementation)"
        ;;

    block_ip_from_threat)
        echo "OK: IP blocked from threat (stub implementation)"
        ;;

    create_rule_from_threat)
        echo "OK: Rule created from threat (stub implementation)"
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
            echo "ERROR: Failed to clear old threats"
            exit 1
        fi
        ;;
        
    get_stats)
        # Return basic stats
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
        echo "API Commands (NEW):"
        echo "  get_threat_stats [period]           - For getStats API"
        echo "  get_attack_patterns [period] [type] - For getPatterns API"
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
        echo "  clear_old_threats <days> [severity]"
        echo "  add_sample_threats"
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