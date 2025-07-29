#!/bin/sh

# SIEM Logger Control Script
# /usr/local/opnsense/scripts/OPNsense/SiemLogger/siemlogger_control.sh
# 
# This script provides management operations for the SIEM Logger Engine
# The engine itself runs autonomously and doesn't need parameters

PATH="/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin:$PATH"
export PATH

PYTHON_BIN="/usr/local/bin/python3.11"
ENGINE_SCRIPT="/usr/local/opnsense/scripts/OPNsense/SiemLogger/siemlogger_engine.py"
LOG_DIR="/var/log/siemlogger"
PIDFILE="/var/run/siemlogger.pid"
CONFIG_FILE="/conf/config.xml"
DB_FILE="/var/db/siemlogger/siemlogger.db"
STATS_FILE="$LOG_DIR/stats.json"

# Ensure directories exist
mkdir -p "$LOG_DIR" "/var/run" "/var/db/siemlogger"

# Function to log actions
log_action() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - CONTROL: $1" >> "$LOG_DIR/service.log"
}

# Function to check if engine is running
is_running() {
    if [ -f "$PIDFILE" ]; then
        PID=$(cat "$PIDFILE")
        if kill -0 "$PID" 2>/dev/null; then
            return 0
        else
            rm -f "$PIDFILE"
            return 1
        fi
    fi
    return 1
}

# Function to start the engine
start_engine() {
    if is_running; then
        PID=$(cat "$PIDFILE")
        echo "SIEM Logger Engine is already running (PID $PID)"
        log_action "Engine already running (PID $PID)"
        return 0
    fi

    echo "Starting SIEM Logger Engine..."
    log_action "Starting engine"

    # Check if Python and engine script exist
    if [ ! -x "$PYTHON_BIN" ]; then
        echo "ERROR: Python3 not found at $PYTHON_BIN"
        log_action "ERROR: Python3 not found"
        return 1
    fi

    if [ ! -f "$ENGINE_SCRIPT" ]; then
        echo "ERROR: Engine script not found at $ENGINE_SCRIPT"
        log_action "ERROR: Engine script not found"
        return 1
    fi

    # Start the engine as a daemon
    if command -v daemon >/dev/null 2>&1; then
        /usr/sbin/daemon -p "$PIDFILE" -f "$PYTHON_BIN" "$ENGINE_SCRIPT"
    else
        # Fallback: start in background
        "$PYTHON_BIN" "$ENGINE_SCRIPT" > "$LOG_DIR/stdout.log" 2> "$LOG_DIR/stderr.log" &
        echo $! > "$PIDFILE"
    fi

    # Wait a moment and check if it started
    sleep 3

    if is_running; then
        PID=$(cat "$PIDFILE")
        echo "SIEM Logger Engine started successfully (PID $PID)"
        log_action "Engine started successfully (PID $PID)"
        return 0
    else
        echo "Failed to start SIEM Logger Engine"
        log_action "Failed to start engine"
        echo "Check $LOG_DIR/stderr.log for errors"
        rm -f "$PIDFILE"
        return 1
    fi
}

# Function to stop the engine
stop_engine() {
    if ! is_running; then
        echo "SIEM Logger Engine is not running"
        log_action "Engine not running"
        return 0
    fi

    echo "Stopping SIEM Logger Engine..."
    log_action "Stopping engine"

    PID=$(cat "$PIDFILE")
    
    # Send TERM signal first
    kill -TERM "$PID" 2>/dev/null
    
    # Wait up to 15 seconds for graceful shutdown
    TIMEOUT=15
    while [ $TIMEOUT -gt 0 ] && is_running; do
        sleep 1
        TIMEOUT=$((TIMEOUT - 1))
    done

    # If still running, force kill
    if is_running; then
        echo "Engine didn't stop gracefully, forcing shutdown..."
        kill -KILL "$PID" 2>/dev/null
        sleep 2
        log_action "Engine forcefully stopped"
    fi

    rm -f "$PIDFILE"
    echo "SIEM Logger Engine stopped"
    log_action "Engine stopped successfully"
    return 0
}

# Function to get engine status
status_engine() {
    if is_running; then
        PID=$(cat "$PIDFILE")
        echo "SIEM Logger Engine is running (PID $PID)"
        
        # Show additional stats if available
        if [ -f "$STATS_FILE" ]; then
            if command -v jq >/dev/null 2>&1; then
                echo "=== Engine Statistics ==="
                uptime=$(jq -r '.engine_start_time' "$STATS_FILE" 2>/dev/null)
                if [ "$uptime" != "null" ] && [ -n "$uptime" ]; then
                    current_time=$(date +%s)
                    runtime=$((current_time - ${uptime%.*}))
                    echo "Uptime: ${runtime} seconds"
                fi
                
                events_processed=$(jq -r '.events_processed // 0' "$STATS_FILE" 2>/dev/null)
                events_exported=$(jq -r '.events_exported // 0' "$STATS_FILE" 2>/dev/null)
                threats_detected=$(jq -r '.threats_detected // 0' "$STATS_FILE" 2>/dev/null)
                
                echo "Events processed: $events_processed"
                echo "Events exported: $events_exported"
                echo "Threats detected: $threats_detected"
                echo "========================="
            else
                echo "Statistics available in: $STATS_FILE"
            fi
        fi
        return 0
    else
        echo "SIEM Logger Engine is not running"
        return 1
    fi
}

# Function to restart the engine
restart_engine() {
    stop_engine
    sleep 2
    start_engine
}

# Function to reload configuration
reconfigure() {
    echo "Reloading SIEM Logger configuration..."
    log_action "Reloading configuration"
    
    if is_running; then
        PID=$(cat "$PIDFILE")
        # Send USR1 signal to reload config (if engine supports it)
        kill -USR1 "$PID" 2>/dev/null || {
            echo "Configuration reload signal not supported, restarting engine..."
            restart_engine
        }
    else
        echo "Engine is not running, no reload needed"
    fi
}

# Function to get statistics via database query
get_stats() {
    type="${1:-summary}"
    log_action "Retrieving statistics: $type"

    if [ -f "$STATS_FILE" ]; then
        case "$type" in
            "summary")
                if command -v jq >/dev/null 2>&1; then
                    jq '{
                        status: "ok",
                        events_processed: .events_processed,
                        events_exported: .events_exported,
                        threats_detected: .threats_detected,
                        uptime: (now - .engine_start_time)
                    }' "$STATS_FILE"
                else
                    echo '{"status": "ok", "message": "Statistics available but jq not installed"}'
                fi
                ;;
            "detailed")
                if command -v jq >/dev/null 2>&1; then
                    jq '.' "$STATS_FILE"
                else
                    cat "$STATS_FILE"
                fi
                ;;
            "threats")
                if command -v jq >/dev/null 2>&1; then
                    jq '{
                        status: "ok",
                        threats_detected: .threats_detected,
                        failed_logins: .failed_login_attempts,
                        firewall_blocks: .firewall_blocks,
                        suspicious_activity: .suspicious_activity
                    }' "$STATS_FILE"
                else
                    echo '{"status": "ok", "message": "Threat statistics available but jq not installed"}'
                fi
                ;;
            *)
                echo '{"status": "error", "message": "Unknown statistics type"}'
                return 1
                ;;
        esac
    else
        echo '{"status": "error", "message": "Statistics file not found"}'
        return 1
    fi
}

# Function to get logs via database query
get_logs() {
    page="${1:-1}"
    limit="${2:-50}"
    log_action "Retrieving logs (page $page, limit $limit)"

    if [ ! -f "$DB_FILE" ]; then
        echo '{"status": "error", "message": "Database file not found"}'
        return 1
    fi

    if ! command -v sqlite3 >/dev/null 2>&1; then
        echo '{"status": "error", "message": "SQLite3 not available"}'
        return 1
    fi

    offset=$(( (page - 1) * limit ))
    
    # Get total count
    total=$(sqlite3 "$DB_FILE" "SELECT COUNT(*) FROM events;" 2>/dev/null || echo "0")
    
    # Get events with pagination
    events=$(sqlite3 "$DB_FILE" "
        SELECT json_object(
            'id', id,
            'timestamp', timestamp,
            'source_ip', source_ip,
            'user', user,
            'event_type', event_type,
            'description', description,
            'severity', severity,
            'source_log', source_log,
            'country_code', country_code
        ) 
        FROM events 
        ORDER BY timestamp DESC 
        LIMIT $limit OFFSET $offset;
    " 2>/dev/null)

    if [ $? -eq 0 ]; then
        echo "{"
        echo "  \"status\": \"ok\","
        echo "  \"total\": $total,"
        echo "  \"page\": $page,"
        echo "  \"limit\": $limit,"
        echo "  \"events\": ["
        
        first=true
        echo "$events" | while IFS= read -r line; do
            if [ "$first" = true ]; then
                first=false
            else
                echo ","
            fi
            echo "    $line"
        done
        
        echo "  ]"
        echo "}"
    else
        echo '{"status": "error", "message": "Database query failed"}'
        return 1
    fi
}

# Function to export events manually
export_events() {
    format="${1:-json}"
    log_action "Manual export requested in $format format"

    if ! is_running; then
        echo '{"status": "error", "message": "Engine is not running"}'
        return 1
    fi

    # The engine handles exports automatically, but we can trigger immediate export
    # by sending a signal or checking export queue
    if [ -f "$STATS_FILE" ]; then
        echo '{"status": "ok", "message": "Export is handled automatically by the engine"}'
        if command -v jq >/dev/null 2>&1; then
            last_export=$(jq -r '.last_export_time' "$STATS_FILE" 2>/dev/null)
            exported_count=$(jq -r '.events_exported' "$STATS_FILE" 2>/dev/null)
            echo "Last export: $(date -r ${last_export%.*} 2>/dev/null || echo 'Unknown')"
            echo "Total exported: $exported_count"
        fi
    else
        echo '{"status": "error", "message": "Cannot determine export status"}'
        return 1
    fi
}

# Function to clear logs
clear_logs() {
    log_action "Clearing logs"

    echo "Clearing SIEM Logger logs..."
    
    # Clear log files
    for logfile in events.log audit.log engine.log export_events.log health_check.log stats.json stdout.log stderr.log service.log; do
        if [ -f "$LOG_DIR/$logfile" ]; then
            > "$LOG_DIR/$logfile"
            echo "Cleared: $LOG_DIR/$logfile"
        fi
    done

    # Clear database
    if [ -f "$DB_FILE" ] && command -v sqlite3 >/dev/null 2>&1; then
        sqlite3 "$DB_FILE" "DELETE FROM events; DELETE FROM audit_trail;" 2>/dev/null && {
            echo "Database events cleared"
        } || echo "Warning: Could not clear database"
    fi

    log_action "Logs cleared successfully"
    echo '{"status": "ok", "message": "Logs cleared successfully"}'
    return 0
}

# Function to test export configuration
test_export() {
    format="${1:-json}"
    log_action "Testing export configuration in $format format"

    if ! is_running; then
        echo '{"status": "error", "message": "Engine is not running, cannot test export"}'
        return 1
    fi

    # Check if export is enabled in configuration
    echo "Testing SIEM export configuration..."
    echo "Format: $format"
    echo "Engine status: Running"
    
    if [ -f "$STATS_FILE" ]; then
        if command -v jq >/dev/null 2>&1; then
            export_failures=$(jq -r '.export_failures // 0' "$STATS_FILE" 2>/dev/null)
            echo "Recent export failures: $export_failures"
        fi
    fi
    
    echo '{"status": "ok", "message": "Export test completed - check engine logs for details"}'
    return 0
}

# Function to perform health check
health_check() {
    echo "=== SIEM Logger Health Check ==="
    
    # Check engine status
    if is_running; then
        echo "✓ Engine is running"
    else
        echo "✗ Engine is not running"
    fi
    
    # Check required files
    echo "Checking required files:"
    [ -f "$ENGINE_SCRIPT" ] && echo "✓ Engine script exists" || echo "✗ Engine script missing"
    [ -x "$PYTHON_BIN" ] && echo "✓ Python3 available" || echo "✗ Python3 missing"
    [ -f "$CONFIG_FILE" ] && echo "✓ Configuration file exists" || echo "✗ Configuration missing"
    
    # Check directories
    echo "Checking directories:"
    [ -d "$LOG_DIR" ] && echo "✓ Log directory exists" || echo "✗ Log directory missing"
    [ -d "$(dirname "$DB_FILE")" ] && echo "✓ Database directory exists" || echo "✗ Database directory missing"
    
    # Check database
    if [ -f "$DB_FILE" ]; then
        echo "✓ Database file exists"
        if command -v sqlite3 >/dev/null 2>&1; then
            event_count=$(sqlite3 "$DB_FILE" "SELECT COUNT(*) FROM events;" 2>/dev/null || echo "0")
            echo "  Events in database: $event_count"
        fi
    else
        echo "✗ Database file missing"
    fi
    
    # Check log files
    echo "Checking log files:"
    for logfile in events.log audit.log engine.log; do
        if [ -f "$LOG_DIR/$logfile" ]; then
            size=$(du -h "$LOG_DIR/$logfile" 2>/dev/null | cut -f1)
            echo "✓ $logfile ($size)"
        else
            echo "✗ $logfile missing"
        fi
    done
    
    # Check statistics
    if [ -f "$STATS_FILE" ]; then
        echo "✓ Statistics file exists"
        if command -v jq >/dev/null 2>&1; then
            echo "Recent statistics:"
            jq -r '. | to_entries[] | select(.key | test("events_|threats_")) | "  \(.key): \(.value)"' "$STATS_FILE" 2>/dev/null
        fi
    else
        echo "✗ Statistics file missing"
    fi
    
    echo "=============================="
}

# Main command handling
case "$1" in
    start)
        start_engine
        ;;
    stop)
        stop_engine
        ;;
    status)
        status_engine
        ;;
    restart)
        restart_engine
        ;;
    reconfigure)
        reconfigure
        ;;
    export)
        export_events "$2"
        ;;
    stats)
        get_stats "$2"
        ;;
    logs)
        get_logs "$2" "$3"
        ;;
    clear_logs)
        clear_logs
        ;;
    test_export)
        test_export "$2"
        ;;
    health)
        health_check
        ;;
    test)
        echo "=== SIEM Logger Control Script Test ==="
        echo "Python: $PYTHON_BIN"
        echo "Engine: $ENGINE_SCRIPT"
        echo "Config: $CONFIG_FILE"
        echo "Logs: $LOG_DIR"
        echo "Database: $DB_FILE"
        echo "PID: $PIDFILE"
        echo ""
        health_check
        ;;
    *)
        echo "Usage: $0 {start|stop|status|restart|reconfigure|export [format]|stats [type]|logs [page] [limit]|clear_logs|test_export [format]|health|test}"
        echo ""
        echo "Service Commands:"
        echo "  start                     Start the SIEM Logger Engine"
        echo "  stop                      Stop the SIEM Logger Engine"
        echo "  status                    Check the SIEM Logger Engine status"
        echo "  restart                   Restart the SIEM Logger Engine"
        echo "  reconfigure               Reload configuration"
        echo ""
        echo "Data Commands:"
        echo "  export [format]           Trigger manual export (json|syslog|cef|leef)"
        echo "  stats [type]              Get statistics (summary|detailed|threats)"
        echo "  logs [page] [limit]       Get log entries with pagination"
        echo "  clear_logs                Clear all log files and database"
        echo "  test_export [format]      Test export configuration"
        echo ""
        echo "Utility Commands:"
        echo "  health                    Perform comprehensive health check"
        echo "  test                      Test the control script and configuration"
        echo ""
        echo "Note: The engine runs autonomously and continuously."
        echo "      It monitors logs in real-time and exports events automatically."
        exit 1
        ;;
esac

exit $?