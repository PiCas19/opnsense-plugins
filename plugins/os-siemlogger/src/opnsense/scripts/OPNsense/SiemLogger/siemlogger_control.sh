#!/bin/sh

# SIEM Logger Control Script
# /usr/local/opnsense/scripts/OPNsense/SiemLogger/siemlogger_control.sh

PATH="/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin:$PATH"
export PATH

PYTHON_BIN="/usr/local/bin/python3.11"
ENGINE_SCRIPT="/usr/local/opnsense/scripts/OPNsense/SiemLogger/siemlogger_engine.py"
LOG_DIR="/var/log/siemlogger"
PIDFILE="/var/run/siemlogger.pid"
CONFIG_FILE="/usr/local/etc/siemlogger/config.json"

# Ensure directories exist
mkdir -p "$LOG_DIR" "/var/run"

# Function to log actions
log_action() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_DIR/service.log"
}

# Function to check if service is running
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

# Function to start the service
start_service() {
    if is_running; then
        PID=$(cat "$PIDFILE")
        echo "SIEM Logger is already running (PID $PID)"
        log_action "Service already running (PID $PID)"
        return 0
    fi

    # Check if enabled in config
    if [ -f "$CONFIG_FILE" ]; then
        if command -v jq >/dev/null 2>&1; then
            enabled=$(jq -r '.general.enabled' "$CONFIG_FILE" 2>/dev/null)
            [ "$enabled" = "false" ] && { echo "SIEM Logger is disabled in configuration"; log_action "Service disabled in config"; return 0; }
        else
            grep -q '"enabled".*:.*false' "$CONFIG_FILE" 2>/dev/null && { echo "SIEM Logger appears to be disabled in configuration"; log_action "Service disabled in config (no jq)"; return 0; }
        fi
    fi

    echo "Starting SIEM Logger service..."
    log_action "Starting service"

    "$PYTHON_BIN" "$ENGINE_SCRIPT" >> "$LOG_DIR/stdout.log" 2>> "$LOG_DIR/stderr.log" &
    echo $! > "$PIDFILE"

    sleep 2

    if is_running; then
        PID=$(cat "$PIDFILE")
        echo "SIEM Logger started successfully (PID $PID)"
        log_action "Service started successfully (PID $PID)"
        return 0
    else
        echo "Failed to start SIEM Logger"
        log_action "Failed to start service"
        rm -f "$PIDFILE"
        return 1
    fi
}

# Function to stop the service
stop_service() {
    if ! is_running; then
        echo "SIEM Logger is not running"
        log_action "Service not running"
        return 0
    fi

    echo "Stopping SIEM Logger service..."
    log_action "Stopping service"

    PID=$(cat "$PIDFILE")
    kill -TERM "$PID" 2>/dev/null

    TIMEOUT=15
    while [ $TIMEOUT -gt 0 ] && is_running; do
        sleep 1
        TIMEOUT=$((TIMEOUT - 1))
    done

    if is_running; then
        kill -KILL "$PID" 2>/dev/null
        sleep 2
        log_action "Service forcefully stopped"
    fi

    rm -f "$PIDFILE"
    echo "SIEM Logger stopped"
    log_action "Service stopped successfully"
    return 0
}

# Function to get service status
status_service() {
    if is_running; then
        PID=$(cat "$PIDFILE")
        echo "SIEM Logger is running (PID $PID)"
        if [ -f "$LOG_DIR/stats.json" ]; then
            if command -v jq >/dev/null 2>&1; then
                events=$(jq -r '.events_processed // 0' "$LOG_DIR/stats.json" 2>/dev/null)
                exported=$(jq -r '.events_exported // 0' "$LOG_DIR/stats.json" 2>/dev/null)
                [ -n "$events" ] && echo "Events processed: $events"
                [ -n "$exported" ] && echo "Events exported: $exported"
            else
                echo "Statistics file exists: $LOG_DIR/stats.json"
            fi
        fi
        return 0
    else
        echo "SIEM Logger is not running"
        return 1
    fi
}

# Function to export events
export_events() {
    format="${1:-json}"
    log_action "Starting event export in $format format"

    result=$("$PYTHON_BIN" "$ENGINE_SCRIPT" export "$format" 2>> "$LOG_DIR/stderr.log")
    if [ $? -eq 0 ]; then
        echo "$result"
        log_action "Event export completed successfully"
        return 0
    else
        echo "Failed to export events"
        log_action "Event export failed"
        return 1
    fi
}

# Function to get statistics
get_stats() {
    type="${1:-summary}"
    log_action "Retrieving statistics: $type"

    result=$("$PYTHON_BIN" "$ENGINE_SCRIPT" stats "$type" 2>> "$LOG_DIR/stderr.log")
    if [ $? -eq 0 ]; then
        echo "$result"
        log_action "Statistics retrieved successfully"
        return 0
    else
        echo "Failed to get statistics"
        log_action "Failed to retrieve statistics"
        return 1
    fi
}

# Function to get logs
get_logs() {
    page="${1:-1}"
    limit="${2:-50}"
    log_action "Retrieving logs (page $page, limit $limit)"

    result=$("$PYTHON_BIN" "$ENGINE_SCRIPT" logs "$page" "$limit" 2>> "$LOG_DIR/stderr.log")
    if [ $? -eq 0 ]; then
        echo "$result"
        log_action "Logs retrieved successfully"
        return 0
    else
        echo "Failed to get logs"
        log_action "Failed to retrieve logs"
        return 1
    fi
}

# Function to clear logs
clear_logs() {
    log_action "Clearing logs"

    for logfile in events.log audit.log engine.log export_events.log health_check.log stats.json stdout.log stderr.log export.log service.log; do
        [ -f "$LOG_DIR/$logfile" ] && > "$LOG_DIR/$logfile"
    done

    "$PYTHON_BIN" "$ENGINE_SCRIPT" clear_logs >> "$LOG_DIR/service.log" 2>&1

    log_action "Logs cleared successfully"
    echo "OK: Logs cleared"
    return 0
}

# Function to test export
test_export() {
    format="${1:-json}"
    log_action "Testing export in $format format"

    result=$("$PYTHON_BIN" "$ENGINE_SCRIPT" test_export "$format" 2>> "$LOG_DIR/stderr.log")
    if [ $? -eq 0 ]; then
        echo "$result"
        log_action "Export test completed successfully"
        return 0
    else
        echo "Export test failed"
        log_action "Export test failed"
        return 1
    fi
}

# Function to reconfigure
reconfigure() {
    stop_service
    sleep 2
    "$PYTHON_BIN" "$ENGINE_SCRIPT" configure >> "$LOG_DIR/service.log" 2>> "$LOG_DIR/stderr.log"
    start_service
}

# Main command handling
case "$1" in
    start)
        start_service
        ;;
    stop)
        stop_service
        ;;
    status)
        status_service
        ;;
    restart)
        stop_service
        sleep 2
        start_service
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
    test)
        echo "Testing SIEM Logger control script:"
        echo "Python: $PYTHON_BIN"
        echo "Engine: $ENGINE_SCRIPT"
        echo "Config: $CONFIG_FILE"
        echo "Logs: $LOG_DIR"
        echo "PID: $PIDFILE"
        [ -f "$ENGINE_SCRIPT" ] && echo "Engine script exists" || echo "Engine script missing!"
        "$PYTHON_BIN" "$ENGINE_SCRIPT" test 2>> "$LOG_DIR/stderr.log"
        ;;
    *)
        echo "Usage: $0 {start|stop|status|restart|reconfigure|export [format]|stats [type]|logs [page] [limit]|clear_logs|test_export [format]|test}"
        echo ""
        echo "Service Commands:"
        echo "  start                     Start the SIEM Logger service"
        echo "  stop                      Stop the SIEM Logger service"
        echo "  status                    Check the SIEM Logger service status"
        echo "  restart                   Restart the SIEM Logger service"
        echo "  reconfigure               Reconfigure and restart the service"
        echo ""
        echo "Data Commands:"
        echo "  export [format]           Export events (json|syslog|cef|leef)"
        echo "  stats [type]              Get statistics (summary|detailed|threats)"
        echo "  logs [page] [limit]       Get log entries with pagination"
        echo "  clear_logs                Clear all log files"
        echo "  test_export [format]      Test export configuration"
        echo ""
        echo "Utility:"
        echo "  test                      Test the control script and configuration"
        exit 1
        ;;
esac

exit $?