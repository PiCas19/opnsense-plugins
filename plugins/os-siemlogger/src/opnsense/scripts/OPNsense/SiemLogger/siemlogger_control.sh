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
        fi
    fi
    return 1
}

# Function to start the service
start_service() {
    if is_running; then
        echo "SIEM Logger is already running (PID $(cat "$PIDFILE"))"
        return 0
    fi

    # Check if enabled in config
    if [ -f "$CONFIG_FILE" ]; then
        enabled=$(jq -r '.general.enabled' "$CONFIG_FILE" 2>/dev/null)
        if [ "$enabled" = "false" ]; then
            echo "SIEM Logger is disabled in configuration"
            return 0
        fi
    fi

    echo "Starting SIEM Logger service..."
    log_action "Starting service"

    # Start the engine in background
    "$PYTHON_BIN" "$ENGINE_SCRIPT" >> "$LOG_DIR/stdout.log" 2>> "$LOG_DIR/stderr.log" &
    echo $! > "$PIDFILE"

    sleep 2  # Give it time to start

    if is_running; then
        echo "SIEM Logger started successfully (PID $(cat "$PIDFILE"))"
        log_action "Service started successfully with PID $(cat "$PIDFILE")"
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
        return 0
    fi

    echo "Stopping SIEM Logger service..."
    log_action "Stopping service"

    PID=$(cat "$PIDFILE")
    kill -TERM "$PID" 2>/dev/null

    # Wait for graceful shutdown
    TIMEOUT=15
    while [ $TIMEOUT -gt 0 ] && is_running; do
        sleep 1
        TIMEOUT=$((TIMEOUT - 1))
    done

    if is_running; then
        kill -KILL "$PID" 2>/dev/null
        sleep 2
        log_action "Service was forcefully stopped"
    fi

    if ! is_running; then
        rm -f "$PIDFILE"
        echo "SIEM Logger stopped"
        log_action "Service stopped successfully"
        return 0
    else
        echo "Failed to stop SIEM Logger"
        log_action "Failed to stop service"
        return 1
    fi
}

# Function to get service status
status_service() {
    if is_running; then
        PID=$(cat "$PIDFILE")
        echo "SIEM Logger is running (PID $PID)"
        
        # Get additional status info if available
        if [ -f "$LOG_DIR/stats.json" ]; then
            events=$(jq -r '.events_processed // 0' "$LOG_DIR/stats.json" 2>/dev/null)
            threats=$(jq -r '.threats_detected // 0' "$LOG_DIR/stats.json" 2>/dev/null)
            [ -n "$events" ] && echo "Events processed: $events"
            [ -n "$threats" ] && echo "Threats detected: $threats"
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
    
    "$PYTHON_BIN" "$ENGINE_SCRIPT" export "$format" >> "$LOG_DIR/export.log" 2>&1
    result=$?
    
    if [ $result -eq 0 ]; then
        echo "Events exported successfully in $format format"
        log_action "Event export completed successfully"
        return 0
    else
        echo "Failed to export events (code $result)"
        log_action "Event export failed with code $result"
        return $result
    fi
}

# Function to get statistics
get_stats() {
    type="${1:-summary}"
    log_action "Retrieving statistics: $type"
    
    stats=$("$PYTHON_BIN" "$ENGINE_SCRIPT" stats "$type" 2>&1)
    result=$?
    
    if [ $result -eq 0 ]; then
        echo "$stats"
        log_action "Statistics retrieved successfully"
        return 0
    else
        echo "Failed to get statistics (code $result)"
        echo "$stats"
        log_action "Failed to retrieve statistics"
        return $result
    fi
}

# Function to get logs
get_logs() {
    page="${1:-1}"
    limit="${2:-50}"
    log_action "Retrieving logs (page $page, limit $limit)"
    
    logs=$("$PYTHON_BIN" "$ENGINE_SCRIPT" logs "$page" "$limit" 2>&1)
    result=$?
    
    if [ $result -eq 0 ]; then
        echo "$logs"
        log_action "Logs retrieved successfully"
        return 0
    else
        echo "Failed to get logs (code $result)"
        echo "$logs"
        log_action "Failed to retrieve logs"
        return $result
    fi
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
        stop_service
        sleep 2
        "$PYTHON_BIN" "$ENGINE_SCRIPT" configure
        start_service
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
    test)
        echo "Testing SIEM Logger control script:"
        echo "Python: $PYTHON_BIN"
        echo "Engine: $ENGINE_SCRIPT"
        echo "Config: $CONFIG_FILE"
        echo "Logs: $LOG_DIR"
        echo "PID: $PIDFILE"
        
        if [ -f "$ENGINE_SCRIPT" ]; then
            echo "Engine script exists"
            "$PYTHON_BIN" "$ENGINE_SCRIPT" test
        else
            echo "Engine script missing!"
        fi
        ;;
    *)
        echo "Usage: $0 {start|stop|status|restart|reconfigure|export [format]|stats [type]|logs [page] [limit]|test}"
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
        echo ""
        echo "Utility:"
        echo "  test                      Test the control script and configuration"
        exit 1
        ;;
esac

exit $?