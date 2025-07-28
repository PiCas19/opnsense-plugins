#!/bin/sh

# SIEM Logger Control Script
# /usr/local/opnsense/scripts/OPNsense/SiemLogger/siemlogger_control.sh

PATH="/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin:$PATH"
export PATH

PYTHON_BIN="python3.11"
SCRIPTS_DIR="/usr/local/opnsense/scripts/OPNsense/SiemLogger"
LOG_DIR="/var/log/siemlogger"

# Ensure directories exist
mkdir -p $LOG_DIR

# Function to log actions
log_action() {
    echo "$(date): $1" >> $LOG_DIR/control.log
}

case "$1" in
    start)
        echo "Starting SIEM Logger service..."
        $PYTHON_BIN "$SCRIPTS_DIR/export_events.py" > $LOG_DIR/export_events.log 2>&1 &
        echo $! > /var/run/siemlogger.pid
        $PYTHON_BIN "$SCRIPTS_DIR/audit_monitor.py" > $LOG_DIR/audit_monitor.log 2>&1 &
        echo $! >> /var/run/siemlogger.pid
        $PYTHON_BIN "$SCRIPTS_DIR/health_check.py" > $LOG_DIR/health_check.log 2>&1 &
        echo $! >> /var/run/siemlogger.pid
        log_action "SIEM Logger service started"
        echo "OK: SIEM Logger service started"
        ;;
    stop)
        echo "Stopping SIEM Logger service..."
        if [ -f /var/run/siemlogger.pid ]; then
            while read -r pid; do
                kill $pid 2>/dev/null
            done < /var/run/siemlogger.pid
            rm -f /var/run/siemlogger.pid
            log_action "SIEM Logger service stopped"
            echo "OK: SIEM Logger service stopped"
        else
            log_action "No PID file found for SIEM Logger"
            echo "ERROR: No PID file found. Is SIEM Logger running?"
            exit 1
        fi
        ;;
    status)
        if [ -f /var/run/siemlogger.pid ]; then
            running=false
            while read -r pid; do
                if ps -p $pid > /dev/null; then
                    echo "SIEM Logger service is running with PID $pid"
                    running=true
                fi
            done < /var/run/siemlogger.pid
            if [ "$running" = false ]; then
                echo "SIEM Logger PID file exists but processes are not running"
                exit 1
            fi
        else
            echo "SIEM Logger service is not running"
            exit 1
        fi
        ;;
    restart)
        $0 stop
        sleep 1
        $0 start
        log_action "SIEM Logger service restarted"
        echo "OK: SIEM Logger service restarted"
        ;;
    reconfigure)
        $0 stop
        $PYTHON_BIN "$SCRIPTS_DIR/export_events.py" configure
        sleep 1
        $0 start
        log_action "SIEM Logger service reconfigured"
        echo "OK: SIEM Logger service reconfigured"
        ;;
    export_events)
        FORMAT="${2:-json}"
        result=$($PYTHON_BIN "$SCRIPTS_DIR/export_events.py" export "$FORMAT" 2>&1)
        if [ $? -eq 0 ]; then
            log_action "Exported events in $FORMAT format"
            echo "$result"
        else
            log_action "Failed to export events: $result"
            echo "ERROR: $result"
            exit 1
        fi
        ;;
    get_stats)
        TYPE="${2:-all}"
        result=$($PYTHON_BIN "$SCRIPTS_DIR/health_check.py" stats "$TYPE" 2>&1)
        if [ $? -eq 0 ]; then
            echo "$result"
        else
            echo '{"status": "error", "message": "Failed to retrieve statistics", "data": {}}'
            exit 1
        fi
        ;;
    get_logs)
        PAGE="${2:-1}"
        LIMIT="${3:-100}"
        result=$($PYTHON_BIN "$SCRIPTS_DIR/export_events.py" get_logs "$PAGE" "$LIMIT" 2>&1)
        if [ $? -eq 0 ]; then
            echo "$result"
        else
            echo '{"status": "error", "message": "Failed to retrieve logs", "data": []}'
            exit 1
        fi
        ;;
    clear_logs)
        for logfile in siemlogger.log export_events.log audit_monitor.log health_check.log control.log; do
            if [ -f "$LOG_DIR/$logfile" ]; then
                > "$LOG_DIR/$logfile"
            fi
        done
        log_action "SIEM Logger logs cleared"
        echo "OK: SIEM Logger logs cleared"
        ;;
    test_export)
        FORMAT="${2:-json}"
        result=$($PYTHON_BIN "$SCRIPTS_DIR/export_events.py" test "$FORMAT" 2>&1)
        if [ $? -eq 0 ]; then
            log_action "Tested SIEM export in $FORMAT format"
            echo "$result"
        else
            log_action "Failed to test SIEM export: $result"
            echo "ERROR: $result"
            exit 1
        fi
        ;;
    test)
        echo "Testing SIEM Logger control script..."
        echo "PATH: $PATH"
        echo "Python: $PYTHON_BIN"
        echo "Scripts directory: $SCRIPTS_DIR"
        echo "Log directory: $LOG_DIR"
        echo ""
        echo "Available Python scripts:"
        ls -la "$SCRIPTS_DIR"/*.py 2>/dev/null || echo "No Python scripts found"
        echo ""
        echo "Testing configuration..."
        result=$($PYTHON_BIN "$SCRIPTS_DIR/export_events.py" test_config 2>&1)
        if [ $? -eq 0 ]; then
            echo "Configuration test: OK"
        else
            echo "Configuration test: ERROR - $result"
        fi
        echo "Test complete"
        ;;
    *)
        echo "Usage: $0 {start|stop|status|restart|reconfigure|export_events|get_stats|get_logs|clear_logs|test_export|test}"
        echo ""
        echo "Service Commands:"
        echo "  start                     Start the SIEM Logger service"
        echo "  stop                      Stop the SIEM Logger service"
        echo "  status                    Check the SIEM Logger service status"
        echo "  restart                   Restart the SIEM Logger service"
        echo "  reconfigure               Reconfigure and restart the SIEM Logger service"
        echo ""
        echo "Event and Log Management:"
        echo "  export_events [format]    Export events to SIEM in specified format (json, syslog, cef, leef)"
        echo "  get_stats [type]          Get statistics (all, disk, events, audit)"
        echo "  get_logs [page] [limit]   Get log entries with pagination"
        echo "  clear_logs                Clear all SIEM Logger logs"
        echo "  test_export [format]      Test SIEM export configuration"
        echo ""
        echo "Utility:"
        echo "  test                      Test the control script and configuration"
        exit 1
        ;;
esac

exit 0