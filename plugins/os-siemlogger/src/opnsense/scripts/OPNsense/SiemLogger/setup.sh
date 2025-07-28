#!/bin/sh
# SIEM Logger Clean Setup for OPNsense

set -e

CONFIG_DIR="/usr/local/etc/siemlogger"
LOG_DIR="/var/log/siemlogger"
SCRIPTS_DIR="/usr/local/opnsense/scripts/OPNsense/SiemLogger"
PY="/usr/local/bin/python3.11"
CONFIG_FILE="${CONFIG_DIR}/config.json"

echo "=============================================="
echo "SIEM Logger Clean Setup"
echo "=============================================="

echo "[*] Creating directories..."
mkdir -p "$CONFIG_DIR" "$LOG_DIR" "$SCRIPTS_DIR"

echo "[*] Creating empty log files..."
: > "${LOG_DIR}/siemlogger.log"
: > "${LOG_DIR}/export_events.log"
: > "${LOG_DIR}/audit_monitor.log"
: > "${LOG_DIR}/health_check.log"
: > "${LOG_DIR}/control.log"

echo "[*] Creating default configuration..."
cat << EOF > "${CONFIG_FILE}"
{
    "general": {
        "enabled": true,
        "log_level": "info"
    },
    "siem_export": {
        "export_enabled": false,
        "siem_server": "",
        "siem_port": 514,
        "protocol": "udp",
        "export_format": "json",
        "facility": "local0"
    },
    "logging_rules": {
        "log_authentication": true,
        "log_network_events": true,
        "log_firewall_events": true,
        "log_system_events": true
    },
    "audit_settings": {
        "audit_enabled": true
    },
    "notifications": {
        "email_alerts": false,
        "email_recipients": "",
        "webhook_url": "",
        "alert_on_failed_export": true
    },
    "monitoring": {
        "metrics_collection": true,
        "health_check_interval": 300,
        "disk_usage_threshold": 80
    }
}
EOF

echo "[*] Adding sample log entries..."
CURRENT_TIME=$(date +%s)
echo "$(date): Sample authentication event: Login attempt by admin" >> "${LOG_DIR}/siemlogger.log"
echo "$(date -r $((CURRENT_TIME - 3600))): Sample network event: Unusual traffic detected" >> "${LOG_DIR}/siemlogger.log"
echo "$(date -r $((CURRENT_TIME - 7200))): Sample firewall event: Blocked port scan" >> "${LOG_DIR}/siemlogger.log"
echo "$(date): Started export_events.py" >> "${LOG_DIR}/export_events.log"
echo "$(date): Started audit_monitor.py" >> "${LOG_DIR}/audit_monitor.log"
echo "$(date): Health check completed: disk_usage=10%" >> "${LOG_DIR}/health_check.log"
echo "$(date): Control script initialized" >> "${LOG_DIR}/control.log"

echo "[*] Installing Python dependencies..."
$PY -m pip install -q psutil requests || echo "[!] pip install errors ignored"

echo "[*] Setting permissions..."
chown -R root:wheel "$CONFIG_DIR" "$LOG_DIR" "$SCRIPTS_DIR"
chmod -R 755 "$CONFIG_DIR" "$LOG_DIR" "$SCRIPTS_DIR"
chmod 644 "$CONFIG_DIR"/*.json 2>/dev/null || true
chmod 644 "$LOG_DIR"/*.log 2>/dev/null || true

echo ""
echo "=============================================="
echo "SIEM Logger Setup Complete!"
echo "=============================================="
echo "Config:   $CONFIG_DIR"
echo "Logs:     $LOG_DIR"
echo "Scripts:  $SCRIPTS_DIR"
echo ""
echo "Sample Log Entries Inserted:"
echo "  - siemlogger.log: 3 entries (authentication, network, firewall)"
echo "  - export_events.log: 1 entry"
echo "  - audit_monitor.log: 1 entry"
echo "  - health_check.log: 1 entry"
echo "  - control.log: 1 entry"
echo ""
echo "Test the setup:"
echo "configctl siemlogger get_stats"
echo "configctl siemlogger get_logs 1 10"
echo ""
echo "Log file check:"
echo "ls -l $LOG_DIR"
echo "=============================================="