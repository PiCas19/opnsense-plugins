#!/bin/sh
# SIEM Logger Clean Setup for OPNsense

set -e

CONFIG_DIR="/usr/local/etc/siemlogger"
LOG_DIR="/var/log/siemlogger"
SCRIPTS_DIR="/usr/local/opnsense/scripts/OPNsense/SiemLogger"
DB_DIR="/var/db/siemlogger"
CONFIG_FILE="/conf/config.xml"
PY="/usr/local/bin/python3.11"

echo "=============================================="
echo "SIEM Logger Clean Setup"
echo "=============================================="

echo "[*] Creating directories..."
mkdir -p "$CONFIG_DIR" "$LOG_DIR" "$SCRIPTS_DIR" "$DB_DIR"

echo "[*] Creating empty log files..."
: > "${LOG_DIR}/events.log"
: > "${LOG_DIR}/audit.log"
: > "${LOG_DIR}/engine.log"
: > "${LOG_DIR}/export_events.log"
: > "${LOG_DIR}/health_check.log"

echo "[*] Checking and copying scripts (if needed)..."
for script in siemlogger_engine.py export_events.py health_check.py settings_logger.py siemlogger_control.sh; do
    if [ -f "${SCRIPTS_DIR}/$script" ]; then
        if [ -f "$script" ]; then
            if ! cmp -s "$script" "${SCRIPTS_DIR}/$script"; then
                cp "$script" "${SCRIPTS_DIR}/$script" || echo "[!] Warning: Failed to copy $script, proceeding anyway"
                chmod 755 "${SCRIPTS_DIR}/$script"
                echo "[*] $script updated in ${SCRIPTS_DIR}"
            else
                echo "[*] $script in ${SCRIPTS_DIR} is identical, skipping copy"
            fi
        else
            echo "[!] Warning: $script not found in current directory, skipping"
        fi
    else
        if [ -f "$script" ]; then
            cp "$script" "${SCRIPTS_DIR}/$script" || echo "[!] Warning: Failed to copy $script, proceeding anyway"
            chmod 755 "${SCRIPTS_DIR}/$script"
            echo "[*] $script copied to ${SCRIPTS_DIR}"
        else
            echo "[!] Warning: $script not found in current directory or ${SCRIPTS_DIR}, skipping"
        fi
    fi
done

echo "[*] Checking configuration file..."
if ! grep -q "<SiemLogger>" "$CONFIG_FILE"; then
    echo "[*] Adding default SIEM Logger configuration to $CONFIG_FILE..."
    cp "$CONFIG_FILE" "${CONFIG_FILE}.bak"
    cat << EOF >> "$CONFIG_FILE"
    <SiemLogger>
        <general>
            <enabled>1</enabled>
            <log_level>INFO</log_level>
            <max_log_size>100</max_log_size>
            <retention_days>30</retention_days>
        </general>
        <siem_export>
            <export_enabled>0</export_enabled>
            <export_format>json</export_format>
            <siem_server></siem_server>
            <siem_port>514</siem_port>
            <protocol>udp</protocol>
            <facility>local0</facility>
            <tls_cert></tls_cert>
            <batch_size>100</batch_size>
            <export_interval>60</export_interval>
        </siem_export>
        <logging_rules>
            <log_authentication>1</log_authentication>
            <log_authorization>1</log_authorization>
            <log_configuration_changes>1</log_configuration_changes>
            <log_network_events>1</log_network_events>
            <log_system_events>1</log_system_events>
            <log_firewall_events>1</log_firewall_events>
            <log_vpn_events>1</log_vpn_events>
            <custom_log_paths></custom_log_paths>
        </logging_rules>
        <audit_settings>
            <audit_enabled>1</audit_enabled>
            <audit_failed_logins>1</audit_failed_logins>
            <audit_admin_actions>1</audit_admin_actions>
            <audit_privilege_escalation>1</audit_privilege_escalation>
            <audit_file_access>0</audit_file_access>
            <suspicious_activity_threshold>5</suspicious_activity_threshold>
        </audit_settings>
        <notifications>
            <email_alerts>0</email_alerts>
            <email_recipients></email_recipients>
            <alert_on_failed_logins>1</alert_on_failed_logins>
            <alert_on_suspicious_activity>1</alert_on_suspicious_activity>
            <webhook_url></webhook_url>
        </notifications>
        <monitoring>
            <health_check_interval>300</health_check_interval>
            <metrics_collection>1</metrics_collection>
            <performance_monitoring>1</performance_monitoring>
            <disk_usage_threshold>80</disk_usage_threshold>
        </monitoring>
    </SiemLogger>
EOF
else
    echo "[*] SIEM Logger configuration already exists in $CONFIG_FILE"
fi

echo "[*] Adding sample log entries..."
CURRENT_TIME=$(date +%s)
# Formato compatibile con parse_system_log
echo "${CURRENT_TIME} sshd: Accepted publickey for admin from 192.168.1.100 port 12345 ssh2" >> "${LOG_DIR}/events.log"
echo "${CURRENT_TIME} webgui: action=login user=admin src_ip=192.168.1.100 result=success" >> "${LOG_DIR}/events.log"
echo "${CURRENT_TIME} openvpn: client 10.0.0.2 connected" >> "${LOG_DIR}/events.log"
echo "${CURRENT_TIME} filterlog: src=192.168.1.200 blocked" >> "${LOG_DIR}/events.log"
echo "${CURRENT_TIME} configd: user=admin changed configuration" >> "${LOG_DIR}/events.log"
echo "${CURRENT_TIME} sudo: user=admin command=/bin/sh" >> "${LOG_DIR}/audit.log"
echo "${CURRENT_TIME} Started export_events.py" >> "${LOG_DIR}/export_events.log"
echo "${CURRENT_TIME} Health check completed: disk_usage=10%" >> "${LOG_DIR}/health_check.log"
echo "${CURRENT_TIME} SiemLogger Engine started" >> "${LOG_DIR}/engine.log"

echo "[*] Installing Python dependencies..."
pkg install -y py311-sqlite3 py311-requests py311-psutil || echo "[!] Warning: Some packages may already be installed"
echo "[*] Optional: Install GeoIP2 support with 'pkg install py311-geoip2'"

echo "[*] Setting permissions..."
chown -R root:wheel "$CONFIG_DIR" "$LOG_DIR" "$SCRIPTS_DIR" "$DB_DIR"
chmod -R 755 "$CONFIG_DIR" "$SCRIPTS_DIR"
chmod -R 644 "$LOG_DIR"/*.log
chmod 644 "$DB_DIR"/*.db 2>/dev/null || true

echo ""
echo "=============================================="
echo "SIEM Logger Setup Complete!"
echo "=============================================="
echo "Config:   $CONFIG_FILE"
echo "Logs:     $LOG_DIR"
echo "Scripts:  $SCRIPTS_DIR"
echo "Database: $DB_DIR"
echo ""
echo "Sample Log Entries Inserted:"
echo "  - events.log: 5 entries (authentication, webgui, vpn, firewall, configuration)"
echo "  - audit.log: 1 entry (authorization)"
echo "  - engine.log: 1 entry"
echo "  - export_events.log: 1 entry"
echo "  - health_check.log: 1 entry"
echo ""
echo "Test the setup:"
echo "configctl siemlogger test"
echo "configctl siemlogger get_stats"
echo "configctl siemlogger get_logs 1 10"
echo ""
echo "Log file check:"
echo "ls -l $LOG_DIR"
echo "=============================================="