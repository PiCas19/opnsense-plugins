#!/bin/sh
# SIEM Logger Clean Setup for OPNsense - VERSIONE CORRETTA

set -e

CONFIG_DIR="/usr/local/etc/siemlogger"
LOG_DIR="/var/log/siemlogger"
SCRIPTS_DIR="/usr/local/opnsense/scripts/OPNsense/SiemLogger"
DB_DIR="/var/db/siemlogger"
DB_FILE="${DB_DIR}/siemlogger.db"
CONFIG_FILE="/conf/config.xml"
PY="/usr/local/bin/python3.11"

echo "=============================================="
echo "SIEM Logger Clean Setup - VERSIONE CORRETTA"
echo "=============================================="

echo "[*] Creating directories..."
mkdir -p "$CONFIG_DIR" "$LOG_DIR" "$SCRIPTS_DIR" "$DB_DIR"

echo "[*] Creating empty log files..."
: > "${LOG_DIR}/events.log"
: > "${LOG_DIR}/audit.log"
: > "${LOG_DIR}/engine.log"
: > "${LOG_DIR}/export_events.log"
: > "${LOG_DIR}/health_check.log"

# CORREZIONE DATABASE - Backup e pulizia
if [ -f "$DB_FILE" ]; then
    echo "[*] Database esistente trovato - creando backup..."
    cp "$DB_FILE" "${DB_FILE}.backup.$(date +%Y%m%d_%H%M%S)"
    echo "[*] Backup creato: ${DB_FILE}.backup.$(date +%Y%m%d_%H%M%S)"
    
    echo "[*] Pulendo dati corrotti nel database esistente..."
    sqlite3 "$DB_FILE" << 'EOF'
-- Backup dei dati esistenti
CREATE TABLE IF NOT EXISTS events_backup AS SELECT * FROM events WHERE NOT EXISTS (SELECT 1 FROM events_backup);

-- CORREZIONE: Aggiornare source_ip vuoti a NULL
UPDATE events SET source_ip = NULL WHERE source_ip = '' OR source_ip = 'unknown';

-- CORREZIONE: Aggiornare user vuoti a NULL  
UPDATE events SET user = NULL WHERE user = 'unknown' OR user = '';

-- CORREZIONE: Pulire event_type unknown che non hanno senso
DELETE FROM events WHERE event_type = 'unknown' AND (description = 'System event' OR description = '');

-- Verificare le correzioni
.mode line
SELECT 'Records with NULL source_ip: ' || COUNT(*) as info FROM events WHERE source_ip IS NULL;
SELECT 'Records with NULL user: ' || COUNT(*) as info FROM events WHERE user IS NULL;
SELECT 'Records with valid source_ip: ' || COUNT(*) as info FROM events WHERE source_ip IS NOT NULL;
SELECT 'Records with valid user: ' || COUNT(*) as info FROM events WHERE user IS NOT NULL;
SELECT 'Total events after cleanup: ' || COUNT(*) as info FROM events;
EOF
    echo "[*] Database esistente pulito!"
else
    echo "[*] Nessun database esistente - ne verrà creato uno nuovo"
fi

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
            <log_sources>/var/log/system/latest.log</log_sources>
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

# INIZIALIZZAZIONE DATABASE CORRETTA
echo "[*] Inizializzando database con struttura corretta..."
sqlite3 "$DB_FILE" << 'EOF'
-- Creare tabelle se non esistono
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp INTEGER NOT NULL,
    source_ip TEXT,
    user TEXT,
    event_type TEXT NOT NULL,
    description TEXT,
    details TEXT,
    severity TEXT NOT NULL,
    source_log TEXT,
    country_code TEXT,
    processed INTEGER DEFAULT 0,
    exported INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS audit_trail (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp INTEGER NOT NULL,
    user TEXT,
    action TEXT,
    resource TEXT,
    result TEXT,
    details TEXT
);

-- Creare indici per performance
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_processed ON events(processed);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_trail(timestamp);

-- Configurazione database per performance
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA cache_size=10000;
EOF

echo "[*] Aggiungendo dati di test CORRETTI..."
CURRENT_TIME=$(date +%s)

# AGGIUNGERE EVENTI DI TEST CORRETTI AL DATABASE
sqlite3 "$DB_FILE" << EOF
-- Inserire eventi di test realistici con dati corretti
INSERT OR IGNORE INTO events (timestamp, source_ip, user, event_type, description, details, severity, source_log, country_code) VALUES
-- SSH Login con dati validi
(${CURRENT_TIME}, '192.168.1.100', 'admin', 'authentication', 'SSH login successful', '{"log_line": "sshd: Accepted publickey for admin from 192.168.1.100 port 22 ssh2", "country_code": "PR", "country_name": "Private"}', 'info', '/var/log/system/latest.log', 'PR'),

-- SSH Login fallito con IP esterno
(${CURRENT_TIME}, '203.0.113.50', 'hacker', 'authentication', 'SSH login failed', '{"log_line": "sshd: Failed password for invalid user hacker from 203.0.113.50 port 22 ssh2", "country_code": "US", "country_name": "United States"}', 'warning', '/var/log/system/latest.log', 'US'),

-- Web GUI Login
(${CURRENT_TIME}, '192.168.1.100', 'admin', 'authentication', 'Web GUI login successful', '{"log_line": "webgui: action=login user=admin src_ip=192.168.1.100 result=success", "country_code": "PR", "country_name": "Private"}', 'info', '/var/log/system/latest.log', 'PR'),

-- VPN Connection (no user, solo IP)
(${CURRENT_TIME}, '10.0.0.50', NULL, 'network', 'OpenVPN client connected', '{"log_line": "openvpn: client 10.0.0.50 connected from 203.0.113.100", "country_code": "PR", "country_name": "Private"}', 'info', '/var/log/system/latest.log', 'PR'),

-- Firewall Block (no user, solo IP)
(${CURRENT_TIME}, '203.0.113.200', NULL, 'firewall', 'Traffic blocked by firewall', '{"log_line": "filterlog: rule 10: block in on em0: 203.0.113.200 > 192.168.1.1", "country_code": "US", "country_name": "United States"}', 'warning', '/var/log/system/latest.log', 'US'),

-- Configuration Change (no IP, solo user)
(${CURRENT_TIME}, NULL, 'admin', 'configuration', 'Configuration change detected', '{"log_line": "configd: user=admin changed configuration", "country_code": "XX", "country_name": "Unknown"}', 'info', '/var/log/system/latest.log', 'XX'),

-- Authorization (no IP, solo user)
(${CURRENT_TIME}, NULL, 'admin', 'authorization', 'Sudo command executed: /bin/ls', '{"log_line": "sudo: user=admin command=/bin/ls", "command": "/bin/ls", "country_code": "XX", "country_name": "Unknown"}', 'info', '/var/log/system/latest.log', 'XX'),

-- System Event generico (no IP, no user)
(${CURRENT_TIME}, NULL, NULL, 'system', 'System startup completed', '{"log_line": "kernel: System startup completed", "country_code": "XX", "country_name": "Unknown"}', 'info', '/var/log/system/latest.log', 'XX');
EOF

# AGGIUNGERE EVENTI ANCHE AI FILE DI LOG (formato corretto)
echo "[*] Aggiungendo sample log entries ai file..."
cat >> "${LOG_DIR}/events.log" << EOF
{"timestamp": ${CURRENT_TIME}, "source_ip": "192.168.1.100", "user": "admin", "event_type": "authentication", "description": "SSH login successful", "details": "{\"log_line\": \"sshd: Accepted publickey for admin from 192.168.1.100 port 22 ssh2\"}", "severity": "info", "source_log": "/var/log/system/latest.log", "country_code": "PR"}
{"timestamp": ${CURRENT_TIME}, "source_ip": "203.0.113.50", "user": "hacker", "event_type": "authentication", "description": "SSH login failed", "details": "{\"log_line\": \"sshd: Failed password for hacker from 203.0.113.50\"}", "severity": "warning", "source_log": "/var/log/system/latest.log", "country_code": "US"}
{"timestamp": ${CURRENT_TIME}, "source_ip": "192.168.1.100", "user": "admin", "event_type": "authentication", "description": "Web GUI login successful", "details": "{\"log_line\": \"webgui: action=login user=admin result=success\"}", "severity": "info", "source_log": "/var/log/system/latest.log", "country_code": "PR"}
{"timestamp": ${CURRENT_TIME}, "source_ip": "10.0.0.50", "user": null, "event_type": "network", "description": "OpenVPN client connected", "details": "{\"log_line\": \"openvpn: client 10.0.0.50 connected\"}", "severity": "info", "source_log": "/var/log/system/latest.log", "country_code": "PR"}
{"timestamp": ${CURRENT_TIME}, "source_ip": null, "user": "admin", "event_type": "configuration", "description": "Configuration change detected", "details": "{\"log_line\": \"configd: user=admin changed configuration\"}", "severity": "info", "source_log": "/var/log/system/latest.log", "country_code": "XX"}
EOF

# Altri file di log
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

# VERIFICA FINALE DEL DATABASE
echo ""
echo "=============================================="
echo "VERIFICA DATABASE CORRETTI"
echo "=============================================="

sqlite3 "$DB_FILE" << 'EOF'
.mode column
.headers on

SELECT 'VERIFICA DATI CORRETTI' as test;
SELECT 
    'Total Events' as metric,
    COUNT(*) as value
FROM events
UNION ALL
SELECT 
    'Events with source_ip',
    COUNT(*)
FROM events 
WHERE source_ip IS NOT NULL
UNION ALL
SELECT 
    'Events with user',
    COUNT(*)
FROM events 
WHERE user IS NOT NULL
UNION ALL
SELECT 
    'Events with NULL source_ip (OK)',
    COUNT(*)
FROM events 
WHERE source_ip IS NULL
UNION ALL
SELECT 
    'Events with NULL user (OK)',
    COUNT(*)
FROM events 
WHERE user IS NULL;

SELECT '' as space;
SELECT 'ULTIMI EVENTI INSERITI' as test;
SELECT 
    datetime(timestamp, 'unixepoch') as time,
    COALESCE(source_ip, 'NULL') as source_ip,
    COALESCE(user, 'NULL') as user,
    event_type,
    description
FROM events 
ORDER BY timestamp DESC 
LIMIT 8;
EOF

echo ""
echo "=============================================="
echo "SIEM Logger Setup Complete - VERSIONE CORRETTA!"
echo "=============================================="
echo "Config:   $CONFIG_FILE"
echo "Logs:     $LOG_DIR"
echo "Scripts:  $SCRIPTS_DIR"
echo "Database: $DB_FILE"
echo ""
echo "✅ CORREZIONI APPLICATE:"
echo "  ✓ Database pulito da stringhe vuote"
echo "  ✓ Valori NULL impostati correttamente"
echo "  ✓ Eventi di test realistici con dati corretti"
echo "  ✓ JSON formato corretto nei log files"
echo "  ✓ Indici database per performance"
echo ""
echo "Sample Data inseriti correttamente:"
echo "  - 8 eventi nel database con mix di dati NULL/validi"
echo "  - 5 eventi JSON nel file events.log"
echo "  - File di log ausiliari popolati"
echo ""
echo "Test immediati:"
echo "sqlite3 $DB_FILE 'SELECT COUNT(*) as total FROM events;'"
echo "sqlite3 $DB_FILE \"SELECT COALESCE(source_ip,'NULL') as ip, COALESCE(user,'NULL') as user, event_type FROM events LIMIT 5;\""
echo ""
echo "Per avviare il motore:"
echo "cd $SCRIPTS_DIR && python3.11 siemlogger_engine.py"
echo ""
echo "Log file check:"
echo "ls -l $LOG_DIR"
echo "tail -5 ${LOG_DIR}/events.log"
echo "=============================================="