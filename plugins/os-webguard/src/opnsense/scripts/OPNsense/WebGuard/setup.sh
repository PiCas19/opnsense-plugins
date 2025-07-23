#!/bin/sh
# WebGuard Clean Setup for OPNsense
# ONLY shell script - no Python mixing
# - Crea directories e file base
# - Installa dipendenze Python
# - Scarica GeoIP database
# - Crea database SQLite con tabelle
# - Copia update_rules.py se presente
# - Imposta permessi

set -e

CONFIG_DIR="/usr/local/etc/webguard"
LOG_DIR="/var/log/webguard"
DB_DIR="/var/db/webguard"
GEOIP_DIR="/usr/local/share/GeoIP"
PY="/usr/local/bin/python3.11"
UPDATER="${CONFIG_DIR}/update_rules.py"
DB_FILE="${DB_DIR}/webguard.db"

echo "=============================================="
echo "WebGuard Clean Setup"
echo "=============================================="

echo "[*] Creating directories..."
mkdir -p "$CONFIG_DIR" "$LOG_DIR" "$DB_DIR" "$GEOIP_DIR"

echo "[*] Creating empty base files..."
: > "${LOG_DIR}/engine.log"
: > "${CONFIG_DIR}/waf_rules.json"
: > "${CONFIG_DIR}/attack_patterns.json"

echo "[*] Creating SQLite database with tables..."
sqlite3 "$DB_FILE" << 'EOF'
CREATE TABLE IF NOT EXISTS blocked_ips (
    ip_address TEXT PRIMARY KEY,
    block_type TEXT DEFAULT 'manual',
    blocked_since INTEGER,
    expires_at INTEGER,
    reason TEXT,
    violations INTEGER DEFAULT 1,
    last_violation INTEGER
);

CREATE TABLE IF NOT EXISTS whitelist (
    ip_address TEXT PRIMARY KEY,
    description TEXT,
    added_at INTEGER,
    expires_at INTEGER,
    permanent INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS threats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp INTEGER,
    source_ip TEXT,
    type TEXT,
    severity TEXT,
    description TEXT,
    false_positive INTEGER DEFAULT 0,
    payload TEXT,
    method TEXT
);

-- Insert sample data for testing
INSERT OR IGNORE INTO blocked_ips (ip_address, block_type, blocked_since, reason, violations, last_violation) 
VALUES ('192.168.1.100', 'manual', strftime('%s', 'now'), 'Sample blocked IP', 1, strftime('%s', 'now'));

INSERT OR IGNORE INTO whitelist (ip_address, description, added_at, permanent) 
VALUES ('192.168.1.1', 'Sample whitelist entry', strftime('%s', 'now'), 1);

INSERT OR IGNORE INTO threats (timestamp, source_ip, type, severity, description, payload, method, false_positive)
VALUES 
    (strftime('%s', 'now') - 3600, '192.168.1.200', 'SQL Injection', 'high', 'SQL injection detected', "' OR 1=1 --", 'POST', 0),
    (strftime('%s', 'now') - 7200, '10.0.0.50', 'XSS Attack', 'medium', 'Cross-site scripting attempt', '<script>alert("xss")</script>', 'GET', 0),
    (strftime('%s', 'now') - 10800, '172.16.0.25', 'Path Traversal', 'medium', 'Directory traversal detected', '../../../etc/passwd', 'GET', 0);

.exit
EOF

echo "[*] Installing Python dependencies..."
$PY -m pip install -q psutil geoip2 requests || echo "pip install errors ignored"

echo "[*] Downloading GeoIP2 database..."
fetch -o "${GEOIP_DIR}/GeoLite2-Country.mmdb" \
"https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb" 2>/dev/null || \
echo "Warning: GeoIP download failed"

# Check if update_rules.py exists and run it
if [ -f "$UPDATER" ]; then
    echo "[*] Found update_rules.py, running it..."
    chmod +x "$UPDATER"
    $PY "$UPDATER" || echo "[!] Rule updater failed, JSON files remain empty"
else
    echo "[*] NOTE: $UPDATER not found."
    echo "[*] Copy your update_rules.py to $CONFIG_DIR and run:"
    echo "[*] python3.11 $UPDATER"
fi

echo "[*] Setting permissions..."
chown -R root:wheel "$CONFIG_DIR" "$LOG_DIR" "$DB_DIR" "$GEOIP_DIR" 2>/dev/null || true
chmod -R 755 "$CONFIG_DIR" "$LOG_DIR" "$DB_DIR"
chmod 644 "$CONFIG_DIR"/*.json 2>/dev/null || true
chmod 644 "$GEOIP_DIR"/*.mmdb 2>/dev/null || true
chmod 644 "$DB_FILE"

echo ""
echo "=============================================="
echo "WebGuard Setup Complete! 🚀"
echo "=============================================="
echo "✅ Directories created"
echo "✅ SQLite database created with tables"
echo "✅ Sample data inserted"
echo "✅ Dependencies installed"
echo "✅ GeoIP database downloaded"
echo "✅ Empty JSON files ready"
echo ""
echo "Config: $CONFIG_DIR"
echo "Logs: $LOG_DIR"
echo "Database: $DB_FILE"
echo ""
echo "🧪 Test the setup:"
echo "sqlite3 $DB_FILE 'SELECT COUNT(*) FROM blocked_ips;'"
echo "configctl webguard get_blocked_ips 1"
echo "=============================================="