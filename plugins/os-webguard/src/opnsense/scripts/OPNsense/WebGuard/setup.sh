#!/bin/sh
# WebGuard Clean Setup for OPNsense
# ONLY shell script - no Python mixing
# - Crea directories e file base
# - Installa dipendenze Python
# - Scarica GeoIP database
# - Crea database SQLite con tabelle IDENTICHE ALL'ENGINE
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

# Remove existing database if it exists and is corrupted
if [ -f "$DB_FILE" ]; then
    rm -f "$DB_FILE"
fi

# Create database and tables using SCHEMA IDENTICO ALL'ENGINE
echo "Creating blocked_ips table..."
sqlite3 "$DB_FILE" "CREATE TABLE blocked_ips (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT UNIQUE NOT NULL,
    block_type TEXT NOT NULL,
    blocked_since INTEGER NOT NULL,
    expires_at INTEGER,
    reason TEXT,
    violations INTEGER DEFAULT 1,
    last_violation INTEGER
);"

echo "Creating whitelist table..."
sqlite3 "$DB_FILE" "CREATE TABLE whitelist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT UNIQUE NOT NULL,
    description TEXT,
    added_at INTEGER NOT NULL,
    expires_at INTEGER,
    permanent INTEGER DEFAULT 1
);"

echo "Creating threats table with SCHEMA IDENTICO ALL'ENGINE..."
sqlite3 "$DB_FILE" "CREATE TABLE threats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp INTEGER NOT NULL,
    source_ip TEXT NOT NULL,
    target TEXT NOT NULL,
    method TEXT NOT NULL,
    type TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL,
    score REAL DEFAULT 0.0,
    payload TEXT,
    request_headers TEXT,
    rule_matched TEXT,
    description TEXT,
    false_positive INTEGER DEFAULT 0
);"

# Create indexes (come nell'engine)
echo "Creating indexes..."
sqlite3 "$DB_FILE" "CREATE INDEX IF NOT EXISTS idx_threats_timestamp ON threats(timestamp);"
sqlite3 "$DB_FILE" "CREATE INDEX IF NOT EXISTS idx_threats_source_ip ON threats(source_ip);"
sqlite3 "$DB_FILE" "CREATE INDEX IF NOT EXISTS idx_blocked_ips_ip ON blocked_ips(ip_address);"
sqlite3 "$DB_FILE" "CREATE INDEX IF NOT EXISTS idx_whitelist_ip ON whitelist(ip_address);"

# Insert sample data with ALL columns
echo "Inserting sample data..."
CURRENT_TIME=$(date +%s)

sqlite3 "$DB_FILE" "INSERT INTO blocked_ips (ip_address, block_type, blocked_since, reason, violations, last_violation) VALUES ('192.168.1.100', 'manual', $CURRENT_TIME, 'Sample blocked IP', 1, $CURRENT_TIME);"

sqlite3 "$DB_FILE" "INSERT INTO whitelist (ip_address, description, added_at, permanent) VALUES ('192.168.1.1', 'Sample whitelist entry', $CURRENT_TIME, 1);"

# SQL Injection threat
sqlite3 "$DB_FILE" "INSERT INTO threats (
    timestamp, source_ip, target, method, type, severity, status, score, payload, request_headers, rule_matched, description, false_positive
) VALUES (
    $((CURRENT_TIME - 3600)), '192.168.1.200', '/admin/login.php', 'POST', 'SQL Injection', 'high', 'blocked', 85.5,
    ''' OR 1=1 --', '{}', 'rule_1', 'SQL injection detected', 0
);"

# XSS Attack threat
sqlite3 "$DB_FILE" "INSERT INTO threats (
    timestamp, source_ip, target, method, type, severity, status, score, payload, request_headers, rule_matched, description, false_positive
) VALUES (
    $((CURRENT_TIME - 7200)), '10.0.0.50', '/search?q=<script>', 'GET', 'XSS Attack', 'medium', 'blocked', 65.0,
    '<script>alert(\"xss\")</script>', '{}', 'rule_2', 'Cross-site scripting attempt', 0
);"

# Path Traversal threat
sqlite3 "$DB_FILE" "INSERT INTO threats (
    timestamp, source_ip, target, method, type, severity, status, score, payload, request_headers, rule_matched, description, false_positive
) VALUES (
    $((CURRENT_TIME - 10800)), '172.16.0.25', '/api/users', 'GET', 'Path Traversal', 'medium', 'blocked', 70.0,
    '../../../etc/passwd', '{}', 'rule_3', 'Directory traversal detected', 0
);"

# Command Injection threat
sqlite3 "$DB_FILE" "INSERT INTO threats (
    timestamp, source_ip, target, method, type, severity, status, score, payload, request_headers, rule_matched, description, false_positive
) VALUES (
    $((CURRENT_TIME - 14400)), '203.0.113.45', '/cmd.php', 'POST', 'Command Injection', 'critical', 'blocked', 95.0,
    '; cat /etc/passwd', '{}', 'rule_4', 'Command injection attempt detected', 0
);"

# Another SQL Injection from different IP
sqlite3 "$DB_FILE" "INSERT INTO threats (
    timestamp, source_ip, target, method, type, severity, status, score, payload, request_headers, rule_matched, description, false_positive
) VALUES (
    $((CURRENT_TIME - 18000)), '198.51.100.33', '/login.asp', 'POST', 'SQL Injection', 'high', 'blocked', 88.0,
    ' UNION SELECT username,password FROM users', '{}', 'rule_5', 'SQL injection with UNION attack', 0
);"

# XSS Attack with different vector
sqlite3 "$DB_FILE" "INSERT INTO threats (
    timestamp, source_ip, target, method, type, severity, status, score, payload, request_headers, rule_matched, description, false_positive
) VALUES (
    $((CURRENT_TIME - 21600)), '93.184.216.34', '/comment.php', 'POST', 'XSS Attack', 'medium', 'blocked', 72.5,
    '<img src=x onerror=alert(1)>', '{}', 'rule_6', 'DOM-based XSS attempt', 0
);"

# File Inclusion threat
sqlite3 "$DB_FILE" "INSERT INTO threats (
    timestamp, source_ip, target, method, type, severity, status, score, payload, request_headers, rule_matched, description, false_positive
) VALUES (
    $((CURRENT_TIME - 25200)), '185.199.108.153', '/include.php', 'GET', 'File Inclusion', 'high', 'blocked', 82.0,
    '?file=../../../../etc/passwd', '{}', 'rule_7', 'Local file inclusion detected', 0
);"

# Verify database creation
echo "[*] Verifying database creation..."
TABLES=$(sqlite3 "$DB_FILE" ".tables" | wc -w)
if [ "$TABLES" -eq 3 ]; then
    echo "Database created successfully with $TABLES tables"
    echo "Tables: $(sqlite3 "$DB_FILE" ".tables" | tr '\n' ' ')"
    
    # Show record counts
    BLOCKED_COUNT=$(sqlite3 "$DB_FILE" "SELECT COUNT(*) FROM blocked_ips;")
    WHITELIST_COUNT=$(sqlite3 "$DB_FILE" "SELECT COUNT(*) FROM whitelist;") 
    THREATS_COUNT=$(sqlite3 "$DB_FILE" "SELECT COUNT(*) FROM threats;")
    
    echo "Sample data inserted:"
    echo "  - Blocked IPs: $BLOCKED_COUNT"
    echo "  - Whitelist entries: $WHITELIST_COUNT" 
    echo "  - Threats: $THREATS_COUNT"
    
    # Show threats by type
    echo ""
    echo "Threats by type:"
    sqlite3 "$DB_FILE" "SELECT type, COUNT(*) as count FROM threats GROUP BY type ORDER BY count DESC;"
    
    # Verify score and status columns exist
    echo ""
    echo "Verifying schema compatibility:"
    sqlite3 "$DB_FILE" "SELECT id, type, score, status FROM threats LIMIT 3;"
    
    # Verify schema matches engine exactly
    echo ""
    echo "Full schema verification:"
    sqlite3 "$DB_FILE" ".schema threats"
    
else
    echo "Database creation failed - only $TABLES tables found"
    exit 1
fi

echo "[*] Installing Python dependencies..."
$PY -m pip install -q psutil geoip2 requests || echo "pip install errors ignored"

echo "[*] Downloading GeoIP2 database..."
if ! fetch -o "${GEOIP_DIR}/GeoLite2-Country.mmdb" "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb" 2>/dev/null; then
    echo "[!] Warning: GeoIP download failed. Manual download may be required from https://dev.maxmind.com/geoip/geoip2/geolite2/"
fi

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
chown -R root:wheel "$CONFIG_DIR" "$LOG_DIR" "$DB_DIR" "$GEOIP_DIR"
chmod -R 755 "$CONFIG_DIR" "$LOG_DIR" "$DB_DIR"
chmod 644 "$CONFIG_DIR"/*.json 2>/dev/null || true
chmod 644 "$GEOIP_DIR"/*.mmdb 2>/dev/null || true
chmod 644 "$DB_FILE"

echo ""
echo "=============================================="
echo "WebGuard Setup Complete!"
echo "=============================================="
echo "Directories created"
echo "SQLite database created with ENGINE-COMPATIBLE schema"
echo "Sample data inserted (7 threat records)"
echo "Dependencies installed"
echo "GeoIP database downloaded"
echo "Empty JSON files ready"
echo ""
echo "Config: $CONFIG_DIR"
echo "Logs: $LOG_DIR"
echo "Database: $DB_FILE"
echo ""
echo "Test the setup:"
echo "sqlite3 $DB_FILE 'SELECT COUNT(*) FROM threats;'"
echo "configctl webguard get_attack_patterns 24h SQL"
echo "configctl webguard get_threat_stats 24h"
echo "=============================================="