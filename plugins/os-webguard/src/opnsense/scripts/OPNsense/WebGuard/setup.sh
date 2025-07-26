#!/bin/sh
# WebGuard Clean Setup for OPNsense
# Only shell - no Python mixed here

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

echo "[*] Creating SQLite database..."
[ -f "$DB_FILE" ] && rm -f "$DB_FILE"

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

sqlite3 "$DB_FILE" "CREATE TABLE whitelist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT UNIQUE NOT NULL,
    description TEXT,
    added_at INTEGER NOT NULL,
    expires_at INTEGER,
    permanent INTEGER DEFAULT 1
);"

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

echo "[*] Creating indexes..."
sqlite3 "$DB_FILE" "CREATE INDEX IF NOT EXISTS idx_threats_timestamp ON threats(timestamp);"
sqlite3 "$DB_FILE" "CREATE INDEX IF NOT EXISTS idx_threats_source_ip ON threats(source_ip);"
sqlite3 "$DB_FILE" "CREATE INDEX IF NOT EXISTS idx_blocked_ips_ip ON blocked_ips(ip_address);"
sqlite3 "$DB_FILE" "CREATE INDEX IF NOT EXISTS idx_whitelist_ip ON whitelist(ip_address);"

echo "[*] Inserting sample data..."
CURRENT_TIME=$(date +%s)

sqlite3 "$DB_FILE" "INSERT INTO blocked_ips (ip_address, block_type, blocked_since, reason, violations, last_violation) VALUES ('192.168.1.100', 'manual', $CURRENT_TIME, 'Sample blocked IP', 1, $CURRENT_TIME);"

sqlite3 "$DB_FILE" "INSERT INTO whitelist (ip_address, description, added_at, permanent) VALUES ('192.168.1.1', 'Sample whitelist entry', $CURRENT_TIME, 1);"

echo "[*] Inserting sample threats..."
for entry in \
  "$((CURRENT_TIME - 3600))|192.168.1.200|/admin/login.php|POST|SQL Injection|high|85.5|'' OR 1=1 --|rule_1|SQL injection detected" \
  "$((CURRENT_TIME - 7200))|10.0.0.50|/search?q=<script>|GET|XSS Attack|medium|65.0|<script>alert(\"xss\")</script>|rule_2|Cross-site scripting attempt" \
  "$((CURRENT_TIME - 10800))|172.16.0.25|/api/users|GET|Path Traversal|medium|70.0|../../../etc/passwd|rule_3|Directory traversal detected" \
  "$((CURRENT_TIME - 14400))|203.0.113.45|/cmd.php|POST|Command Injection|critical|95.0|; cat /etc/passwd|rule_4|Command injection attempt detected" \
  "$((CURRENT_TIME - 18000))|198.51.100.33|/login.asp|POST|SQL Injection|high|88.0|UNION SELECT username,password FROM users|rule_5|SQL injection with UNION attack" \
  "$((CURRENT_TIME - 21600))|93.184.216.34|/comment.php|POST|XSS Attack|medium|72.5|<img src=x onerror=alert(1)>|rule_6|DOM-based XSS attempt" \
  "$((CURRENT_TIME - 25200))|185.199.108.153|/include.php|GET|File Inclusion|high|82.0|?file=../../../../etc/passwd|rule_7|Local file inclusion detected"
do

    IFS='|' read -r ts ip tgt mtd typ sev scr pld rule desc <<EOF
$entry
EOF
    sqlite3 "$DB_FILE" "INSERT INTO threats (
      timestamp, source_ip, target, method, type, severity, status, score,
      payload, request_headers, rule_matched, description, false_positive
    ) VALUES (
      $ts, '$ip', '$tgt', '$mtd', '$typ', '$sev', 'blocked', $scr,
      '$pld', '{}', '$rule', '$desc', 0
    );"
done

echo "[*] Installing Python dependencies..."
$PY -m pip install -q psutil geoip2 requests || echo "[!] pip install errors ignored"

echo "[*] Downloading MaxMind GeoLite2 database..."
if fetch -o "${GEOIP_DIR}/GeoLite2-Country.mmdb" "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb" 2>/dev/null; then
    echo "[+] MaxMind GeoLite2 database downloaded."
else
    echo "[!] GeoLite2 download failed. Manual download from:"
    echo "    https://dev.maxmind.com/geoip/geolite2/"
fi

echo "[*] Checking for IP2Location LITE database..."
if [ -f "${GEOIP_DIR}/IP2LOCATION-LITE-DB1.MMDB" ]; then
    echo "[+] IP2Location LITE database found:"
    echo "    ${GEOIP_DIR}/IP2LOCATION-LITE-DB1.MMDB"
    echo "    Source: https://lite.ip2location.com"
    echo "    Copyright (c) Hexasoft Development Sdn. Bhd."
else
    echo "[*] IP2Location LITE database not found."
    echo "    You may download it from https://lite.ip2location.com"
    echo "    and place it in: ${GEOIP_DIR}/IP2LOCATION-LITE-DB1.MMDB"
fi

echo "[*] Running rule updater if available..."
if [ -f "$UPDATER" ]; then
    chmod +x "$UPDATER"
    $PY "$UPDATER" || echo "[!] Rule updater failed"
else
    echo "[!] update_rules.py not found in $CONFIG_DIR"
    echo "    Copy it there and run: $PY $UPDATER"
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
echo "Config:   $CONFIG_DIR"
echo "Logs:     $LOG_DIR"
echo "Database: $DB_FILE"
echo ""
echo "GeoIP Databases:"
[ -f "${GEOIP_DIR}/GeoLite2-Country.mmdb" ] && echo "  - GeoLite2: OK"
[ -f "${GEOIP_DIR}/IP2LOCATION-LITE-DB1.MMDB" ] && echo "  - IP2Location LITE: OK"
echo ""
echo "Test the setup:"
echo "sqlite3 $DB_FILE 'SELECT COUNT(*) FROM threats;'"
echo "=============================================="
