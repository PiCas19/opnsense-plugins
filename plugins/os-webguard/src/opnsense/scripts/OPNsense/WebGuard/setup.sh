#!/bin/sh
# WebGuard Clean Setup for OPNsense
# UPDATED: Dual GeoIP Database Support

set -e

CONFIG_DIR="/usr/local/etc/webguard"
LOG_DIR="/var/log/webguard"
DB_DIR="/var/db/webguard"
GEOIP_DIR="/usr/local/share/GeoIP"
PY="/usr/local/bin/python3.11"
UPDATER="${CONFIG_DIR}/update_rules.py"
DB_FILE="${DB_DIR}/webguard.db"

echo "=============================================="
echo "WebGuard Clean Setup - Dual GeoIP Support"
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

echo "[*] Inserting REAL PUBLIC IP sample threats for GeoIP testing..."

# Insert real public IPs for GeoIP testing
for entry in \
  "$((CURRENT_TIME - 3600))|8.8.8.8|/admin/login.php|POST|SQL Injection|high|blocked|85.5|'' OR 1=1 --|rule_1|Google DNS - SQL injection test" \
  "$((CURRENT_TIME - 7200))|1.1.1.1|/search?q=<script>|GET|XSS Attack|medium|blocked|65.0|<script>alert(\"xss\")</script>|rule_2|Cloudflare DNS - XSS test" \
  "$((CURRENT_TIME - 10800))|208.67.222.222|/api/users|GET|Path Traversal|medium|blocked|70.0|../../../etc/passwd|rule_3|OpenDNS - Directory traversal test" \
  "$((CURRENT_TIME - 14400))|217.0.43.1|/cmd.php|POST|Command Injection|critical|blocked|95.0|; cat /etc/passwd|rule_4|Deutsche Telekom - Command injection test" \
  "$((CURRENT_TIME - 18000))|80.67.169.12|/login.asp|POST|SQL Injection|high|blocked|88.0|UNION SELECT username,password FROM users|rule_5|Orange France - SQL injection with UNION" \
  "$((CURRENT_TIME - 21600))|194.168.4.100|/comment.php|POST|XSS Attack|medium|blocked|72.5|<img src=x onerror=alert(1)>|rule_6|BT UK - DOM-based XSS" \
  "$((CURRENT_TIME - 25200))|212.216.172.62|/include.php|GET|File Inclusion|high|blocked|82.0|?file=../../../../etc/passwd|rule_7|Telecom Italia - LFI attack" \
  "$((CURRENT_TIME - 25200))|195.121.1.34|/upload.php|POST|File Upload|high|blocked|87.0|shell.php upload attempt|rule_8|KPN Netherlands - Malicious upload" \
  "$((CURRENT_TIME - 28800))|195.238.2.21|/admin/config.php|GET|Directory Traversal|medium|blocked|75.0|../../admin/config.php|rule_9|Proximus Belgium - Config access" \
  "$((CURRENT_TIME - 32400))|130.59.31.251|/wp-admin/admin-ajax.php|POST|WordPress Attack|high|blocked|83.0|wp_ajax_nopriv|rule_10|Swisscom - WordPress exploit"
do
    IFS='|' read -r ts ip tgt mtd typ sev stat scr pld rule desc <<EOF
$entry
EOF
    sqlite3 "$DB_FILE" "INSERT INTO threats (
      timestamp, source_ip, target, method, type, severity, status, score,
      payload, request_headers, rule_matched, description, false_positive
    ) VALUES (
      $ts, '$ip', '$tgt', '$mtd', '$typ', '$sev', '$stat', $scr,
      '$pld', '{}', '$rule', '$desc', 0
    );"
done

echo "[*] Installing Python dependencies..."
$PY -m pip install -q psutil geoip2 requests || echo "[!] pip install errors ignored"

echo "[*] Setting up DUAL GeoIP databases..."

# Download MaxMind GeoLite2
echo "[*] Downloading MaxMind GeoLite2 database..."
if fetch -o "${GEOIP_DIR}/GeoLite2-Country.mmdb" "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb" 2>/dev/null; then
    echo "[+] MaxMind GeoLite2 database downloaded successfully"
    echo "    Location: ${GEOIP_DIR}/GeoLite2-Country.mmdb"
    echo "    Size: $(ls -lh ${GEOIP_DIR}/GeoLite2-Country.mmdb | awk '{print $5}')"
else
    echo "[!] GeoLite2 download failed. Manual download from:"
    echo "    https://dev.maxmind.com/geoip/geolite2/"
fi

# Check for IP2Location LITE database
echo "[*] Checking for IP2Location LITE database..."
if [ -f "${GEOIP_DIR}/IP2LOCATION-LITE-DB1.MMDB" ]; then
    echo "[+] IP2Location LITE database found"
    echo "    Location: ${GEOIP_DIR}/IP2LOCATION-LITE-DB1.MMDB"
    echo "    Size: $(ls -lh ${GEOIP_DIR}/IP2LOCATION-LITE-DB1.MMDB | awk '{print $5}')"
    echo "    Source: IP2Location LITE Database"
    echo "    Copyright (c) Hexasoft Development Sdn. Bhd."
else
    echo "[!] IP2Location LITE database not found"
    echo "    Download from: https://lite.ip2location.com"
    echo "    Place file at: ${GEOIP_DIR}/IP2LOCATION-LITE-DB1.MMDB"
    echo "    Note: Both databases will be used for maximum IP resolution coverage"
fi

# Test GeoIP databases
echo "[*] Testing GeoIP databases..."
if $PY -c "
import geoip2.database
import sys
import os

databases_tested = 0
databases_working = 0

# Test GeoLite2
geolite_path = '${GEOIP_DIR}/GeoLite2-Country.mmdb'
if os.path.exists(geolite_path):
    try:
        with geoip2.database.Reader(geolite_path) as reader:
            response = reader.country('8.8.8.8')
            print(f'  ✓ GeoLite2: 8.8.8.8 -> {response.country.name} ({response.country.iso_code})')
            databases_working += 1
    except Exception as e:
        print(f'  ✗ GeoLite2 test failed: {e}')
    databases_tested += 1

# Test IP2Location
ip2location_path = '${GEOIP_DIR}/IP2LOCATION-LITE-DB1.MMDB'
if os.path.exists(ip2location_path):
    try:
        with geoip2.database.Reader(ip2location_path) as reader:
            response = reader.country('8.8.8.8')
            country_name = getattr(response.country, 'name', 'Unknown')
            country_code = getattr(response.country, 'iso_code', 'XX')
            print(f'  ✓ IP2Location: 8.8.8.8 -> {country_name} ({country_code})')
            databases_working += 1
    except Exception as e:
        print(f'  ✗ IP2Location test failed: {e}')
    databases_tested += 1

if databases_tested == 0:
    print('  ✗ No GeoIP databases found')
    sys.exit(1)
elif databases_working == 0:
    print('  ✗ No GeoIP databases are working')
    sys.exit(1)
else:
    print(f'  → {databases_working}/{databases_tested} GeoIP databases working')
    sys.exit(0)
"; then
    echo "[+] GeoIP database test passed"
else
    echo "[!] GeoIP database test failed"
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
echo "WebGuard Setup Complete - Dual GeoIP Ready!"
echo "=============================================="
echo "Config:   $CONFIG_DIR"
echo "Logs:     $LOG_DIR"
echo "Database: $DB_FILE"
echo ""
echo "GeoIP Databases Status:"
if [ -f "${GEOIP_DIR}/GeoLite2-Country.mmdb" ]; then
    echo "  ✓ GeoLite2-Country: READY"
else
    echo "  ✗ GeoLite2-Country: MISSING"
fi

if [ -f "${GEOIP_DIR}/IP2LOCATION-LITE-DB1.MMDB" ]; then
    echo "  ✓ IP2Location-LITE: READY"
else
    echo "  ✗ IP2Location-LITE: MISSING"
fi

echo ""
echo "Sample Data Inserted:"
echo "  - Real public IP threats for GeoIP testing"
echo "  - Countries: US, France, Germany, UK, Italy, Netherlands, Belgium, Switzerland"
echo ""
echo "Test the GeoIP setup:"
echo "configctl webguard get_geo_stats last24h"
echo ""
echo "Database threat count:"
echo "sqlite3 $DB_FILE 'SELECT COUNT(*) FROM threats;'"
echo "=============================================="