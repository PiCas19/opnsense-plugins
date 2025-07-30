#!/bin/sh
# WebGuard Clean Setup for OPNsense
# UPDATED: Dual GeoIP Database Support with Robust Script Copying

set -e

CONFIG_DIR="/usr/local/etc/webguard"
LOG_DIR="/var/log/webguard"
DB_DIR="/var/db/webguard"
GEOIP_DIR="/usr/local/share/GeoIP"
GEOIP_CONF="/usr/local/etc/GeoIP.conf"
PLUGIN_SRC_DIR="/usr/plugins/security/os-webguard/src"
SCRIPT_SRC_DIR="${PLUGIN_SRC_DIR}/opnsense/scripts/OPNsense/WebGuard"
SCRIPT_DEST_DIR="/usr/local/opnsense/scripts/OPNsense/WebGuard"
RCD_SRC_DIR="${PLUGIN_SRC_DIR}/etc/rc.d"
RCD_DEST_DIR="/usr/local/etc/rc.d"
PY="/usr/local/bin/python3.11"
UPDATER="${CONFIG_DIR}/update_rules.py"
DB_FILE="${DB_DIR}/webguard.db"

echo "=============================================="
echo "WebGuard Clean Setup - Dual GeoIP Support"
echo "=============================================="

# Create directories
echo "[*] Creating directories..."
mkdir -p "$CONFIG_DIR" "$LOG_DIR" "$DB_DIR" "$GEOIP_DIR" "$SCRIPT_DEST_DIR" "$RCD_DEST_DIR"
chmod 755 "$CONFIG_DIR" "$LOG_DIR" "$DB_DIR" "$GEOIP_DIR" "$SCRIPT_DEST_DIR" "$RCD_DEST_DIR"
chown root:wheel "$CONFIG_DIR" "$LOG_DIR" "$DB_DIR" "$GEOIP_DIR" "$SCRIPT_DEST_DIR" "$RCD_DEST_DIR"
echo "[+] Directories created with permissions set"

# Copy scripts
echo "[*] Copying scripts from $SCRIPT_SRC_DIR to $SCRIPT_DEST_DIR..."
if [ -d "$SCRIPT_SRC_DIR" ]; then
    echo "[*] Source directory contents:"
    ls -l "$SCRIPT_SRC_DIR" || echo "[!] Failed to list $SCRIPT_SRC_DIR contents"
    if ls "$SCRIPT_SRC_DIR"/* >/dev/null 2>&1; then
        cp -rv "$SCRIPT_SRC_DIR"/* "$SCRIPT_DEST_DIR/" 2>/dev/null || {
            echo "[!] Failed to copy scripts from $SCRIPT_SRC_DIR to $SCRIPT_DEST_DIR"
            echo "[!] Check permissions or if source files exist (e.g., webguard.py, update_rules.py, initialize_geoip.sh)"
            exit 1
        }
        chmod -R 755 "$SCRIPT_DEST_DIR"
        chown -R root:wheel "$SCRIPT_DEST_DIR"
        echo "[+] Scripts copied successfully"
    else
        echo "[!] No files found in $SCRIPT_SRC_DIR. Skipping script copy."
        echo "[!] Ensure the plugin is installed correctly and contains required scripts."
    fi
else
    echo "[!] Script source directory $SCRIPT_SRC_DIR not found."
    echo "[!] Ensure the plugin is installed in /usr/plugins/security/os-webguard/"
    exit 1
fi

# Copy or create webguard rc.d script
echo "[*] Setting up WebGuard rc.d script..."
if [ -f "${RCD_SRC_DIR}/webguard" ]; then
    cp -v "${RCD_SRC_DIR}/webguard" "${RCD_DEST_DIR}/webguard" 2>/dev/null || {
        echo "[!] Failed to copy webguard rc.d script from $RCD_SRC_DIR to $RCD_DEST_DIR"
        exit 1
    }
    chmod 755 "${RCD_DEST_DIR}/webguard"
    chown root:wheel "${RCD_DEST_DIR}/webguard"
    echo "[+] WebGuard rc.d script copied successfully"
else
    echo "[!] WebGuard rc.d script not found in $RCD_SRC_DIR. Creating default..."
    cat > "${RCD_DEST_DIR}/webguard" <<EOF
#!/bin/sh
#
# PROVIDE: webguard
# REQUIRE: LOGIN
# KEYWORD: shutdown
#
. /etc/rc.subr

name="webguard"
rcvar="webguard_enable"
command="${PY}"
command_args="${CONFIG_DIR}/webguard.py"
pidfile="/var/run/\${name}.pid"
start_cmd="webguard_start"
stop_cmd="webguard_stop"

webguard_start() {
    echo "Starting WebGuard..."
    /usr/sbin/daemon -f -p "\${pidfile}" \${command} \${command_args}
}

webguard_stop() {
    echo "Stopping WebGuard..."
    if [ -f "\${pidfile}" ]; then
        pkill -F "\${pidfile}" 2>/dev/null
        rm -f "\${pidfile}"
    fi
}

load_rc_config \$name
run_rc_command "\$1"
EOF
    chmod 755 "${RCD_DEST_DIR}/webguard"
    chown root:wheel "${RCD_DEST_DIR}/webguard"
    echo "[+] Default WebGuard rc.d script created"
fi

# Create geoipupdate rc.d script
echo "[*] Creating geoipupdate rc.d script..."
cat > "${RCD_DEST_DIR}/geoipupdate" <<EOF
#!/bin/sh
#
# PROVIDE: geoipupdate
# REQUIRE: NETWORKING
# KEYWORD: shutdown
#
. /etc/rc.subr

name="geoipupdate"
rcvar="geoipupdate_enable"
command="/usr/local/bin/geoipupdate"
command_args="-f ${GEOIP_CONF}"
pidfile="/var/run/\${name}.pid"
start_cmd="geoipupdate_start"
stop_cmd="geoipupdate_stop"

geoipupdate_start() {
    echo "Starting GeoIP database update..."
    /usr/sbin/daemon -f -p "\${pidfile}" \${command} \${command_args}
}

geoipupdate_stop() {
    echo "Stopping GeoIP database update..."
    if [ -f "\${pidfile}" ]; then
        pkill -F "\${pidfile}" 2>/dev/null
        rm -f "\${pidfile}"
    fi
}

load_rc_config \$name
run_rc_command "\$1"
EOF
chmod 755 "${RCD_DEST_DIR}/geoipupdate"
chown root:wheel "${RCD_DEST_DIR}/geoipupdate"
echo "[+] GeoIPupdate rc.d script created"

# Enable services
echo "[*] Enabling WebGuard and GeoIPupdate services..."
sysrc webguard_enable="YES"
sysrc geoipupdate_enable="YES"

# Create empty base files
echo "[*] Creating empty base files..."
: > "${LOG_DIR}/engine.log"
: > "${CONFIG_DIR}/waf_rules.json"
: > "${CONFIG_DIR}/attack_patterns.json"
chmod 644 "${LOG_DIR}/engine.log" "${CONFIG_DIR}/waf_rules.json" "${CONFIG_DIR}/attack_patterns.json" 2>/dev/null || true
chown root:wheel "${LOG_DIR}/engine.log" "${CONFIG_DIR}/waf_rules.json" "${CONFIG_DIR}/attack_patterns.json"

# Create SQLite database
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

# Insert sample data
echo "[*] Inserting sample data..."
CURRENT_TIME=$(date +%s)

sqlite3 "$DB_FILE" "INSERT INTO blocked_ips (ip_address, block_type, blocked_since, reason, violations, last_violation) VALUES ('192.168.1.100', 'manual', $CURRENT_TIME, 'Sample blocked IP', 1, $CURRENT_TIME);"

sqlite3 "$DB_FILE" "INSERT INTO whitelist (ip_address, description, added_at, permanent) VALUES ('192.168.1.1', 'Sample whitelist entry', $CURRENT_TIME, 1);"

echo "[*] Inserting REAL PUBLIC IP sample threats for GeoIP testing..."
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

# Install Python dependencies
echo "[*] Installing Python dependencies..."
$PY -m pip install -q psutil geoip2 requests || echo "[!] pip install errors ignored"

# GeoIP database setup
echo "[*] Setting up GeoIP databases..."
echo "[*] GeoLite2 database setup required"
echo "    Run the following command to configure and download the GeoLite2 database:"
echo "    $SCRIPT_DEST_DIR/initialize_geoip.sh"
echo "    Ensure you have a MaxMind account and valid credentials."
echo "    Get them from: https://www.maxmind.com/en/accounts/current/license-key"

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

# Run rule updater
echo "[*] Running rule updater if available..."
if [ -f "$UPDATER" ]; then
    chmod +x "$UPDATER"
    $PY "$UPDATER" || echo "[!] Rule updater failed"
else
    echo "[!] update_rules.py not found in $CONFIG_DIR"
    echo "    Copy it there and run: $PY $UPDATER"
fi

# Set permissions
echo "[*] Setting permissions..."
chown -R root:wheel "$CONFIG_DIR" "$LOG_DIR" "$DB_DIR" "$GEOIP_DIR" "$SCRIPT_DEST_DIR" "$RCD_DEST_DIR"
chmod -R 755 "$CONFIG_DIR" "$LOG_DIR" "$DB_DIR" "$SCRIPT_DEST_DIR" "$RCD_DEST_DIR"
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
echo "Scripts:  $SCRIPT_DEST_DIR"
echo "rc.d:     $RCD_DEST_DIR"
echo ""
echo "GeoIP Databases Status:"
if [ -f "${GEOIP_DIR}/GeoLite2-Country.mmdb" ]; then
    echo "  ✓ GeoLite2-Country: READY"
else
    echo "  ✗ GeoLite2-Country: MISSING"
    echo "    Run $SCRIPT_DEST_DIR/initialize_geoip.sh to configure and download"
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
echo "Start WebGuard service:"
echo "service webguard start"
echo ""
echo "Start GeoIPupdate service:"
echo "service geoipupdate start"
echo ""
echo "Database threat count:"
echo "sqlite3 $DB_FILE 'SELECT COUNT(*) FROM threats;'"
echo "=============================================="