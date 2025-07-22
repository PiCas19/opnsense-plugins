#!/bin/sh
# WebGuard Clean Setup for OPNsense
# ONLY shell script - no Python mixing
# - Crea directories e file base
# - Installa dipendenze Python
# - Scarica GeoIP database
# - Copia update_rules.py se presente
# - Imposta permessi

set -e

CONFIG_DIR="/usr/local/etc/webguard"
LOG_DIR="/var/log/webguard"
DB_DIR="/var/db/webguard"
GEOIP_DIR="/usr/local/share/GeoIP"
PY="/usr/local/bin/python3.11"
UPDATER="${CONFIG_DIR}/update_rules.py"

echo "=============================================="
echo "WebGuard Clean Setup"
echo "=============================================="

echo "[*] Creating directories..."
mkdir -p "$CONFIG_DIR" "$LOG_DIR" "$DB_DIR" "$GEOIP_DIR"

echo "[*] Creating empty base files..."
: > "${LOG_DIR}/engine.log"
: > "${DB_DIR}/webguard.db"
: > "${CONFIG_DIR}/waf_rules.json"
: > "${CONFIG_DIR}/attack_patterns.json"

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

echo ""
echo "=============================================="
echo "WebGuard Setup Complete! 🚀"
echo "=============================================="
echo "Directories created"
echo "Dependencies installed" 
echo "GeoIP database downloaded"
echo "Empty JSON files ready"
echo ""
echo "Config: $CONFIG_DIR"
echo "Logs: $LOG_DIR"
echo "Rules: Copy update_rules.py and run it"
echo ""
echo "Next steps:"
echo "1. Copy update_rules.py to $CONFIG_DIR"
echo "2. Run: $PY $UPDATER"
echo "3. service webguard start"
echo "4. tail -f /var/log/webguard/engine.log"
echo "=============================================="