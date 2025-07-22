#!/bin/sh
# WebGuard Setup for OPNsense
# - Crea dir/log/db
# - Installa dipendenze Python
# - Scarica GeoIP
# - (se presente) lancia update_rules.py
# - Imposta permessi
set -e

CONFIG_DIR="/usr/local/etc/webguard"
LOG_DIR="/var/log/webguard"
DB_DIR="/var/db/webguard"
GEOIP_DIR="/usr/local/share/GeoIP"
PY="/usr/local/bin/python3.11"
UPDATER="${CONFIG_DIR}/update_rules.py"

echo "=============================================="
echo "WebGuard Setup"
echo "=============================================="

echo "[*] Creating directories..."
mkdir -p "$CONFIG_DIR" "$LOG_DIR" "$DB_DIR" "$GEOIP_DIR"

echo "[*] Creating empty db/log/json files..."
: > "${LOG_DIR}/engine.log"
: > "${DB_DIR}/webguard.db"
: > "${CONFIG_DIR}/waf_rules.json"
: > "${CONFIG_DIR}/attack_patterns.json"

echo "[*] Installing Python deps..."
$PY -m pip install -q psutil geoip2 requests || echo "pip install errors ignored"

echo "[*] Downloading GeoIP2 database..."
fetch -o "${GEOIP_DIR}/GeoLite2-Country.mmdb" \
  "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb" 2>/dev/null || \
echo "Warning: GeoIP download failed"

# Lancia updater solo se presente (riempirà i JSON)
if [ -f "$UPDATER" ]; then
  chmod +x "$UPDATER"
  echo "[*] Running update_rules.py..."
  $PY "$UPDATER" || echo "Updater failed, leaving empty/old JSON" >&2
else
  echo "NOTE: $UPDATER non trovato. I JSON restano vuoti finché non lo copi/esegui."
fi

echo "[*] Setting permissions..."
chown -R root:wheel "$CONFIG_DIR" "$LOG_DIR" "$DB_DIR" "$GEOIP_DIR" 2>/dev/null || true
chmod -R 755 "$CONFIG_DIR" "$LOG_DIR" "$DB_DIR"
chmod 644 "$CONFIG_DIR"/*.json 2>/dev/null || true
chmod 644 "$GEOIP_DIR"/*.mmdb 2>/dev/null || true

echo ""
echo "=============================================="
echo "WebGuard Setup Complete!"
echo "=============================================="
echo "Next steps:"
echo "1. service webguard start"
echo "2. tail -f /var/log/webguard/engine.log"
echo "=============================================="