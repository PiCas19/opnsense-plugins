#!/bin/sh
# WebGuard Setup for OPNsense
# - Crea dir/log/db
# - Installa dipendenze Python
# - Scarica GeoIP
# - Esegue update_rules.py se presente (genera waf_rules.json e attack_patterns.json)
# - Valida JSON e sistema permessi

set -e

CONFIG_DIR="/usr/local/etc/webguard"
LOG_DIR="/var/log/webguard"
DB_DIR="/var/db/webguard"
GEOIP_DIR="/usr/local/share/GeoIP"
TEMP_DIR="/tmp/webguard_setup"
PY="/usr/local/bin/python3.11"
UPDATER="${CONFIG_DIR}/update_rules.py"

echo "=============================================="
echo "WebGuard Setup - Downloading Real Threat Intelligence"
echo "=============================================="

echo "[*] Creating directories..."
mkdir -p "${CONFIG_DIR}" "${LOG_DIR}" "${DB_DIR}" "${GEOIP_DIR}" "${TEMP_DIR}"

echo "[*] Creating db/log files..."
touch "${DB_DIR}/webguard.db" "${LOG_DIR}/engine.log"

echo "[*] Installing Python dependencies..."
${PY} -m pip install -q psutil geoip2 requests || echo "pip install errors ignored"

echo "[*] Downloading GeoIP2 database..."
fetch -o "${GEOIP_DIR}/GeoLite2-Country.mmdb" \
  "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb" 2>/dev/null || \
echo "Warning: GeoIP download failed"

# Esegui updater se presente
if [ -f "${UPDATER}" ]; then
  chmod +x "${UPDATER}"
  echo "[*] Running update_rules.py..."
  if ! ${PY} "${UPDATER}"; then
    echo "Updater failed, keeping existing JSON (if any)" >&2
  fi
else
  echo "NOTE: ${UPDATER} non trovato. Copialo o genera i JSON manualmente."
fi

echo "[*] Verifying JSON files..."
JSON_VALID=true
for json_file in "${CONFIG_DIR}"/*.json; do
  [ -f "$json_file" ] || continue
  if ! ${PY} - <<'PY' "$json_file"
import json,sys
with open(sys.argv[1],'rb') as f:
    json.load(f)
print("OK", sys.argv[1])
PY
  then
    JSON_VALID=false
  fi
done

echo "[*] Setting permissions..."
chown -R root:wheel "${CONFIG_DIR}" "${LOG_DIR}" "${DB_DIR}" "${GEOIP_DIR}"
chmod -R 755 "${CONFIG_DIR}" "${LOG_DIR}" "${DB_DIR}"
chmod 644 "${CONFIG_DIR}"/*.json 2>/dev/null || true
chmod 644 "${GEOIP_DIR}"/*.mmdb 2>/dev/null || true

rm -rf "${TEMP_DIR}"

echo ""
echo "=============================================="
echo "WebGuard Setup Complete!"
echo "=============================================="
echo ""
echo "✓ Files generati/aggiornati (se updater ok):"
echo "  - ${CONFIG_DIR}/waf_rules.json"
echo "  - ${CONFIG_DIR}/attack_patterns.json"
echo "✓ GeoLite2-Country.mmdb scaricato (se disponibile)"
echo "✓ Dipendenze Python: psutil, geoip2, requests"
echo ""
if [ "$JSON_VALID" = "true" ]; then
  echo "WebGuard è pronto. JSON validi."
else
  echo "⚠ Alcuni JSON non validi: controlla i log sopra."
fi
echo ""
echo "Next steps:"
echo "1. Copia/abilita il motore WebGuard"
echo "2. service webguard start"
echo "3. tail -f /var/log/webguard/engine.log"
echo "=============================================="
