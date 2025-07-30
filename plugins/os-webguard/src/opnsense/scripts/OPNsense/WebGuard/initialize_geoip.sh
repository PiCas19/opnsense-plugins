#!/bin/sh
# WebGuard GeoIP Initialization Script
# Configures GeoIP.conf, downloads GeoLite2 database, and verifies it

set -e

GEOIP_DIR="/usr/local/share/GeoIP"
GEOIP_CONF="/usr/local/etc/GeoIP.conf"
PY="/usr/local/bin/python3.11"

echo "=============================================="
echo "WebGuard GeoIP Initialization"
echo "=============================================="

# Check if geoipupdate is installed
if ! command -v geoipupdate >/dev/null 2>&1; then
    echo "[!] geoipupdate not found. Please install it with:"
    echo "    pkg install geoipupdate"
    exit 1
fi

# Prompt for MaxMind Account ID and License Key if not provided via environment variables
if [ -z "$MAXMIND_ACCOUNT_ID" ] || [ -z "$MAXMIND_LICENSE_KEY" ]; then
    if [ ! -f "$GEOIP_CONF" ] || ! grep -q "AccountID" "$GEOIP_CONF" || ! grep -q "LicenseKey" "$GEOIP_CONF"; then
        echo "[*] Please provide your MaxMind Account ID and License Key."
        echo "    Get them from: https://www.maxmind.com/en/accounts/current/license-key"
        echo ""
        read -p "Enter MaxMind Account ID: " MAXMIND_ACCOUNT_ID
        read -p "Enter MaxMind License Key: " MAXMIND_LICENSE_KEY
    else
        echo "[*] Reading existing GeoIP.conf..."
        MAXMIND_ACCOUNT_ID=$(grep "AccountID" "$GEOIP_CONF" | awk '{print $2}')
        MAXMIND_LICENSE_KEY=$(grep "LicenseKey" "$GEOIP_CONF" | awk '{print $2}')
    fi
else
    echo "[*] Using environment variables for MaxMind credentials..."
fi

# Create or update GeoIP.conf
if [ ! -z "$MAXMIND_ACCOUNT_ID" ] && [ ! -z "$MAXMIND_LICENSE_KEY" ]; then
    echo "[*] Creating/Updating GeoIP.conf..."
    mkdir -p "$(dirname $GEOIP_CONF)"
    cat > "$GEOIP_CONF" <<EOF
AccountID $MAXMIND_ACCOUNT_ID
LicenseKey $MAXMIND_LICENSE_KEY
EditionIDs GeoLite2-Country
EOF
    chmod 600 "$GEOIP_CONF"
    chown root:wheel "$GEOIP_CONF"
    echo "[+] GeoIP.conf created/updated at $GEOIP_CONF"
else
    echo "[!] MaxMind credentials not provided. Cannot create GeoIP.conf."
    exit 1
fi

# Download GeoLite2 database
echo "[*] Downloading GeoLite2-Country.mmdb via geoipupdate..."
if geoipupdate -f "$GEOIP_CONF"; then
    echo "[+] GeoLite2 database downloaded successfully"
    echo "    Location: ${GEOIP_DIR}/GeoLite2-Country.mmdb"
    echo "    Size: $(ls -lh ${GEOIP_DIR}/GeoLite2-Country.mmdb 2>/dev/null | awk '{print $5}' || echo 'Unknown')"
else
    echo "[!] Failed to download GeoLite2 database. Check $GEOIP_CONF for valid AccountID and LicenseKey."
    echo "    Alternatively, manually download from: https://dev.maxmind.com/geoip/geolite2/"
    exit 1
fi

# Test GeoLite2 database
echo "[*] Testing GeoLite2 database..."
if $PY -c "
import geoip2.database
import sys
import os

geolite_path = '${GEOIP_DIR}/GeoLite2-Country.mmdb'
if os.path.exists(geolite_path):
    try:
        with geoip2.database.Reader(geolite_path) as reader:
            response = reader.country('8.8.8.8')
            print(f'  ✓ GeoLite2: 8.8.8.8 -> {response.country.name} ({response.country.iso_code})')
            sys.exit(0)
    except Exception as e:
        print(f'  ✗ GeoLite2 test failed: {e}')
        sys.exit(1)
else:
    print('  ✗ GeoLite2 database not found at ${GEOIP_DIR}/GeoLite2-Country.mmdb')
    sys.exit(1)
"; then
    echo "[+] GeoLite2 database test passed"
else
    echo "[!] GeoLite2 database test failed"
    exit 1
fi

echo ""
echo "=============================================="
echo "GeoIP Initialization Complete!"
echo "=============================================="
echo "GeoIP Config: $GEOIP_CONF"
echo "GeoIP Database: ${GEOIP_DIR}/GeoLite2-Country.mmdb"
echo ""
echo "Next steps:"
echo "  - Start WebGuard service: service webguard start"
echo "  - Test GeoIP integration: configctl webguard get_geo_stats last24h"
echo "=============================================="