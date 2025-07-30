#!/bin/sh
# WebGuard GeoIP Initialization Script
# Configures GeoIP download via OPNsense method and verifies it

set -e

GEOIP_DIR="/usr/local/share/GeoIP"
GEOIP_CONF="/usr/local/etc/GeoIP.conf"
PY="/usr/local/bin/python3.11"
DOWNLOAD_URL_TEMPLATE="https://%s:%s@download.maxmind.com/geoip/databases/GeoLite2-Country-CSV/download?suffix=zip"
TEMP_DIR="/tmp/geoip_download"
DOWNLOAD_FILE="${TEMP_DIR}/GeoLite2-Country-CSV.zip"
EXTRACT_DIR="${TEMP_DIR}/extracted"

echo "=============================================="
echo "WebGuard GeoIP Initialization"
echo "=============================================="

# Create temporary directory
echo "[*] Creating temporary directory..."
mkdir -p "$TEMP_DIR" "$EXTRACT_DIR"
chmod 755 "$TEMP_DIR" "$EXTRACT_DIR"
chown root:wheel "$TEMP_DIR" "$EXTRACT_DIR"
echo "[+] Temporary directory created"

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
EOF
    chmod 600 "$GEOIP_CONF"
    chown root:wheel "$GEOIP_CONF"
    echo "[+] GeoIP.conf created/updated at $GEOIP_CONF"
else
    echo "[!] MaxMind credentials not provided. Cannot create GeoIP.conf."
    exit 1
fi

# Construct download URL
DOWNLOAD_URL=$(printf "$DOWNLOAD_URL_TEMPLATE" "$MAXMIND_ACCOUNT_ID" "$MAXMIND_LICENSE_KEY")
echo "[*] Downloading GeoLite2-Country-CSV from $DOWNLOAD_URL..."

# Download the database
echo "[*] Downloading database..."
if fetch -o "$DOWNLOAD_FILE" "$DOWNLOAD_URL"; then
    echo "[+] Database downloaded successfully to $DOWNLOAD_FILE"
else
    echo "[!] Failed to download database. Check credentials or network."
    echo "    Alternatively, manually download from: https://www.maxmind.com/en/geolite2/signup"
    rm -rf "$TEMP_DIR"
    exit 1
fi

# Extract the database
echo "[*] Extracting database..."
unzip -o "$DOWNLOAD_FILE" -d "$EXTRACT_DIR" >/dev/null 2>&1 || {
    echo "[!] Failed to extract database."
    rm -rf "$TEMP_DIR"
    exit 1
}
MMDB_FILE=$(find "$EXTRACT_DIR" -name "GeoLite2-Country.mmdb")
if [ -z "$MMDB_FILE" ]; then
    echo "[!] GeoLite2-Country.mmdb not found in archive."
    rm -rf "$TEMP_DIR"
    exit 1
fi
echo "[+] Database extracted to $MMDB_FILE"

# Move the database to the final location
echo "[*] Moving database to $GEOIP_DIR..."
mkdir -p "$GEOIP_DIR"
mv "$MMDB_FILE" "$GEOIP_DIR/GeoLite2-Country.mmdb"
chmod 644 "$GEOIP_DIR/GeoLite2-Country.mmdb"
chown root:wheel "$GEOIP_DIR/GeoLite2-Country.mmdb"
echo "[+] Database moved successfully"

# Clean up
echo "[*] Cleaning up temporary files..."
rm -rf "$TEMP_DIR"
echo "[+] Cleanup complete"

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