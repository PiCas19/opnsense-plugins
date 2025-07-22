#!/bin/sh
# WebGuard File Structure Setup for OPNsense
# This script creates only the essential directories and empty files

set -e

# Essential directories
CONFIG_DIR="/usr/local/etc/webguard"
LOG_DIR="/var/log/webguard"
DB_DIR="/var/db/webguard"
GEOIP_DIR="/usr/local/share/GeoIP"

echo "=============================================="
echo "Creating WebGuard File Structure"
echo "=============================================="

# Create necessary directories
echo "Creating directories..."
mkdir -p "${CONFIG_DIR}"
mkdir -p "${LOG_DIR}"
mkdir -p "${DB_DIR}"
mkdir -p "${GEOIP_DIR}"

# Create empty configuration files
echo "Creating empty configuration files..."
touch "${CONFIG_DIR}/config.json"
touch "${CONFIG_DIR}/waf_rules.json"
touch "${CONFIG_DIR}/attack_patterns.json"

# Create empty database file
echo "Creating empty database file..."
touch "${DB_DIR}/webguard.db"

# Create empty log file
echo "Creating empty log file..."
touch "${LOG_DIR}/engine.log"

# Install required Python libraries
echo "Installing Python dependencies..."
echo "Installing psutil..."
/usr/local/bin/python3.11 -m pip install psutil || {
    echo "Warning: Failed to install psutil"
}

echo "Installing geoip2..."
/usr/local/bin/python3.11 -m pip install geoip2 || {
    echo "Warning: Failed to install geoip2"
}

# Download GeoIP2 database
echo "Downloading GeoIP2 database..."
fetch -o /usr/local/share/GeoIP/GeoLite2-Country.mmdb \
  "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"

# Set proper permissions
echo "Setting permissions..."
chown -R root:wheel "${CONFIG_DIR}"
chown -R root:wheel "${LOG_DIR}"  
chown -R root:wheel "${DB_DIR}"
chown -R root:wheel "${GEOIP_DIR}"
chmod -R 755 "${CONFIG_DIR}"
chmod -R 755 "${LOG_DIR}"
chmod -R 755 "${DB_DIR}"
chmod 644 "${GEOIP_DIR}/GeoLite2-Country.mmdb"

echo ""
echo "=============================================="
echo "WebGuard File Structure Created!"
echo "=============================================="
echo ""
echo "Installed Python dependencies:"
echo "- psutil (system monitoring)"
echo "- geoip2 (IP geolocation)"
echo ""
echo "Created directories:"
echo "- ${CONFIG_DIR}"
echo "- ${LOG_DIR}"
echo "- ${DB_DIR}"
echo "- ${GEOIP_DIR}"
echo ""
echo "Created empty files:"
echo "- ${CONFIG_DIR}/config.json"
echo "- ${CONFIG_DIR}/waf_rules.json"
echo "- ${CONFIG_DIR}/attack_patterns.json"
echo "- ${DB_DIR}/webguard.db"
echo "- ${LOG_DIR}/engine.log"
echo ""
echo "Downloaded:"
echo "- GeoLite2-Country.mmdb (IP geolocation database)"
echo ""
echo "File structure ready for WebGuard deployment!"
echo "=============================================="