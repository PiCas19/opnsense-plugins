#!/bin/sh
# setup.sh - Deep Packet Inspector setup script

set -e

SCRIPT_DIR="/usr/local/opnsense/scripts/OPNsense/DeepInspector"
LOG_DIR="/var/log/deepinspector"
CONFIG_DIR="/usr/local/etc/deepinspector"
RC_SCRIPT="/usr/local/etc/rc.d/deepinspector"

echo "Setting up Deep Packet Inspector..."

# Create directories
echo "Creating directories..."
mkdir -p "${SCRIPT_DIR}"
mkdir -p "${LOG_DIR}"
mkdir -p "${CONFIG_DIR}"

# Set proper permissions
echo "Setting permissions..."
chmod 755 "${SCRIPT_DIR}"
chmod 755 "${LOG_DIR}"
chmod 755 "${CONFIG_DIR}"

# Install Python dependencies
echo "Installing Python dependencies..."
/usr/local/bin/python3.11 -m pip install --upgrade pip
/usr/local/bin/python3.11 -m pip install psutil