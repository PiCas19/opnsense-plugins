#!/bin/bash

# install-nagios-plugin.sh - Install Nagios plugin and configurations

# Load .env file
if [ -f .env ]; then
    export $(grep -v '^#' .env | xargs)
else
    echo "Error: .env file not found in $(pwd)"
    exit 1
fi

NAGIOS_PLUGINS_DIR="/usr/lib/nagios/plugins"
NAGIOS_CONFIG_DIR="/etc/nagios"

# Copy Nagios plugin
cp monitoring/nagios/plugins/check_opnsense_bridge.sh "$NAGIOS_PLUGINS_DIR/"
chmod +x "$NAGIOS_PLUGINS_DIR/check_opnsense_bridge.sh"

# Copy Nagios configurations
cp monitoring/nagios/commands/opnsense-commands.cfg "$NAGIOS_CONFIG_DIR/commands/"
cp monitoring/nagios/services/opnsense-services.cfg "$NAGIOS_CONFIG_DIR/services/"

# Update host in configurations
sed -i "s/host_name.*/host_name               $BRIDGE_IP/" "$NAGIOS_CONFIG_DIR/services/opnsense-services.cfg"

# Restart Nagios
systemctl restart nagios
if [ $? -eq 0 ]; then
    echo "Nagios plugin and configurations installed successfully"
else
    echo "Error: Failed to restart Nagios"
    exit 1
fi