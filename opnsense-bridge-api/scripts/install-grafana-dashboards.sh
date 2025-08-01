#!/bin/bash

# install-grafana-dashboards.sh - Install Grafana dashboards and provisioning

# Load .env file
if [ -f .env ]; then
    export $(grep -v '^#' .env | xargs)
else
    echo "Error: .env file not found in $(pwd)"
    exit 1
fi

GRAFANA_DASHBOARDS_DIR="/etc/grafana/dashboards"
GRAFANA_PROVISIONING_DIR="/etc/grafana/provisioning"

# Create Grafana directories
mkdir -p "$GRAFANA_DASHBOARDS_DIR" "$GRAFANA_PROVISIONING_DIR/datasources" "$GRAFANA_PROVISIONING_DIR/dashboards"

# Copy dashboards and provisioning
cp monitoring/grafana/dashboards/*.json "$GRAFANA_DASHBOARDS_DIR/"
cp monitoring/grafana/provisioning/datasources.yaml "$GRAFANA_PROVISIONING_DIR/datasources/"
cp monitoring/grafana/provisioning/dashboards.yaml "$GRAFANA_PROVISIONING_DIR/dashboards/"

# Update Prometheus URL in datasources.yaml
sed -i "s|url:.*|url: http://$BRIDGE_IP:${PROMETHEUS_PORT:-9090}|" "$GRAFANA_PROVISIONING_DIR/datasources/datasources.yaml"

# Restart Grafana
systemctl restart grafana-server
if [ $? -eq 0 ]; then
    echo "Grafana dashboards and provisioning installed successfully"
else
    echo "Error: Failed to restart Grafana"
    exit 1
fi