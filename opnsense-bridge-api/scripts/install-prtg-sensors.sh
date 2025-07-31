#!/bin/bash

# install-prtg-sensors.sh - Install PRTG sensor scripts

# Load .env file
if [ -f .env ]; then
    export $(grep -v '^#' .env | xargs)
else
    echo "Error: .env file not found in $(pwd)"
    exit 1
fi

PRTG_SENSORS_DIR="/var/prtg/scripts"

# Create PRTG sensors directory
mkdir -p "$PRTG_SENSORS_DIR"

# Copy PRTG sensor scripts
cp monitoring/prtg/sensors/*.py "$PRTG_SENSORS_DIR/"
chmod +x "$PRTG_SENSORS_DIR"/*.py

# Verify installation
for script in "$PRTG_SENSORS_DIR"/*.py; do
    python3 "$script" > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "Successfully installed $script"
    else
        echo "Error: Failed to run $script"
        exit 1
    fi
done

echo "PRTG sensors installed successfully"