#!/bin/sh

PYTHON_SCRIPT="/usr/local/opnsense/scripts/OPNsense/AdvInspector/export_rules.py"

echo "[INFO] Starting export of rules with Python..."
if [ ! -x "$PYTHON_SCRIPT" ]; then
    echo "[✗] Python script not found or not executable: $PYTHON_SCRIPT"
    exit 1
fi

/usr/local/bin/python3.11 "$PYTHON_SCRIPT"