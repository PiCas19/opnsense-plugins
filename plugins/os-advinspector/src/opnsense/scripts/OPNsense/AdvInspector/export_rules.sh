#!/bin/sh

PYTHON_SCRIPT="/usr/local/opnsense/scripts/OPNsense/AdvInspector/export_rules.py"

echo "[INFO] Avvio esportazione regole con Python..."
if [ ! -x "$PYTHON_SCRIPT" ]; then
    echo "[✗] Script Python non trovato o non eseguibile: $PYTHON_SCRIPT"
    exit 1
fi

/usr/local/bin/python3.11 "$PYTHON_SCRIPT"