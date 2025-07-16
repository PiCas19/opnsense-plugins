#!/usr/local/bin/python3
import datetime
import json
import os

ALERT_LOG_FILE = "/var/log/advinspector_alerts.log"
PACKET_LOG_FILE = "/var/log/advinspector_packets.log"

def log_alert(packet, reason=""):
    """
    Logga un alert nel file degli alert.
    """
    entry = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "src": packet.get("src"),
        "dst": packet.get("dst"),
        "port": packet.get("port"),
        "protocol": packet.get("protocol"),
        "reason": reason,
        "raw": packet.get("raw", "")[:512]  # Limita a ~256 byte
    }

    try:
        os.makedirs(os.path.dirname(ALERT_LOG_FILE), exist_ok=True)
        with open(ALERT_LOG_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass

def log_packet(packet, reason=""):
    """
    Logga un pacchetto normale nel file dedicato.
    """
    entry = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "src": packet.get("src"),
        "dst": packet.get("dst"),
        "port": packet.get("port"),
        "protocol": packet.get("protocol"),
        "interface": packet.get("interface") or "unknown",
        "reason": reason,
        "raw": packet.get("raw", "")[:512]  # Limita a ~256 byte
    }

    try:
        os.makedirs(os.path.dirname(PACKET_LOG_FILE), exist_ok=True)
        with open(PACKET_LOG_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass