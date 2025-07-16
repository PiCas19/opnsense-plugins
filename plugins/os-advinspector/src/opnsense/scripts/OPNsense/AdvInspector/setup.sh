#!/bin/sh

CONF_DIR="/usr/local/etc/advinspector"
RULES_FILE="${CONF_DIR}/rules.json"
ALERT_LOG="/var/log/advinspector_alerts.log"
PACKET_LOG="/var/log/advinspector_packets.log"
PF_ANCHOR_CONF="/usr/local/etc/ips_block.conf"

# Crea directory di configurazione e log se non esistono
mkdir -p "$CONF_DIR"
mkdir -p "$(dirname "$ALERT_LOG")"

# Crea file di log per alert
[ -f "$ALERT_LOG" ] || touch "$ALERT_LOG"
chmod 644 "$ALERT_LOG"

# Crea file di log per pacchetti
[ -f "$PACKET_LOG" ] || touch "$PACKET_LOG"
chmod 644 "$PACKET_LOG"

# Crea file di regole se non esiste
if [ ! -f "$RULES_FILE" ]; then
  echo '{ "rules": [] }' > "$RULES_FILE"
  chmod 644 "$RULES_FILE"
fi

# Crea anchor PF se non esiste
if [ ! -f "$PF_ANCHOR_CONF" ]; then
  touch "$PF_ANCHOR_CONF"
  chmod 600 "$PF_ANCHOR_CONF"
  echo "# IPS dynamic rules loaded via pfctl" > "$PF_ANCHOR_CONF"
fi

echo "[✓] Complete setup: logs, rules.json, and pf anchor ready"