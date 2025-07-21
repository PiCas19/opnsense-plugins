#!/bin/sh
# Complete WebGuard Installation Script for OPNsense
# This script installs all components and fixes the configd integration

set -e

# Directories
WEBGUARD_SCRIPTS_DIR="/usr/local/opnsense/scripts/OPNsense/WebGuard"
CONFIGD_ACTIONS_DIR="/usr/local/opnsense/service/conf/actions.d"
CONFIG_DIR="/usr/local/etc/webguard"
LOG_DIR="/var/log/webguard"
DB_DIR="/var/db/webguard"
RC_SCRIPT="/usr/local/etc/rc.d/webguard"
GEOIP_DIR="/usr/local/share/GeoIP"

echo "=============================================="
echo "Installing WebGuard for OPNsense"
echo "=============================================="

# Create all necessary directories
echo "Creating directories..."
mkdir -p "${WEBGUARD_SCRIPTS_DIR}"
mkdir -p "${CONFIGD_ACTIONS_DIR}"
mkdir -p "${CONFIG_DIR}"
mkdir -p "${LOG_DIR}"
mkdir -p "${DB_DIR}"
mkdir -p "${GEOIP_DIR}"

# Copy the WebGuard engine script (assume it's in current directory as web_guard_engine.py)
echo "Installing WebGuard engine..."
if [ -f "./web_guard_engine.py" ]; then
    cp "./web_guard_engine.py" "${WEBGUARD_SCRIPTS_DIR}/"
    chmod +x "${WEBGUARD_SCRIPTS_DIR}/web_guard_engine.py"
    echo "WebGuard engine copied and made executable"
else
    echo "ERROR: web_guard_engine.py not found in current directory"
    echo "Please ensure the engine script is present before running setup"
    exit 1
fi

# Create basic support scripts
echo "Creating support scripts..."

# start.sh
cat > "${WEBGUARD_SCRIPTS_DIR}/start.sh" << 'EOF'
#!/bin/sh
service webguard start
echo "WebGuard started"
EOF

# stop.sh
cat > "${WEBGUARD_SCRIPTS_DIR}/stop.sh" << 'EOF'
#!/bin/sh
service webguard stop
echo "WebGuard stopped"
EOF

# restart.sh
cat > "${WEBGUARD_SCRIPTS_DIR}/restart.sh" << 'EOF'
#!/bin/sh
service webguard restart
echo "WebGuard restarted"
EOF

# status.sh
cat > "${WEBGUARD_SCRIPTS_DIR}/status.sh" << 'EOF'
#!/bin/sh
if [ -f "/var/run/webguard.pid" ] && kill -0 "$(cat /var/run/webguard.pid)" 2>/dev/null; then
    echo "WebGuard is running (PID: $(cat /var/run/webguard.pid))"
    exit 0
else
    echo "WebGuard is not running"
    exit 1
fi
EOF

# reload.sh
cat > "${WEBGUARD_SCRIPTS_DIR}/reload.sh" << 'EOF'
#!/bin/sh
if [ -f "/var/run/webguard.pid" ]; then
    kill -HUP "$(cat /var/run/webguard.pid)" 2>/dev/null
    echo "WebGuard configuration reloaded"
else
    echo "WebGuard is not running"
    exit 1
fi
EOF

# Make scripts executable
chmod +x "${WEBGUARD_SCRIPTS_DIR}"/*.sh

# Create support Python scripts
echo "Creating support Python scripts..."

# export_config.py
cat > "${WEBGUARD_SCRIPTS_DIR}/export_config.py" << 'EOF'
#!/usr/local/bin/python3.11
import json
import os

def export_config():
    config_dir = "/usr/local/etc/webguard"
    os.makedirs(config_dir, exist_ok=True)
    
    config = {
        "general": {"enabled": True, "interfaces": ["em0"]},
        "waf": {"enabled": True},
        "response": {"auto_blocking": False}
    }
    
    with open(f"{config_dir}/config.json", 'w') as f:
        json.dump(config, f, indent=2)
    
    return True

if __name__ == "__main__":
    export_config()
    print("Configuration exported")
EOF

# Create all other required Python scripts
for script in "update_rules.py" "get_waf_stats.py" "get_threat_metrics.py" "get_metrics.py" "get_stats.py" "get_threats.py" "manage_threats.py" "manage_blocking.py" "manage_whitelist.py" "test_rules.py"; do
    cat > "${WEBGUARD_SCRIPTS_DIR}/${script}" << 'EOF'
#!/usr/local/bin/python3.11
import json
import sys

def main():
    # Return empty JSON for basic functionality
    result = {
        "status": "ok",
        "message": "WebGuard module placeholder",
        "data": {}
    }
    print(json.dumps(result))
    return 0

if __name__ == "__main__":
    sys.exit(main())
EOF
    chmod +x "${WEBGUARD_SCRIPTS_DIR}/${script}"
done

chmod +x "${WEBGUARD_SCRIPTS_DIR}/export_config.py"

# Copy configd actions file (assume it's in current directory as actions_webguard.conf)
echo "Installing configd actions..."
if [ -f "./actions_webguard.conf" ]; then
    cp "./actions_webguard.conf" "${CONFIGD_ACTIONS_DIR}/"
    echo "Configd actions file copied"
else
    echo "ERROR: actions_webguard.conf not found in current directory"
    echo "Please ensure the actions file is present before running setup"
    exit 1
fi

# Create configuration files
echo "Creating configuration files..."

cat > "${CONFIG_DIR}/config.json" << 'EOF'
{
    "general": {
        "enabled": true,
        "interfaces": ["em0"],
        "log_level": "info",
        "auto_block_threshold": 5,
        "block_duration": 3600
    },
    "waf": {
        "enabled": true,
        "sql_injection_protection": true,
        "xss_protection": true,
        "csrf_protection": true
    },
    "response": {
        "auto_blocking": false,
        "notification_webhook": ""
    },
    "whitelist": {
        "trusted_sources": ["127.0.0.0/8", "10.0.0.0/8", "192.168.0.0/16"]
    }
}
EOF

cat > "${CONFIG_DIR}/waf_rules.json" << 'EOF'
{
    "version": "1.0",
    "updated": "2024-01-01T00:00:00",
    "rules": [
        {
            "id": 1,
            "name": "SQL Injection - Basic",
            "type": "sql_injection",
            "pattern": "union\\s+select|or\\s+1\\s*=\\s*1",
            "enabled": true,
            "score": 50,
            "description": "Detects basic SQL injection attempts"
        },
        {
            "id": 2,
            "name": "XSS - Script Tag",
            "type": "xss",
            "pattern": "<script[^>]*>.*?</script>",
            "enabled": true,
            "score": 40,
            "description": "Detects script tag XSS attempts"
        }
    ]
}
EOF

cat > "${CONFIG_DIR}/attack_patterns.json" << 'EOF'
{
    "version": "1.0",
    "patterns": {
        "sql_injection": ["union", "select", "insert", "update", "delete"],
        "xss": ["script", "javascript", "onerror", "onload"],
        "command_injection": [";", "|", "&", "`", "$("]
    }
}
EOF

# Copy RC script (assume it's in current directory as webguard)
echo "Installing RC service script..."
if [ -f "./webguard" ]; then
    cp "./webguard" "${RC_SCRIPT}"
    chmod +x "${RC_SCRIPT}"
    echo "RC script copied and made executable"
else
    echo "ERROR: webguard RC script not found in current directory"
    echo "Please ensure the RC script is present before running setup"
    exit 1
fi

# Initialize database
echo "Initializing database..."
/usr/local/bin/python3.11 -c "
import sqlite3
import os
os.makedirs('/var/db/webguard', exist_ok=True)
db = sqlite3.connect('/var/db/webguard/webguard.db')
db.execute('''CREATE TABLE IF NOT EXISTS threats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp INTEGER NOT NULL,
    source_ip TEXT NOT NULL,
    target TEXT NOT NULL,
    method TEXT NOT NULL,
    type TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL,
    score INTEGER DEFAULT 0,
    payload TEXT,
    request_headers TEXT,
    rule_matched TEXT,
    description TEXT,
    false_positive INTEGER DEFAULT 0
)''')
db.execute('''CREATE TABLE IF NOT EXISTS blocked_ips (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT UNIQUE NOT NULL,
    block_type TEXT NOT NULL,
    blocked_since INTEGER NOT NULL,
    expires_at INTEGER,
    reason TEXT,
    violations INTEGER DEFAULT 1,
    last_violation INTEGER
)''')
db.execute('''CREATE TABLE IF NOT EXISTS whitelist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT UNIQUE NOT NULL,
    description TEXT,
    added_at INTEGER NOT NULL,
    expires_at INTEGER,
    permanent INTEGER DEFAULT 1
)''')
db.commit()
db.close()
print('Database initialized')
"

# Set proper permissions
echo "Setting permissions..."
chown -R root:wheel "${WEBGUARD_SCRIPTS_DIR}"
chown -R root:wheel "${CONFIG_DIR}"
chown -R root:wheel "${LOG_DIR}"
chown -R root:wheel "${DB_DIR}"
chmod -R 755 "${WEBGUARD_SCRIPTS_DIR}"
chmod -R 644 "${CONFIG_DIR}"/*.json

# Restart configd to reload actions
echo "Restarting configd service..."
service configd restart
sleep 3

echo ""
echo "=============================================="
echo "WebGuard Installation Complete!"
echo "=============================================="
echo ""
echo "Files installed:"
echo "- Engine: ${WEBGUARD_SCRIPTS_DIR}/web_guard_engine.py"
echo "- Scripts: ${WEBGUARD_SCRIPTS_DIR}/*.sh"
echo "- Actions: ${CONFIGD_ACTIONS_DIR}/actions_webguard.conf"
echo "- Config: ${CONFIG_DIR}/config.json"
echo "- RC Script: ${RC_SCRIPT}"
echo ""
echo "Next steps:"
echo "1. Enable the service:"
echo "   echo 'webguard_enable=\"YES\"' >> /etc/rc.conf"
echo ""
echo "2. Test configd integration:"
echo "   configctl webguard status"
echo ""
echo "3. Start WebGuard:"
echo "   configctl webguard start"
echo ""
echo "4. Check status:"
echo "   configctl webguard status"
echo "   service webguard status"
echo ""
echo "5. View logs:"
echo "   tail -f /var/log/webguard/engine.log"
echo ""
echo "=============================================="