#!/bin/sh
# setup.sh - WebGuard setup script
set -e

SCRIPT_DIR="/usr/local/opnsense/scripts/OPNsense/WebGuard"
LOG_DIR="/var/log/webguard"
CONFIG_DIR="/usr/local/etc/webguard"
DB_DIR="/var/db/webguard"
RC_SCRIPT="/usr/local/etc/rc.d/webguard"
GEOIP_DIR="/usr/local/share/GeoIP"

echo "Setting up WebGuard..."

# Create directories
echo "Creating directories..."
mkdir -p "${SCRIPT_DIR}"
mkdir -p "${LOG_DIR}"
mkdir -p "${CONFIG_DIR}"
mkdir -p "${DB_DIR}"
mkdir -p "${GEOIP_DIR}"

# Set proper permissions
echo "Setting permissions..."
chmod 755 "${SCRIPT_DIR}"
chmod 755 "${LOG_DIR}"
chmod 755 "${CONFIG_DIR}"
chmod 755 "${DB_DIR}"
chmod 755 "${GEOIP_DIR}"

# Install Python dependencies
echo "Installing Python dependencies..."
/usr/local/bin/python3.11 -m pip install --upgrade pip
/usr/local/bin/python3.11 -m pip install psutil requests geoip2 numpy scapy

# Create main configuration file
echo "Creating configuration files..."
cat > "${CONFIG_DIR}/config.json" << 'EOF'
{
    "general": {
        "enabled": true,
        "interfaces": ["em0", "em1"],
        "log_level": "info",
        "learning_period": 168,
        "auto_block_threshold": 5,
        "block_duration": 3600
    },
    "waf": {
        "enabled": true,
        "sql_injection_protection": true,
        "xss_protection": true,
        "csrf_protection": true,
        "lfi_protection": true,
        "rfi_protection": true
    },
    "behavioral": {
        "enabled": true,
        "anomaly_detection": true,
        "beaconing_detection": true,
        "data_exfiltration_detection": true,
        "learning_mode": true
    },
    "covert_channels": {
        "enabled": true,
        "dns_tunneling_detection": true,
        "protocol_anomaly_detection": true
    },
    "response": {
        "auto_blocking": true,
        "notification_webhook": "",
        "email_notifications": false,
        "log_blocked_requests": true
    },
    "whitelist": {
        "trusted_sources": [
            "127.0.0.0/8",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16"
        ]
    }
}
EOF

# Create WAF rules file
cat > "${CONFIG_DIR}/waf_rules.json" << 'EOF'
{
    "rules": [
        {
            "name": "SQL Injection - UNION SELECT",
            "pattern": "union\\s+(all\\s+)?select",
            "score": 50,
            "enabled": true,
            "description": "Detects UNION SELECT SQL injection attempts"
        },
        {
            "name": "SQL Injection - Boolean",
            "pattern": "(or|and)\\s+\\d+\\s*=\\s*\\d+",
            "score": 40,
            "enabled": true,
            "description": "Detects boolean-based SQL injection"
        },
        {
            "name": "SQL Injection - Comment",
            "pattern": "(--|#|/\\*|\\*/)",
            "score": 30,
            "enabled": true,
            "description": "Detects SQL comment injection"
        },
        {
            "name": "XSS - Script Tag",
            "pattern": "<script[^>]*>.*?</script>",
            "score": 45,
            "enabled": true,
            "description": "Detects script tag XSS"
        },
        {
            "name": "XSS - Event Handlers",
            "pattern": "on(load|error|click|mouse|focus|blur)\\s*=",
            "score": 40,
            "enabled": true,
            "description": "Detects event handler XSS"
        },
        {
            "name": "XSS - Javascript URL",
            "pattern": "javascript:\\s*[^\\s]",
            "score": 35,
            "enabled": true,
            "description": "Detects javascript: URL XSS"
        },
        {
            "name": "LFI - Directory Traversal",
            "pattern": "\\.\\./.*\\.\\./",,
            "score": 40,
            "enabled": true,
            "description": "Detects directory traversal attempts"
        },
        {
            "name": "LFI - System Files",
            "pattern": "(/etc/passwd|/etc/shadow|/windows/system32)",
            "score": 50,
            "enabled": true,
            "description": "Detects system file access attempts"
        },
        {
            "name": "Command Injection",
            "pattern": "(;|\\||&|`|\\$\\(|\\$\\{)\\s*(cat|ls|pwd|id|whoami|uname)",
            "score": 45,
            "enabled": true,
            "description": "Detects command injection attempts"
        },
        {
            "name": "LDAP Injection",
            "pattern": "(\\*|\\)|\\(|&|\\|)(cn=|uid=|objectclass=)",
            "score": 35,
            "enabled": true,
            "description": "Detects LDAP injection attempts"
        }
    ]
}
EOF

# Create attack patterns file
cat > "${CONFIG_DIR}/attack_patterns.json" << 'EOF'
{
    "patterns": [
        {
            "name": "SQL Injection Keywords",
            "keywords": ["union", "select", "insert", "update", "delete", "drop", "create", "alter", "exec", "execute"],
            "category": "sql_injection"
        },
        {
            "name": "XSS Keywords",
            "keywords": ["script", "javascript", "onerror", "onload", "onclick", "alert", "document.cookie"],
            "category": "xss"
        },
        {
            "name": "File Inclusion Keywords",
            "keywords": ["../", "..\\", "/etc/", "\\windows\\", "file://", "http://", "https://"],
            "category": "file_inclusion"
        },
        {
            "name": "Command Injection Keywords",
            "keywords": [";", "|", "&", "`", "$(", "${", "cat", "ls", "pwd", "whoami"],
            "category": "command_injection"
        }
    ]
}
EOF

# Create behavioral baseline file
cat > "${CONFIG_DIR}/behavioral_baseline.json" << 'EOF'
{
    "baselines": {
        "http_request_rate": {
            "normal_range": [1, 10],
            "unit": "requests_per_minute"
        },
        "payload_size": {
            "normal_range": [100, 8192],
            "unit": "bytes"
        },
        "session_duration": {
            "normal_range": [60, 3600],
            "unit": "seconds"
        }
    },
    "thresholds": {
        "anomaly_score": 80,
        "beaconing_regularity": 0.9,
        "data_exfiltration_threshold": 1048576
    }
}
EOF

# Download GeoIP database (free version)
echo "Downloading GeoIP database..."
if command -v fetch >/dev/null 2>&1; then
    # FreeBSD fetch
    fetch -o /tmp/GeoLite2-Country.tar.gz "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key=YOUR_LICENSE_KEY&suffix=tar.gz" || echo "Warning: Could not download GeoIP database. Please download manually."
elif command -v wget >/dev/null 2>&1; then
    # wget
    wget -O /tmp/GeoLite2-Country.tar.gz "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key=YOUR_LICENSE_KEY&suffix=tar.gz" || echo "Warning: Could not download GeoIP database. Please download manually."
else
    echo "Warning: Neither fetch nor wget available. Please download GeoIP database manually."
fi

# Extract GeoIP database if downloaded
if [ -f "/tmp/GeoLite2-Country.tar.gz" ]; then
    echo "Extracting GeoIP database..."
    cd /tmp
    tar -xzf GeoLite2-Country.tar.gz
    find . -name "GeoLite2-Country.mmdb" -exec cp {} "${GEOIP_DIR}/" \;
    rm -rf GeoLite2-Country*
    echo "GeoIP database installed."
else
    echo "Creating placeholder GeoIP database..."
    touch "${GEOIP_DIR}/GeoLite2-Country.mmdb"
fi

# Initialize database
echo "Initializing database..."
cat > /tmp/init_db.py << 'EOF'
#!/usr/local/bin/python3
import sqlite3
import os

DB_FILE = '/var/db/webguard/webguard.db'

# Ensure directory exists
os.makedirs(os.path.dirname(DB_FILE), exist_ok=True)

# Create database and tables
db = sqlite3.connect(DB_FILE)
db.execute('PRAGMA journal_mode=WAL')

db.executescript('''
    CREATE TABLE IF NOT EXISTS threats (
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
    );
    
    CREATE TABLE IF NOT EXISTS blocked_ips (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT UNIQUE NOT NULL,
        block_type TEXT NOT NULL,
        blocked_since INTEGER NOT NULL,
        expires_at INTEGER,
        reason TEXT,
        violations INTEGER DEFAULT 1,
        last_violation INTEGER
    );
    
    CREATE TABLE IF NOT EXISTS whitelist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT UNIQUE NOT NULL,
        description TEXT,
        added_at INTEGER NOT NULL,
        expires_at INTEGER,
        permanent INTEGER DEFAULT 1
    );
    
    CREATE TABLE IF NOT EXISTS behavioral_baselines (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        entity_type TEXT NOT NULL,
        entity_id TEXT NOT NULL,
        baseline_data TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
    );
    
    CREATE INDEX IF NOT EXISTS idx_threats_timestamp ON threats(timestamp);
    CREATE INDEX IF NOT EXISTS idx_threats_source_ip ON threats(source_ip);
    CREATE INDEX IF NOT EXISTS idx_blocked_ips_ip ON blocked_ips(ip_address);
    CREATE INDEX IF NOT EXISTS idx_whitelist_ip ON whitelist(ip_address);
''')

db.commit()
db.close()

print("Database initialized successfully")
EOF

/usr/local/bin/python3.11 /tmp/init_db.py
rm /tmp/init_db.py

# Create RC script for service management
echo "Creating RC script..."
cat > "${RC_SCRIPT}" << 'EOF'
#!/bin/sh
#
# PROVIDE: webguard
# REQUIRE: DAEMON NETWORKING
# KEYWORD: shutdown
#
# Add these lines to /etc/rc.conf.local or /etc/rc.conf
# to enable this service:
#
# webguard_enable (bool):   Set to NO by default.
#               Set it to YES to enable webguard.
# webguard_config (path):   Set to /usr/local/etc/webguard/config.json
#               by default.

. /etc/rc.subr

name=webguard
rcvar=webguard_enable

load_rc_config $name

: ${webguard_enable:="NO"}
: ${webguard_config:="/usr/local/etc/webguard/config.json"}
: ${webguard_user:="root"}
: ${webguard_group:="wheel"}

pidfile="/var/run/webguard.pid"
command="/usr/sbin/daemon"
procname="/usr/local/bin/python3.11"
command_args="-c -f -P ${pidfile} ${procname} /usr/local/opnsense/scripts/OPNsense/WebGuard/webguard_engine.py --config ${webguard_config} --daemon"

start_precmd="webguard_prestart"

webguard_prestart()
{
    if [ ! -f "${webguard_config}" ]; then
        err 1 "Configuration file ${webguard_config} does not exist"
    fi
    
    # Ensure log directory exists
    if [ ! -d "/var/log/webguard" ]; then
        mkdir -p /var/log/webguard
        chown ${webguard_user}:${webguard_group} /var/log/webguard
    fi
    
    # Ensure database directory exists
    if [ ! -d "/var/db/webguard" ]; then
        mkdir -p /var/db/webguard
        chown ${webguard_user}:${webguard_group} /var/db/webguard
    fi
}

run_rc_command "$1"
EOF

chmod +x "${RC_SCRIPT}"

# Set proper ownership for all files
echo "Setting file ownership..."
chown -R root:wheel "${CONFIG_DIR}"
chown -R root:wheel "${LOG_DIR}"
chown -R root:wheel "${DB_DIR}"
chown -R root:wheel "${GEOIP_DIR}"

# Create log rotation configuration
echo "Setting up log rotation..."
cat > /etc/newsyslog.conf.d/webguard.conf << 'EOF'
# WebGuard log rotation
/var/log/webguard/engine.log       644  7     1000 *     Z
/var/log/webguard/waf.log          644  7     1000 *     Z
/var/log/webguard/behavioral.log   644  7     1000 *     Z
/var/log/webguard/covert_channels.log 644  7  1000 *     Z
/var/log/webguard/blocked.log      644  30    1000 *     Z
EOF

# Create systemd-style service file for compatibility
mkdir -p /usr/local/etc/webguard/scripts
cat > /usr/local/etc/webguard/scripts/start.sh << 'EOF'
#!/bin/sh
service webguard start
EOF

cat > /usr/local/etc/webguard/scripts/stop.sh << 'EOF'
#!/bin/sh
service webguard stop
EOF

cat > /usr/local/etc/webguard/scripts/restart.sh << 'EOF'
#!/bin/sh
service webguard restart
EOF

chmod +x /usr/local/etc/webguard/scripts/*.sh

# Create status check script
cat > /usr/local/etc/webguard/scripts/status.sh << 'EOF'
#!/bin/sh
if [ -f "/var/run/webguard.pid" ] && kill -0 "$(cat /var/run/webguard.pid)" 2>/dev/null; then
    echo "WebGuard is running (PID: $(cat /var/run/webguard.pid))"
    exit 0
else
    echo "WebGuard is not running"
    exit 1
fi
EOF

chmod +x /usr/local/etc/webguard/scripts/status.sh

# Create maintenance script
cat > /usr/local/etc/webguard/scripts/maintenance.sh << 'EOF'
#!/bin/sh
# WebGuard maintenance script

SCRIPT_DIR="$(dirname "$0")"
LOG_FILE="/var/log/webguard/maintenance.log"

log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

# Cleanup old logs
log_message "Starting maintenance tasks"

# Rotate logs if they get too large
find /var/log/webguard -name "*.log" -size +10M -exec newsyslog -f {} \;

# Clean up database
/usr/local/bin/python3.11 << 'PYTHON_EOF'
import sqlite3
import time
import sys

try:
    db = sqlite3.connect('/var/db/webguard/webguard.db')
    
    # Clean up old threats (keep 30 days)
    cutoff_time = int(time.time() - (30 * 24 * 3600))
    cursor = db.execute('DELETE FROM threats WHERE timestamp < ? AND severity != "critical"', (cutoff_time,))
    deleted_threats = cursor.rowcount
    
    # Clean up expired blocks
    current_time = int(time.time())
    cursor = db.execute('DELETE FROM blocked_ips WHERE expires_at IS NOT NULL AND expires_at <= ?', (current_time,))
    deleted_blocks = cursor.rowcount
    
    db.commit()
    db.close()
    
    print(f"Cleaned up {deleted_threats} old threats and {deleted_blocks} expired blocks")
    
except Exception as e:
    print(f"Database cleanup failed: {e}")
    sys.exit(1)
PYTHON_EOF

log_message "Maintenance tasks completed"
EOF

chmod +x /usr/local/etc/webguard/scripts/maintenance.sh

# Add crontab entry for maintenance
echo "Setting up maintenance cron job..."
(crontab -l 2>/dev/null; echo "0 2 * * * /usr/local/etc/webguard/scripts/maintenance.sh") | crontab -

# Create test configuration validation script
cat > /usr/local/etc/webguard/scripts/validate_config.py << 'EOF'
#!/usr/local/bin/python3
import json
import sys
import os

CONFIG_FILE = '/usr/local/etc/webguard/config.json'

def validate_config():
    try:
        with open(CONFIG_FILE, 'r') as f:
            config = json.load(f)
        
        # Check required sections
        required_sections = ['general', 'waf', 'behavioral', 'covert_channels', 'response', 'whitelist']
        for section in required_sections:
            if section not in config:
                print(f"Error: Missing required section '{section}' in config")
                return False
        
        # Validate general section
        general = config['general']
        if 'enabled' not in general or not isinstance(general['enabled'], bool):
            print("Error: 'enabled' must be a boolean in general section")
            return False
        
        if 'interfaces' not in general or not isinstance(general['interfaces'], list):
            print("Error: 'interfaces' must be a list in general section")
            return False
        
        print("Configuration is valid")
        return True
        
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in config file: {e}")
        return False
    except FileNotFoundError:
        print(f"Error: Config file not found: {CONFIG_FILE}")
        return False
    except Exception as e:
        print(f"Error validating config: {e}")
        return False

if __name__ == '__main__':
    if validate_config():
        sys.exit(0)
    else:
        sys.exit(1)
EOF

chmod +x /usr/local/etc/webguard/scripts/validate_config.py

# Validate the configuration we just created
echo "Validating configuration..."
/usr/local/bin/python3.11 /usr/local/etc/webguard/scripts/validate_config.py

# Create README file
cat > "${CONFIG_DIR}/README.md" << 'EOF'
# WebGuard Configuration

This directory contains the WebGuard configuration files:

## Files

- `config.json`: Main configuration file
- `waf_rules.json`: Web Application Firewall rules
- `attack_patterns.json`: Attack pattern definitions
- `behavioral_baseline.json`: Behavioral analysis baselines

## Scripts

- `scripts/start.sh`: Start WebGuard service
- `scripts/stop.sh`: Stop WebGuard service
- `scripts/restart.sh`: Restart WebGuard service
- `scripts/status.sh`: Check WebGuard status
- `scripts/maintenance.sh`: Maintenance tasks
- `scripts/validate_config.py`: Validate configuration

## Service Management

Enable and start WebGuard:
```bash
echo 'webguard_enable="YES"' >> /etc/rc.conf
service webguard start
```

Check status:
```bash
service webguard status
```

View logs:
```bash
tail -f /var/log/webguard/engine.log
```

## Configuration

Edit `/usr/local/etc/webguard/config.json` to customize settings.
After making changes, validate with:
```bash
/usr/local/etc/webguard/scripts/validate_config.py
```

Then restart the service:
```bash
service webguard restart
```
EOF

echo ""
echo "=============================================="
echo "WebGuard setup completed successfully!"
echo "=============================================="
echo ""
echo "Files created:"
echo "- Configuration: ${CONFIG_DIR}/config.json"
echo "- WAF Rules: ${CONFIG_DIR}/waf_rules.json"
echo "- Attack Patterns: ${CONFIG_DIR}/attack_patterns.json"
echo "- Behavioral Baselines: ${CONFIG_DIR}/behavioral_baseline.json"
echo "- Database: ${DB_DIR}/webguard.db"
echo "- RC Script: ${RC_SCRIPT}"
echo ""
echo "To enable and start WebGuard:"
echo "  echo 'webguard_enable=\"YES\"' >> /etc/rc.conf"
echo "  service webguard start"
echo ""
echo "To check status:"
echo "  service webguard status"
echo "  /usr/local/etc/webguard/scripts/status.sh"
echo ""
echo "To view logs:"
echo "  tail -f /var/log/webguard/engine.log"
echo ""
echo "Note: Please obtain a MaxMind license key and update the GeoIP"
echo "      database download URL in this script for full functionality."
echo ""
echo "Configuration validation: PASSED"
echo "=============================================="