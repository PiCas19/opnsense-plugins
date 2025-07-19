#!/bin/sh

# WebGuard Plugin Setup Script
# Copyright (C) 2024 OPNsense WebGuard Plugin
# All rights reserved.

set -e

PLUGIN_NAME="webguard"
PLUGIN_VERSION="1.0.0"
OPNSENSE_BASE="/usr/local/opnsense"
SCRIPTS_DIR="${OPNSENSE_BASE}/scripts/OPNsense/WebGuard"
CONFIG_DIR="/usr/local/etc/webguard"
LOG_DIR="/var/log/webguard"
DB_DIR="/var/db/webguard"
RC_SCRIPT="/usr/local/etc/rc.d/webguard"

echo "Setting up WebGuard Plugin v${PLUGIN_VERSION}..."

# Function to create directory with proper permissions
create_dir() {
    local dir=$1
    local owner=${2:-root}
    local group=${3:-wheel}
    local mode=${4:-755}
    
    if [ ! -d "${dir}" ]; then
        mkdir -p "${dir}"
        echo "Created directory: ${dir}"
    fi
    chown ${owner}:${group} "${dir}"
    chmod ${mode} "${dir}"
}

# Function to install file with proper permissions
install_file() {
    local src=$1
    local dst=$2
    local owner=${3:-root}
    local group=${4:-wheel}
    local mode=${5:-644}
    
    if [ -f "${src}" ]; then
        cp "${src}" "${dst}"
        chown ${owner}:${group} "${dst}"
        chmod ${mode} "${dst}"
        echo "Installed: ${dst}"
    else
        echo "WARNING: Source file not found: ${src}"
    fi
}

# Create necessary directories
echo "Creating directories..."
create_dir "${CONFIG_DIR}" root wheel 755
create_dir "${LOG_DIR}" root wheel 755
create_dir "${DB_DIR}" root wheel 755
create_dir "${SCRIPTS_DIR}" root wheel 755

# Install Python scripts
echo "Installing Python scripts..."
install_file "web_guard_engine.py" "${SCRIPTS_DIR}/web_guard_engine.py" root wheel 755
install_file "export_config.py" "${SCRIPTS_DIR}/export_config.py" root wheel 755
install_file "get_stats.py" "${SCRIPTS_DIR}/get_stats.py" root wheel 755
install_file "manage_whitelist.py" "${SCRIPTS_DIR}/manage_whitelist.py" root wheel 755
install_file "manage_blocking.py" "${SCRIPTS_DIR}/manage_blocking.py" root wheel 755
install_file "manage_threats.py" "${SCRIPTS_DIR}/manage_threats.py" root wheel 755
install_file "get_threats.py" "${SCRIPTS_DIR}/get_threats.py" root wheel 755
install_file "test_rules.py" "${SCRIPTS_DIR}/test_rules.py" root wheel 755
install_file "update_rules.py" "${SCRIPTS_DIR}/update_rules.py" root wheel 755

# Install shell scripts
echo "Installing shell scripts..."
install_file "start.sh" "${SCRIPTS_DIR}/start.sh" root wheel 755
install_file "stop.sh" "${SCRIPTS_DIR}/stop.sh" root wheel 755
install_file "restart.sh" "${SCRIPTS_DIR}/restart.sh" root wheel 755
install_file "status.sh" "${SCRIPTS_DIR}/status.sh" root wheel 755
install_file "reload.sh" "${SCRIPTS_DIR}/reload.sh" root wheel 755
install_file "create_default_config.sh" "${SCRIPTS_DIR}/create_default_config.sh" root wheel 755
install_file "validate_config.py" "${SCRIPTS_DIR}/validate_config.py" root wheel 755

# Install rc.d script
echo "Installing rc.d daemon script..."
install_file "webguard" "${RC_SCRIPT}" root wheel 755

# Create default configuration files
echo "Creating default configuration files..."

# Main configuration
cat > "${CONFIG_DIR}/config.json" << 'EOF'
{
    "general": {
        "enabled": false,
        "mode": "learning",
        "interfaces": ["lan"],
        "protected_networks": ["192.168.1.0/24"],
        "learning_period": 168,
        "sensitivity_level": "medium",
        "auto_block_threshold": 5,
        "block_duration": 3600,
        "ssl_inspection": false,
        "geo_blocking": false,
        "rate_limiting": true,
        "log_level": "info"
    },
    "waf": {
        "sql_injection_protection": true,
        "xss_protection": true,
        "csrf_protection": true,
        "rfi_protection": true,
        "lfi_protection": true,
        "directory_traversal_protection": true,
        "command_injection_protection": true,
        "http_protocol_validation": true,
        "file_upload_protection": true,
        "session_protection": true,
        "custom_rules": ""
    },
    "behavioral": {
        "anomaly_detection": true,
        "beaconing_detection": true,
        "data_exfiltration_detection": true,
        "traffic_pattern_analysis": true,
        "user_behavior_profiling": true,
        "timing_analysis": true,
        "entropy_analysis": true,
        "baseline_learning": true
    },
    "covert_channels": {
        "dns_tunneling_detection": true,
        "http_steganography_detection": true,
        "icmp_tunneling_detection": true,
        "protocol_anomaly_detection": true,
        "payload_entropy_analysis": true,
        "timing_channel_detection": true,
        "size_pattern_analysis": true
    },
    "response": {
        "auto_blocking": true,
        "progressive_blocking": true,
        "session_termination": true,
        "honeypot_redirect": false,
        "tarpit_mode": false,
        "notification_webhook": "",
        "siem_integration": false
    },
    "whitelist": {
        "trusted_sources": ["127.0.0.1/8", "::1/128"],
        "trusted_user_agents": [],
        "bypass_urls": []
    }
}
EOF

# WAF Rules
cat > "${CONFIG_DIR}/waf_rules.json" << 'EOF'
{
    "rules": [
        {
            "name": "SQL Injection - Union Select",
            "pattern": "union\\s+select",
            "score": 50,
            "enabled": true,
            "category": "sql_injection"
        },
        {
            "name": "SQL Injection - OR 1=1",
            "pattern": "or\\s+1\\s*=\\s*1",
            "score": 40,
            "enabled": true,
            "category": "sql_injection"
        },
        {
            "name": "XSS - Script Tag",
            "pattern": "<script[^>]*>",
            "score": 45,
            "enabled": true,
            "category": "xss"
        },
        {
            "name": "XSS - JavaScript Protocol",
            "pattern": "javascript\\s*:",
            "score": 35,
            "enabled": true,
            "category": "xss"
        },
        {
            "name": "Directory Traversal",
            "pattern": "\\.\\./",
            "score": 30,
            "enabled": true,
            "category": "lfi"
        },
        {
            "name": "Command Injection - Semicolon",
            "pattern": ";\\s*(cat|ls|pwd|id|whoami|uname)",
            "score": 45,
            "enabled": true,
            "category": "command_injection"
        },
        {
            "name": "PHP Code Injection",
            "pattern": "<\\?php",
            "score": 40,
            "enabled": true,
            "category": "code_injection"
        },
        {
            "name": "Remote File Inclusion",
            "pattern": "https?://[^/]+/",
            "score": 25,
            "enabled": true,
            "category": "rfi"
        }
    ]
}
EOF

# Attack Patterns
cat > "${CONFIG_DIR}/attack_patterns.json" << 'EOF'
{
    "patterns": [
        {
            "name": "SQL Injection Patterns",
            "type": "sql_injection",
            "signatures": [
                "union select",
                "or 1=1",
                "drop table",
                "insert into",
                "delete from",
                "'; exec",
                "' or '1'='1"
            ]
        },
        {
            "name": "XSS Patterns",
            "type": "xss",
            "signatures": [
                "<script>",
                "javascript:",
                "onerror=",
                "onload=",
                "onclick=",
                "eval(",
                "document.cookie"
            ]
        },
        {
            "name": "Directory Traversal Patterns",
            "type": "lfi",
            "signatures": [
                "../",
                "..\\",
                "/etc/passwd",
                "\\windows\\system32",
                "/proc/self/environ"
            ]
        },
        {
            "name": "Command Injection Patterns",
            "type": "command_injection",
            "signatures": [
                "; cat",
                "| ls",
                "`whoami`",
                "$(id)",
                "&& uname"
            ]
        }
    ]
}
EOF

# Behavioral Baseline (empty initially)
cat > "${CONFIG_DIR}/behavioral_baseline.json" << 'EOF'
{
    "baselines": {},
    "created_at": null,
    "last_updated": null
}
EOF

# Check for required dependencies
echo "Checking Python dependencies..."
python3 -c "
import sys
required_modules = [
    'sqlite3', 'json', 'time', 'threading', 'logging', 
    'collections', 'datetime', 'ipaddress', 'hashlib',
    'numpy', 'requests'
]

missing = []
for module in required_modules:
    try:
        __import__(module)
    except ImportError:
        missing.append(module)

if missing:
    print('Missing required Python modules:', ', '.join(missing))
    sys.exit(1)
else:
    print('All required Python modules are available')
"

# Try to import optional modules
echo "Checking optional dependencies..."
python3 -c "
optional_modules = ['scapy', 'geoip2', 'psutil']
available = []
missing = []

for module in optional_modules:
    try:
        __import__(module)
        available.append(module)
    except ImportError:
        missing.append(module)

if available:
    print('Available optional modules:', ', '.join(available))
if missing:
    print('Missing optional modules (install for full functionality):', ', '.join(missing))
    print('Install with: pkg install', ' '.join(['py39-' + m.replace('geoip2', 'geoip2-python') for m in missing]))
"

# Download GeoIP database if not present
GEOIP_DIR="/usr/local/share/GeoIP"
GEOIP_DB="${GEOIP_DIR}/GeoLite2-Country.mmdb"

if [ ! -f "${GEOIP_DB}" ]; then
    echo "GeoIP database not found. Geographic blocking will be disabled."
    echo "To enable geographic features, install GeoIP database:"
    echo "  pkg install GeoIP"
    echo "  or download manually to ${GEOIP_DB}"
fi

# Set up log rotation
echo "Setting up log rotation..."
cat > /usr/local/etc/newsyslog.conf.d/webguard << 'EOF'
# WebGuard log rotation
/var/log/webguard/*.log    root:wheel  644  7  100  *  J  /var/run/webguard.pid  30
EOF

# Enable webguard in rc.conf if not already enabled
if ! grep -q "webguard_enable" /etc/rc.conf; then
    echo 'webguard_enable="NO"' >> /etc/rc.conf
    echo "Added webguard_enable to /etc/rc.conf (disabled by default)"
fi

# Create initial database
echo "Initializing database..."
python3 << 'EOF'
import sqlite3
import os

db_file = '/var/db/webguard/webguard.db'
os.makedirs(os.path.dirname(db_file), exist_ok=True)

conn = sqlite3.connect(db_file)
conn.execute('PRAGMA journal_mode=WAL')

# Create tables
conn.executescript('''
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

conn.commit()
conn.close()
print("Database initialized successfully")
EOF

# Set proper ownership for all files
chown -R root:wheel "${CONFIG_DIR}"
chown -R root:wheel "${LOG_DIR}"
chown -R root:wheel "${DB_DIR}"
chown -R root:wheel "${SCRIPTS_DIR}"

echo ""
echo "============================================"
echo "WebGuard Plugin Setup Complete!"
echo "============================================"
echo ""
echo "Configuration directory: ${CONFIG_DIR}"
echo "Log directory: ${LOG_DIR}"
echo "Database directory: ${DB_DIR}"
echo "Scripts directory: ${SCRIPTS_DIR}"
echo ""
echo "To enable WebGuard:"
echo "1. Configure the plugin via the OPNsense web interface"
echo "2. Enable the service: sysrc webguard_enable=YES"
echo "3. Start the service: service webguard start"
echo ""
echo "For optimal functionality, install optional dependencies:"
echo "  pkg install py39-scapy py39-geoip2-python py39-psutil"
echo ""
echo "Check service status: service webguard status"
echo "View logs: tail -f ${LOG_DIR}/engine.log"
echo ""
echo "Setup completed successfully!"