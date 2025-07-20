#!/usr/local/bin/python3.11

"""
WebGuard Engine - Main Web Application Firewall and Behavioral Analysis Engine
Copyright (C) 2024 OPNsense WebGuard Plugin
All rights reserved.
"""

import sys
import os
import json
import time
import signal
import threading
import logging
import hashlib
import struct
import re
import sqlite3
from collections import defaultdict, deque
from datetime import datetime
import socket
import subprocess
import xml.etree.ElementTree as ET

# Import support functions from separate files
try:
    from update_rules import download_rules
    from export_config import export_config
    from get_waf_stats import get_waf_stats
    from get_threat_metrics import get_threat_metrics
    from get_metrics import get_metrics
    from get_stats import get_stats as get_webguard_stats
except ImportError as e:
    print(f"Warning: Could not import support functions: {e}")
    # Define fallback functions
    def download_rules():
        return False
    def export_config():
        return False
    def get_waf_stats():
        return {}
    def get_threat_metrics():
        return {}
    def get_metrics():
        return {}
    def get_webguard_stats():
        return {}

# Network capture and analysis
try:
    import pcapy
    import dpkt
    import geoip2.database
    import numpy as np
    import requests
    from ipaddress import IPv4Address, IPv4Network
except ImportError as e:
    print(f"Error: Required packages not installed: {e}")
    print("Install with: pkg install py311-pcapy py311-dpkt py311-geoip2 py311-numpy py311-requests")
    sys.exit(1)

# Configuration and logging
CONFIG_FILE = "/usr/local/etc/webguard/config.json"
WAF_RULES_FILE = "/usr/local/etc/webguard/waf_rules.json"
ATTACK_PATTERNS_FILE = "/usr/local/etc/webguard/attack_patterns.json"
BEHAVIORAL_BASELINE_FILE = "/usr/local/etc/webguard/behavioral_baseline.json"
OPNSENSE_CONFIG = "/conf/config.xml"
LOG_DIR = "/var/log/webguard"
ALERT_LOG = f"{LOG_DIR}/alerts.log"
THREAT_LOG = f"{LOG_DIR}/threats.log"
BLOCKED_LOG = f"{LOG_DIR}/blocked.log"
WAF_LOG = f"{LOG_DIR}/waf.log"
BEHAVIORAL_LOG = f"{LOG_DIR}/behavioral.log"
COVERT_LOG = f"{LOG_DIR}/covert_channels.log"
ENGINE_LOG = f"{LOG_DIR}/engine.log"
STATS_FILE = f"{LOG_DIR}/stats.json"
DB_FILE = "/var/db/webguard/webguard.db"
PID_FILE = "/var/run/webguard.pid"

# Global state
running = True
config = {}
waf_rules = {}
attack_patterns = {}
behavioral_baselines = {}
stats = {
    'requests_analyzed': 0,
    'threats_blocked': 0,
    'ips_blocked': 0,
    'start_time': time.time(),
    'protocols_analyzed': defaultdict(int),
    'threat_types': defaultdict(int),
    'detection_methods': defaultdict(int),
    'performance': {
        'cpu_usage': 0,
        'memory_usage': 0,
        'throughput_mbps': 0,
        'uptime': 0
    },
    'waf_stats': {
        'sql_injection_attempts': 0,
        'xss_attempts': 0,
        'csrf_attempts': 0,
        'lfi_attempts': 0,
        'rfi_attempts': 0,
        'blocked_requests': 0
    }
}

# WAF pattern matching
waf_patterns = {
    'sql_injection': [],
    'xss': [],
    'csrf': [],
    'lfi': [],
    'rfi': [],
    'command_injection': [],
    'generic_attacks': []
}

# Traffic analysis
packet_buffer = deque(maxlen=10000)
ip_stats = defaultdict(lambda: {'requests': 0, 'last_seen': 0, 'violations': 0, 'bytes_sent': 0, 'first_seen': 0})
blocked_ips = set()
whitelist = set()

# Database connection
db = None

def setup_logging():
    """Initialize logging system"""
    os.makedirs(LOG_DIR, exist_ok=True)
    
    # Create all log files if they don't exist
    for log_file in [ALERT_LOG, THREAT_LOG, BLOCKED_LOG, WAF_LOG, BEHAVIORAL_LOG, COVERT_LOG, ENGINE_LOG]:
        if not os.path.exists(log_file):
            with open(log_file, 'w') as f:
                pass  # Create empty file
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(ENGINE_LOG),
            logging.StreamHandler()
        ]
    )
    
    return logging.getLogger(__name__)

def setup_database():
    """Initialize SQLite database"""
    global db
    try:
        os.makedirs(os.path.dirname(DB_FILE), exist_ok=True)
        
        db = sqlite3.connect(DB_FILE, check_same_thread=False)
        db.execute('PRAGMA journal_mode=WAL')
        
        # Create tables
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
        logger.info("Database initialized successfully")
        return True
        
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        return False

def get_interface_mapping():
    """Get mapping of logical interface names to physical interfaces"""
    interface_map = {}
    
    try:
        # Parse OPNsense config.xml
        tree = ET.parse(OPNSENSE_CONFIG)
        root = tree.getroot()
        
        # Get interface mappings
        interfaces = root.find('interfaces')
        if interfaces is not None:
            for interface in interfaces:
                if_name = interface.tag
                if_element = interface.find('if')
                if if_element is not None:
                    physical_if = if_element.text
                    interface_map[if_name] = physical_if
                    logger.info(f"Mapped interface {if_name} -> {physical_if}")
                    
    except Exception as e:
        logger.error(f"Error parsing OPNsense config: {e}")
        
        # Fallback: try to get interfaces from system
        try:
            result = subprocess.run(['ifconfig', '-l'], capture_output=True, text=True)
            if result.returncode == 0:
                system_interfaces = result.stdout.strip().split()
                # Common mappings
                common_mappings = {
                    'lan': 'em0',
                    'wan': 'em1', 
                    'opt1': 'em2',
                    'opt2': 'em3'
                }
                for logical, physical in common_mappings.items():
                    if physical in system_interfaces:
                        interface_map[logical] = physical
                        logger.info(f"Fallback mapped {logical} -> {physical}")
                        
        except Exception as e2:
            logger.error(f"Error getting system interfaces: {e2}")
    
    return interface_map

def resolve_interfaces(logical_interfaces):
    """Convert logical interface names to physical interface names"""
    interface_map = get_interface_mapping()
    physical_interfaces = []
    
    # Ensure logical_interfaces is a list
    if isinstance(logical_interfaces, str):
        # Single interface string, make it a list
        logical_interfaces = [logical_interfaces]
    
    for logical_if in logical_interfaces:
        # Check if it's already a physical interface (starts with common prefixes)
        if logical_if.startswith(('em', 'igb', 'ix', 're', 'bge', 'vtnet')):
            # Already a physical interface
            physical_interfaces.append(logical_if)
            logger.info(f"Using physical interface directly: {logical_if}")
        elif logical_if in interface_map:
            # Map logical to physical
            physical_if = interface_map[logical_if]
            physical_interfaces.append(physical_if)
            logger.info(f"Resolved {logical_if} -> {physical_if}")
        else:
            # Unknown, use as-is but log warning
            physical_interfaces.append(logical_if)
            logger.warning(f"Could not resolve {logical_if}, using as-is")
    
    return physical_interfaces

def load_config():
    """Load WebGuard engine configuration"""
    global config
    try:
        # First try to export from OPNsense
        export_config()
        
        # Then load the configuration
        with open(CONFIG_FILE, 'r') as f:
            config = json.load(f)
            
        # Set defaults for missing values
        defaults = {
            'general': {
                'enabled': False,
                'interfaces': [],
                'log_level': 'info',
                'learning_period': 168,
                'auto_block_threshold': 5,
                'block_duration': 3600
            },
            'waf': {
                'sql_injection_protection': True,
                'xss_protection': True,
                'csrf_protection': True,
                'lfi_protection': True,
                'rfi_protection': True,
                'command_injection_protection': True
            },
            'behavioral': {
                'anomaly_detection': True,
                'beaconing_detection': True,
                'data_exfiltration_detection': True
            },
            'covert_channels': {
                'dns_tunneling_detection': True,
                'protocol_anomaly_detection': True
            },
            'response': {
                'auto_blocking': True,
                'notification_webhook': ""
            },
            'whitelist': {
                'trusted_sources': ["127.0.0.1/8", "10.0.0.0/8"]
            }
        }
        
        # Merge defaults with loaded config
        for section, values in defaults.items():
            if section not in config:
                config[section] = {}
            for key, default_value in values.items():
                if key not in config[section]:
                    config[section][key] = default_value
                    
        logger.info(f"Configuration loaded: {len(config)} sections")
        logger.info(f"Enabled: {config['general']['enabled']}")
        logger.info(f"Interfaces: {config['general']['interfaces']}")
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to load configuration: {e}")
        return False

def load_rules():
    """Load WAF rules and attack patterns"""
    global waf_rules, attack_patterns, behavioral_baselines, waf_patterns
    
    try:
        # Create rule files if they don't exist
        create_default_rule_files()
        
        # Load WAF rules
        try:
            logger.info(f"Loading WAF rules from: {WAF_RULES_FILE}")
            with open(WAF_RULES_FILE, 'r') as f:
                waf_rules = json.load(f)
            logger.info("WAF rules loaded successfully")
        except json.JSONDecodeError as e:
            logger.error(f"JSON error in WAF rules file: {e}")
            logger.info("Creating new default WAF rules file")
            create_default_waf_rules()
            with open(WAF_RULES_FILE, 'r') as f:
                waf_rules = json.load(f)
        except Exception as e:
            logger.error(f"Error loading WAF rules: {e}")
            create_default_waf_rules()
            with open(WAF_RULES_FILE, 'r') as f:
                waf_rules = json.load(f)
            
        # Load attack patterns
        try:
            logger.info(f"Loading attack patterns from: {ATTACK_PATTERNS_FILE}")
            with open(ATTACK_PATTERNS_FILE, 'r') as f:
                attack_patterns = json.load(f)
            logger.info("Attack patterns loaded successfully")
        except json.JSONDecodeError as e:
            logger.error(f"JSON error in attack patterns file: {e}")
            logger.info("Creating new default attack patterns file")
            create_default_attack_patterns()
            with open(ATTACK_PATTERNS_FILE, 'r') as f:
                attack_patterns = json.load(f)
        except Exception as e:
            logger.error(f"Error loading attack patterns: {e}")
            create_default_attack_patterns()
            with open(ATTACK_PATTERNS_FILE, 'r') as f:
                attack_patterns = json.load(f)
            
        # Load behavioral baselines
        try:
            logger.info(f"Loading behavioral baselines from: {BEHAVIORAL_BASELINE_FILE}")
            with open(BEHAVIORAL_BASELINE_FILE, 'r') as f:
                behavioral_baselines = json.load(f)
            logger.info("Behavioral baselines loaded successfully")
        except json.JSONDecodeError as e:
            logger.error(f"JSON error in behavioral baselines file: {e}")
            logger.info("Creating new default behavioral baselines file")
            create_default_behavioral_baselines()
            with open(BEHAVIORAL_BASELINE_FILE, 'r') as f:
                behavioral_baselines = json.load(f)
        except Exception as e:
            logger.error(f"Error loading behavioral baselines: {e}")
            create_default_behavioral_baselines()
            with open(BEHAVIORAL_BASELINE_FILE, 'r') as f:
                behavioral_baselines = json.load(f)
        
        # Compile WAF patterns for faster matching
        compile_waf_patterns()
                
        logger.info("All rules and patterns loaded successfully")
        return True
        
    except Exception as e:
        logger.error(f"Critical error loading rules: {e}")
        load_default_rules()
        return False

def create_default_rule_files():
    """Create default rule files if they don't exist"""
    # Ensure directory exists
    os.makedirs(os.path.dirname(WAF_RULES_FILE), exist_ok=True)
    
    # Create WAF rules file
    if not os.path.exists(WAF_RULES_FILE):
        create_default_waf_rules()
    
    # Create attack patterns file
    if not os.path.exists(ATTACK_PATTERNS_FILE):
        create_default_attack_patterns()
    
    # Create behavioral baselines file
    if not os.path.exists(BEHAVIORAL_BASELINE_FILE):
        create_default_behavioral_baselines()

def create_default_waf_rules():
    """Create default WAF rules file"""
    default_waf_rules = {
        "version": "1.0",
        "updated": datetime.now().isoformat(),
        "rules": [
            {
                "id": 1,
                "name": "SQL Injection - UNION SELECT",
                "type": "sql_injection",
                "pattern": "union\\s+select",
                "enabled": True,
                "score": 50,
                "description": "Detects UNION SELECT SQL injection attempts"
            },
            {
                "id": 2,
                "name": "SQL Injection - OR 1=1",
                "type": "sql_injection",
                "pattern": "or\\s+1\\s*=\\s*1",
                "enabled": True,
                "score": 45,
                "description": "Detects classic OR 1=1 SQL injection"
            },
            {
                "id": 3,
                "name": "XSS - Script Tag",
                "type": "xss",
                "pattern": "<script[^>]*>.*?</script>",
                "enabled": True,
                "score": 40,
                "description": "Detects script tag XSS attempts"
            },
            {
                "id": 4,
                "name": "XSS - JavaScript Protocol",
                "type": "xss",
                "pattern": "javascript:",
                "enabled": True,
                "score": 35,
                "description": "Detects javascript: protocol XSS"
            },
            {
                "id": 5,
                "name": "Command Injection",
                "type": "command_injection",
                "pattern": "[\\;\\|&`\\$\\(\\)].*?(ls|cat|wget|curl|nc)",
                "enabled": True,
                "score": 60,
                "description": "Detects command injection attempts"
            },
            {
                "id": 6,
                "name": "Path Traversal",
                "type": "lfi",
                "pattern": "\\.\\.\\/.*?\\.\\.\\/.*?\\.\\.\/",
                "enabled": True,
                "score": 45,
                "description": "Detects directory traversal attempts"
            }
        ]
    }
    
    try:
        with open(WAF_RULES_FILE, 'w') as f:
            json.dump(default_waf_rules, f, indent=2)
        logger.info(f"Created default WAF rules: {WAF_RULES_FILE}")
    except Exception as e:
        logger.error(f"Error creating default WAF rules: {e}")

def create_default_attack_patterns():
    """Create default attack patterns file"""
    default_attack_patterns = {
        "version": "1.0",
        "updated": datetime.now().isoformat(),
        "patterns": {
            "malware_signatures": [
                "X5O!P%@AP\\[4\\\\PZX54\\(P\\^\\)7CC\\)7\\}\\$EICAR",
                "TVqQAAMAAAAEAAAA//8AALgAAAAA"
            ],
            "crypto_mining": [
                "coinhive",
                "cryptonight",
                "monero",
                "stratum"
            ],
            "suspicious_urls": [
                "bit\\.ly",
                "tinyurl\\.com",
                "t\\.co"
            ],
            "data_exfiltration": [
                "base64",
                "data:image",
                "data:text"
            ]
        }
    }
    
    try:
        with open(ATTACK_PATTERNS_FILE, 'w') as f:
            json.dump(default_attack_patterns, f, indent=2)
        logger.info(f"Created default attack patterns: {ATTACK_PATTERNS_FILE}")
    except Exception as e:
        logger.error(f"Error creating default attack patterns: {e}")

def create_default_behavioral_baselines():
    """Create default behavioral baselines file"""
    default_behavioral_baselines = {
        "version": "1.0",
        "updated": datetime.now().isoformat(),
        "baselines": {
            "normal_request_rate": {
                "min": 1,
                "max": 100,
                "avg": 10
            },
            "normal_payload_size": {
                "min": 100,
                "max": 10000,
                "avg": 2000
            },
            "beaconing_thresholds": {
                "min_frequency": 0.05,
                "max_frequency": 0.5,
                "min_requests": 10
            },
            "data_exfiltration_thresholds": {
                "bytes_per_request": 50000,
                "total_bytes_threshold": 1000000
            }
        }
    }
    
    try:
        with open(BEHAVIORAL_BASELINE_FILE, 'w') as f:
            json.dump(default_behavioral_baselines, f, indent=2)
        logger.info(f"Created default behavioral baselines: {BEHAVIORAL_BASELINE_FILE}")
    except Exception as e:
        logger.error(f"Error creating default behavioral baselines: {e}")

def load_default_rules():
    """Load minimal default WAF rules"""
    global waf_patterns
    
    # Basic SQL injection patterns
    waf_patterns['sql_injection'] = [
        re.compile(r'union\s+select', re.IGNORECASE),
        re.compile(r'or\s+1\s*=\s*1', re.IGNORECASE),
        re.compile(r'drop\s+table', re.IGNORECASE),
        re.compile(r';\s*insert', re.IGNORECASE),
        re.compile(r';\s*delete', re.IGNORECASE)
    ]
    
    # XSS patterns
    waf_patterns['xss'] = [
        re.compile(r'<script[^>]*>.*?</script>', re.IGNORECASE | re.DOTALL),
        re.compile(r'javascript:', re.IGNORECASE),
        re.compile(r'on(load|error|click|mouseover)=', re.IGNORECASE)
    ]
    
    # Command injection patterns
    waf_patterns['command_injection'] = [
        re.compile(r'[\;\|&`\$\(\)].*?(ls|cat|wget|curl|nc|netcat)', re.IGNORECASE),
        re.compile(r'(cmd\.exe|powershell|bash|sh).*?[\;\|&]', re.IGNORECASE)
    ]
    
    # LFI patterns
    waf_patterns['lfi'] = [
        re.compile(r'\.\.\/.*?\.\.\/.*?\.\.\/', re.IGNORECASE),
        re.compile(r'\/etc\/passwd', re.IGNORECASE),
        re.compile(r'\\windows\\system32', re.IGNORECASE)
    ]
    
    # RFI patterns
    waf_patterns['rfi'] = [
        re.compile(r'https?:\/\/[^\/\s]+\/', re.IGNORECASE)
    ]

def compile_waf_patterns():
    """Compile WAF patterns from rules"""
    global waf_patterns
    
    try:
        for rule in waf_rules.get('rules', []):
            if rule.get('enabled', True):
                pattern = rule.get('pattern', '')
                rule_type = rule.get('type', 'generic_attacks')
                
                if pattern and rule_type in waf_patterns:
                    compiled_pattern = re.compile(pattern, re.IGNORECASE)
                    waf_patterns[rule_type].append(compiled_pattern)
                    
    except Exception as e:
        logger.error(f"Error compiling WAF patterns: {e}")

def load_blocked_ips():
    """Load blocked IPs from database"""
    global blocked_ips
    try:
        cursor = db.execute('''
            SELECT ip_address FROM blocked_ips 
            WHERE expires_at IS NULL OR expires_at > ?
        ''', (int(time.time()),))
        
        blocked_ips = set(row[0] for row in cursor.fetchall())
        logger.info(f"Loaded {len(blocked_ips)} blocked IPs")
        
    except Exception as e:
        logger.error(f"Error loading blocked IPs: {e}")

def load_whitelist():
    """Load whitelist from database"""
    global whitelist
    try:
        cursor = db.execute('''
            SELECT ip_address FROM whitelist 
            WHERE expires_at IS NULL OR expires_at > ?
        ''', (int(time.time()),))
        
        whitelist = set(row[0] for row in cursor.fetchall())
        logger.info(f"Loaded {len(whitelist)} whitelisted IPs")
        
    except Exception as e:
        logger.error(f"Error loading whitelist: {e}")

def analyze_packet(packet_data, timestamp, interface='unknown'):
    """Analyze individual packet for threats"""
    global stats, ip_stats
    
    try:
        # Parse packet
        eth = dpkt.ethernet.Ethernet(packet_data)
        if not isinstance(eth.data, dpkt.ip.IP):
            return
            
        ip = eth.data
        stats['requests_analyzed'] += 1
        
        # Protocol analysis
        protocol = get_protocol_name(ip.p)
        stats['protocols_analyzed'][protocol] += 1
        
        # Update IP statistics
        src_ip = socket.inet_ntoa(ip.src)
        dst_ip = socket.inet_ntoa(ip.dst)
        
        current_time = time.time()
        if src_ip not in ip_stats:
            ip_stats[src_ip] = {
                'requests': 0,
                'first_seen': current_time,
                'last_seen': current_time,
                'violations': 0,
                'bytes_sent': 0
            }
        
        ip_stats[src_ip]['requests'] += 1
        ip_stats[src_ip]['last_seen'] = current_time
        
        # Check if IP is whitelisted
        if is_whitelisted(src_ip):
            return
        
        # Check if IP is already blocked
        if is_blocked(src_ip):
            stats['threats_blocked'] += 1
            return
        
        # Deep packet inspection based on protocol
        threats = []
        
        if ip.p == dpkt.ip.IP_PROTO_TCP:
            tcp = ip.data
            threats.extend(analyze_tcp_packet(ip, tcp))
                
        elif ip.p == dpkt.ip.IP_PROTO_UDP:
            udp = ip.data
            threats.extend(analyze_udp_packet(ip, udp))
        
        # Process detected threats
        for threat in threats:
            process_threat(threat, ip, timestamp)
            
    except Exception as e:
        logger.error(f"Error analyzing packet: {e}")

def analyze_tcp_packet(ip, tcp):
    """Analyze TCP packet for threats"""
    threats = []
    
    try:
        payload = tcp.data
        if not payload:
            return threats
            
        # HTTP/HTTPS analysis
        if tcp.dport == 80 or tcp.sport == 80:
            if config['waf']['sql_injection_protection']:
                threats.extend(analyze_http_payload(payload))
                
        elif tcp.dport == 443 or tcp.sport == 443:
            threats.extend(analyze_https_payload(payload))
                
        # Generic payload analysis
        threats.extend(analyze_generic_payload(payload))
        
    except Exception as e:
        logger.error(f"Error analyzing TCP packet: {e}")
        
    return threats

def analyze_udp_packet(ip, udp):
    """Analyze UDP packet for threats"""
    threats = []
    
    try:
        payload = udp.data
        if not payload:
            return threats
            
        # DNS analysis
        if udp.dport == 53 or udp.sport == 53:
            if config['covert_channels']['dns_tunneling_detection']:
                threats.extend(analyze_dns_payload(payload))
                
        # Generic payload analysis
        threats.extend(analyze_generic_payload(payload))
        
    except Exception as e:
        logger.error(f"Error analyzing UDP packet: {e}")
        
    return threats

def analyze_http_payload(payload):
    """Analyze HTTP payload for web application attacks"""
    threats = []
    
    try:
        payload_str = payload.decode('utf-8', errors='ignore')
        
        # Check against WAF patterns
        for pattern_type, patterns in waf_patterns.items():
            for pattern in patterns:
                if pattern.search(payload_str):
                    threat_score = calculate_threat_score(pattern_type)
                    severity = get_severity_from_score(threat_score)
                    
                    threat = {
                        'type': pattern_type,
                        'severity': severity,
                        'score': threat_score,
                        'description': f'{pattern_type.replace("_", " ").title()} attack detected in HTTP',
                        'pattern': pattern.pattern,
                        'payload': payload_str[:1000]  # Limit payload size
                    }
                    threats.append(threat)
                    stats['waf_stats'][f'{pattern_type}_attempts'] += 1
                    
    except Exception as e:
        logger.error(f"Error analyzing HTTP payload: {e}")
        
    return threats

def analyze_https_payload(payload):
    """Analyze HTTPS payload for threats (limited without decryption)"""
    threats = []
    
    try:
        # Basic TLS analysis
        if len(payload) < 5:
            return threats
            
        # Check for TLS handshake anomalies
        if payload[0] == 0x16:  # TLS handshake
            tls_version = struct.unpack('>H', payload[1:3])[0]
            if tls_version < 0x0301:  # TLS 1.0 or older
                threats.append({
                    'type': 'tls_vulnerability',
                    'severity': 'low',
                    'score': 10,
                    'description': f'Outdated TLS version: {tls_version:04x}',
                    'details': {'tls_version': tls_version}
                })
                
    except Exception as e:
        logger.error(f"Error analyzing HTTPS payload: {e}")
        
    return threats

def analyze_dns_payload(payload):
    """Analyze DNS payload for threats"""
    threats = []
    
    try:
        # Basic DNS analysis
        if len(payload) < 12:
            return threats
            
        # Check for DNS tunneling (unusually large queries)
        if len(payload) > 512:
            threats.append({
                'type': 'dns_tunneling',
                'severity': 'medium',
                'score': 30,
                'description': 'Potential DNS tunneling detected',
                'details': {'payload_size': len(payload)}
            })
            
    except Exception as e:
        logger.error(f"Error analyzing DNS payload: {e}")
        
    return threats

def analyze_generic_payload(payload):
    """Analyze generic payload for threats"""
    threats = []
    
    try:
        # Convert to string for pattern matching
        payload_str = payload.decode('utf-8', errors='ignore')
        
        # Check for suspicious patterns
        suspicious_patterns = [
            (r'X5O!P%@AP\[4\\PZX54\(P\^\)7CC\)7\}\$EICAR', 'eicar_test'),
            (r'TVqQAAMAAAAEAAAA//8AALgAAAAA', 'pe_header'),
            (r'(coinhive|cryptonight|monero)', 'crypto_mining')
        ]
        
        for pattern_str, threat_type in suspicious_patterns:
            pattern = re.compile(pattern_str, re.IGNORECASE)
            if pattern.search(payload_str):
                threats.append({
                    'type': threat_type,
                    'severity': 'medium',
                    'score': 25,
                    'description': f'{threat_type.replace("_", " ").title()} detected',
                    'pattern': pattern_str
                })
                
    except Exception as e:
        logger.error(f"Error analyzing generic payload: {e}")
        
    return threats

def calculate_threat_score(threat_type):
    """Calculate threat score based on type"""
    score_map = {
        'sql_injection': 50,
        'xss': 40,
        'command_injection': 60,
        'lfi': 45,
        'rfi': 45,
        'csrf': 30,
        'dns_tunneling': 35,
        'crypto_mining': 25,
        'eicar_test': 100,
        'pe_header': 80
    }
    return score_map.get(threat_type, 20)

def get_severity_from_score(score):
    """Get severity level from threat score"""
    if score >= 80:
        return 'critical'
    elif score >= 50:
        return 'high'
    elif score >= 30:
        return 'medium'
    else:
        return 'low'

def process_threat(threat, ip, timestamp):
    """Process detected threat"""
    global stats
    
    stats['threats_blocked'] += 1
    stats['threat_types'][threat['type']] += 1
    
    src_ip = socket.inet_ntoa(ip.src)
    dst_ip = socket.inet_ntoa(ip.dst)
    
    # Update IP violation count
    ip_stats[src_ip]['violations'] += 1
    
    # Log threat
    log_threat(threat, ip, timestamp)
    
    # Auto-block if threshold exceeded
    if config['response']['auto_blocking']:
        threshold = config['general']['auto_block_threshold']
        if ip_stats[src_ip]['violations'] >= threshold:
            block_ip(src_ip, threat)

def log_threat(threat, ip, timestamp):
    """Log threat to appropriate log files"""
    try:
        src_ip = socket.inet_ntoa(ip.src)
        dst_ip = socket.inet_ntoa(ip.dst)
        
        threat_record = {
            'id': hashlib.md5(f"{timestamp}{src_ip}{dst_ip}{threat['type']}".encode()).hexdigest(),
            'timestamp': timestamp.isoformat(),
            'source_ip': src_ip,
            'destination_ip': dst_ip,
            'protocol': get_protocol_name(ip.p),
            'threat_type': threat['type'],
            'severity': threat['severity'],
            'score': threat['score'],
            'description': threat['description'],
            'pattern': threat.get('pattern', ''),
            'payload': threat.get('payload', '')[:500]  # Limit payload
        }
        
        # Log to main threat log
        with open(THREAT_LOG, 'a') as f:
            f.write(json.dumps(threat_record) + '\n')
        
        # Log to specific category log
        if threat['type'] in ['sql_injection', 'xss', 'csrf', 'lfi', 'rfi']:
            with open(WAF_LOG, 'a') as f:
                f.write(json.dumps(threat_record) + '\n')
        elif threat['type'] in ['dns_tunneling']:
            with open(COVERT_LOG, 'a') as f:
                f.write(json.dumps(threat_record) + '\n')
        
        # Store in database
        store_threat_in_db(threat_record)
        
        logger.warning(f"THREAT DETECTED - IP: {src_ip}, Type: {threat['type']}, Severity: {threat['severity']}")
        
    except Exception as e:
        logger.error(f"Error logging threat: {e}")

def store_threat_in_db(threat_record):
    """Store threat in database"""
    try:
        db.execute('''
            INSERT INTO threats (timestamp, source_ip, target, method, type, severity, status, score, payload, rule_matched, description)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            int(time.time()),
            threat_record['source_ip'],
            threat_record['destination_ip'],
            threat_record['protocol'],
            threat_record['threat_type'],
            threat_record['severity'],
            'detected',
            threat_record['score'],
            threat_record.get('payload', ''),
            threat_record.get('pattern', ''),
            threat_record['description']
        ))
        db.commit()
        
    except Exception as e:
        logger.error(f"Error storing threat in database: {e}")

def block_ip(ip_address, threat):
    """Block IP address"""
    try:
        current_time = int(time.time())
        block_duration = config['general']['block_duration']
        expires_at = current_time + block_duration if block_duration > 0 else None
        
        # Store in database
        db.execute('''
            INSERT OR REPLACE INTO blocked_ips 
            (ip_address, block_type, blocked_since, expires_at, reason, violations, last_violation)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (ip_address, 'automatic', current_time, expires_at, 
              f"Auto-blocked after {ip_stats[ip_address]['violations']} violations", 
              ip_stats[ip_address]['violations'], current_time))
        
        db.commit()
        blocked_ips.add(ip_address)
        
        # Log blocking
        block_record = {
            'timestamp': datetime.now().isoformat(),
            'ip_address': ip_address,
            'reason': f"Auto-blocked after {ip_stats[ip_address]['violations']} violations",
            'threat_type': threat['type'],
            'severity': threat['severity']
        }
        
        with open(BLOCKED_LOG, 'a') as f:
            f.write(json.dumps(block_record) + '\n')
        
        stats['ips_blocked'] += 1
        logger.info(f"BLOCKED IP: {ip_address} - Reason: {block_record['reason']}")
        
    except Exception as e:
        logger.error(f"Error blocking IP {ip_address}: {e}")

def is_blocked(ip_address):
    """Check if IP is blocked"""
    return ip_address in blocked_ips

def is_whitelisted(ip_address_str):
    """Check if IP is whitelisted"""
    if ip_address_str in whitelist:
        return True
    
    # Check if IP is in whitelisted networks
    try:
        for trusted_network in config.get('whitelist', {}).get('trusted_sources', []):
            try:
                ip_obj = IPv4Address(ip_address_str)
                network_obj = IPv4Network(trusted_network, strict=False)
                if ip_obj in network_obj:
                    return True
            except Exception as e:
                logger.debug(f"Error checking network {trusted_network} for IP {ip_address_str}: {e}")
                continue
    except Exception as e:
        logger.error(f"Error checking whitelist for {ip_address_str}: {e}")
    
    return False

def get_protocol_name(protocol_number):
    """Get protocol name from number"""
    protocol_map = {
        1: 'ICMP',
        6: 'TCP',
        17: 'UDP',
        47: 'GRE',
        50: 'ESP',
        51: 'AH'
    }
    return protocol_map.get(protocol_number, f'Protocol-{protocol_number}')

def save_stats():
    """Save statistics to file"""
    try:
        # Update performance stats
        stats['performance']['uptime'] = int(time.time() - stats['start_time'])
        
        # Update stats with data from imported functions
        try:
            waf_stats = get_waf_stats()
            if 'error' not in waf_stats:
                stats['waf_stats'].update(waf_stats)
        except Exception as e:
            logger.error(f"Error getting WAF stats: {e}")
            
        try:
            threat_metrics = get_threat_metrics()
            if 'error' not in threat_metrics:
                stats['threat_metrics'] = threat_metrics
        except Exception as e:
            logger.error(f"Error getting threat metrics: {e}")
            
        try:
            system_metrics = get_metrics()
            if 'error' not in system_metrics:
                stats['performance']['cpu_usage'] = system_metrics.get('system', {}).get('cpu_usage', 0)
                stats['performance']['memory_usage'] = system_metrics.get('system', {}).get('memory_usage', 0)
        except Exception as e:
            logger.error(f"Error getting system metrics: {e}")
            
        try:
            comprehensive_stats = get_webguard_stats()
            if 'error' not in comprehensive_stats:
                stats['threats_by_severity'] = comprehensive_stats.get('threats_by_severity', {})
                stats['top_threats'] = comprehensive_stats.get('top_threats', [])
                stats['recent_threats'] = comprehensive_stats.get('recent_threats', [])
                stats['detection_rate_trend'] = comprehensive_stats.get('detection_rate_trend', [])
                
        except Exception as e:
            logger.error(f"Error getting comprehensive stats: {e}")
        
        stats['timestamp'] = datetime.now().isoformat()
        with open(STATS_FILE, 'w') as f:
            json.dump(stats, f, indent=2, default=str)
            
    except Exception as e:
        logger.error(f"Error saving stats: {e}")

def cleanup_expired_blocks():
    """Remove expired IP blocks"""
    try:
        current_time = int(time.time())
        
        cursor = db.execute('''
            SELECT ip_address FROM blocked_ips 
            WHERE expires_at IS NOT NULL AND expires_at <= ?
        ''', (current_time,))
        
        expired_ips = [row[0] for row in cursor.fetchall()]
        
        if expired_ips:
            db.execute('''
                DELETE FROM blocked_ips 
                WHERE expires_at IS NOT NULL AND expires_at <= ?
            ''', (current_time,))
            
            db.commit()
            
            for ip in expired_ips:
                blocked_ips.discard(ip)
            
            logger.info(f"Cleaned up {len(expired_ips)} expired blocks")
            
    except Exception as e:
        logger.error(f"Error cleaning up expired blocks: {e}")

def behavioral_analyzer():
    """Analyze behavioral patterns in background thread"""
    while running:
        try:
            if config.get('behavioral', {}).get('anomaly_detection', True):
                analyze_behavioral_anomalies()
            time.sleep(30)  # Analyze every 30 seconds
        except Exception as e:
            logger.error(f"Error in behavioral analyzer: {e}")
            time.sleep(60)

def analyze_behavioral_anomalies():
    """Analyze traffic for behavioral anomalies"""
    current_time = time.time()
    
    for ip, ip_data in ip_stats.items():
        if current_time - ip_data['last_seen'] > 300:  # Skip old entries
            continue
        
        # Check for beaconing patterns
        if detect_beaconing(ip, ip_data):
            threat = {
                'type': 'beaconing',
                'severity': 'high',
                'score': 45,
                'description': 'Suspicious beaconing pattern detected',
                'details': {'ip': ip, 'requests': ip_data['requests']}
            }
            
            # Create a fake IP packet for logging
            fake_ip = type('obj', (object,), {
                'src': socket.inet_aton(ip),
                'dst': socket.inet_aton('0.0.0.0'),
                'p': 6  # TCP
            })
            
            process_threat(threat, fake_ip, datetime.now())
        
        # Check for data exfiltration
        if detect_data_exfiltration(ip, ip_data):
            threat = {
                'type': 'data_exfiltration',
                'severity': 'critical',
                'score': 70,
                'description': 'Potential data exfiltration detected',
                'details': {'ip': ip, 'bytes_sent': ip_data['bytes_sent']}
            }
            
            # Create a fake IP packet for logging
            fake_ip = type('obj', (object,), {
                'src': socket.inet_aton(ip),
                'dst': socket.inet_aton('0.0.0.0'),
                'p': 6  # TCP
            })
            
            process_threat(threat, fake_ip, datetime.now())

def detect_beaconing(ip, ip_data):
    """Detect C2 beaconing patterns"""
    if not config.get('behavioral', {}).get('beaconing_detection', True):
        return False
    
    # Simplified beaconing detection
    request_count = ip_data.get('requests', 0)
    time_span = time.time() - ip_data.get('first_seen', time.time())
    
    if time_span > 0 and request_count > 10:
        frequency = request_count / time_span
        # Regular intervals might indicate beaconing
        return 0.05 < frequency < 0.5
    
    return False

def detect_data_exfiltration(ip, ip_data):
    """Detect potential data exfiltration"""
    if not config.get('behavioral', {}).get('data_exfiltration_detection', True):
        return False
    
    # Check for unusual data volumes
    bytes_sent = ip_data.get('bytes_sent', 0)
    requests = ip_data.get('requests', 0)
    
    if requests > 0:
        avg_bytes_per_request = bytes_sent / requests
        # Unusually large amounts of data per request
        return avg_bytes_per_request > 50000
    
    return False

def signal_handler(signum, frame):
    """Handle shutdown signals"""
    global running
    logger.info(f"Received signal {signum}, shutting down...")
    running = False

def main():
    """Main WebGuard engine loop"""
    global logger, running
    
    # Setup
    logger = setup_logging()
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    
    # Check if running as root (required for packet capture)
    if os.geteuid() != 0:
        logger.error("This script must be run as root for packet capture")
        return 1
    
    # Save PID
    try:
        with open(PID_FILE, 'w') as f:
            f.write(str(os.getpid()))
    except Exception as e:
        logger.error(f"Failed to write PID file: {e}")
        return 1
    
    logger.info("Starting WebGuard Engine")
    
    # Initialize database
    if not setup_database():
        logger.error("Failed to initialize database")
        return 1
    
    # Load configuration and rules
    if not load_config():
        logger.error("Failed to load configuration")
        return 1
        
    if not load_rules():
        logger.warning("Using default rules")
    
    # Load IP lists
    load_blocked_ips()
    load_whitelist()
        
    # Check if enabled
    if not config['general']['enabled']:
        logger.info("WebGuard engine is disabled in configuration")
        return 0
        
    # Get and resolve interfaces
    logical_interfaces = config['general']['interfaces']
    if not logical_interfaces:
        logger.error("No interfaces configured for monitoring")
        return 1
        
    # Handle different interface formats
    if isinstance(logical_interfaces, str):
        # If it's a single interface string, convert to list
        if ',' in logical_interfaces:
            # If it's a comma-separated string, split it
            logical_interfaces = [iface.strip() for iface in logical_interfaces.split(',') if iface.strip()]
        else:
            # If it's a single interface, make it a list
            logical_interfaces = [logical_interfaces.strip()]
    elif not isinstance(logical_interfaces, list):
        logger.error(f"Invalid interfaces format: {type(logical_interfaces)}")
        return 1
        
    # Filter out empty or invalid interface names
    logical_interfaces = [iface for iface in logical_interfaces if iface and len(iface) > 1]
    
    if not logical_interfaces:
        logger.error("No valid interfaces found in configuration")
        return 1
        
    logger.info(f"Logical interfaces to resolve: {logical_interfaces}")
        
    # Convert logical interface names to physical interface names
    physical_interfaces = resolve_interfaces(logical_interfaces)
    if not physical_interfaces:
        logger.error("No valid interfaces found after resolution")
        return 1
        
    logger.info(f"Starting packet capture on interfaces: {physical_interfaces}")
    
    # Validate interfaces exist
    valid_interfaces = []
    for interface in physical_interfaces:
        try:
            result = subprocess.run(['ifconfig', interface], capture_output=True, text=True)
            if result.returncode == 0:
                valid_interfaces.append(interface)
                logger.info(f"Interface {interface} is valid and active")
            else:
                logger.error(f"Interface {interface} is not available")
        except Exception as e:
            logger.error(f"Error checking interface {interface}: {e}")
    
    if not valid_interfaces:
        logger.error("No valid interfaces found")
        return 1
        
    # Statistics thread
    def stats_worker():
        while running:
            save_stats()
            cleanup_expired_blocks()
            time.sleep(60)
    
    stats_thread = threading.Thread(target=stats_worker)
    stats_thread.daemon = True
    stats_thread.start()
    
    # Behavioral analysis thread
    behavioral_thread = threading.Thread(target=behavioral_analyzer)
    behavioral_thread.daemon = True
    behavioral_thread.start()
    
    # Rules update thread
    def rules_update_worker():
        while running:
            try:
                # Update rules every 24 hours
                time.sleep(86400)
                if running:
                    logger.info("Updating WAF rules...")
                    download_rules()
                    load_rules()
            except Exception as e:
                logger.error(f"Error in rules update thread: {e}")
    
    rules_thread = threading.Thread(target=rules_update_worker)
    rules_thread.daemon = True
    rules_thread.start()
    
    # Capture threads for each interface
    capture_threads = []
    
    def capture_worker(interface):
        """Worker function for packet capture on a specific interface"""
        logger.info(f"Starting capture worker for interface: {interface}")
        
        try:
            # Open packet capture
            cap = pcapy.open_live(interface, 
                                1500,  # max packet size
                                1,     # promiscuous mode
                                100)   # timeout in ms
            
            logger.info(f"Successfully opened capture on interface: {interface}")
            
            # Main capture loop
            while running:
                try:
                    header, packet = cap.next()
                    if packet:
                        analyze_packet(packet, datetime.now(), interface)
                except pcapy.PcapError as e:
                    if "timeout" not in str(e).lower():
                        logger.error(f"Pcap error on {interface}: {e}")
                        break
                except Exception as e:
                    logger.error(f"Error processing packet on {interface}: {e}")
                    
        except Exception as e:
            logger.error(f"Failed to open capture on interface {interface}: {e}")
            
        logger.info(f"Capture worker for {interface} stopped")
    
    # Start capture threads
    for interface in valid_interfaces:
        thread = threading.Thread(target=capture_worker, args=(interface,))
        thread.daemon = True
        capture_threads.append(thread)
        thread.start()
    
    # Main loop - wait for threads and handle signals
    try:
        logger.info("WebGuard Engine is running...")
        logger.info(f"Monitoring interfaces: {valid_interfaces}")
        logger.info(f"WAF protection enabled: {config['waf']['sql_injection_protection']}")
        logger.info(f"Behavioral analysis enabled: {config['behavioral']['anomaly_detection']}")
        
        while running and any(thread.is_alive() for thread in capture_threads):
            time.sleep(1)
            
    except KeyboardInterrupt:
        logger.info("Received keyboard interrupt")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        return 1
    finally:
        # Cleanup
        running = False
        logger.info("Stopping all capture threads...")
        
        # Wait for threads to finish (with timeout)
        for thread in capture_threads:
            thread.join(timeout=5)
            
        save_stats()
        if db:
            db.close()
        if os.path.exists(PID_FILE):
            os.remove(PID_FILE)
        logger.info("WebGuard Engine stopped")
        
    return 0

if __name__ == "__main__":
    sys.exit(main())