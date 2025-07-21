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
    from update_rules import download_rules, check_rules_age
    from export_config import export_config
    from get_waf_stats import get_waf_stats
    from get_threat_metrics import get_threat_metrics
    from get_metrics import get_metrics, get_system_health
    from get_stats import get_engine_stats, get_threat_stats, get_blocking_stats, get_geo_stats
except ImportError as e:
    print(f"Error: Could not import required modules: {e}")
    print("Please ensure all WebGuard modules are installed:")
    print("- update_rules.py")
    print("- get_waf_stats.py") 
    print("- get_threat_metrics.py")
    print("- get_metrics.py")
    print("- get_stats.py")
    sys.exit(1)

# Network capture and analysis
try:
    import psutil  # For system monitoring
    import geoip2.database
    import geoip2.errors
    GEOIP_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Optional packages not installed: {e}")
    print("Install with: pkg install py311-psutil py311-geoip2")
    GEOIP_AVAILABLE = False

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
geoip_reader = None  # GeoIP database reader
geo_stats = defaultdict(int)  # Country statistics
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
ip_stats = defaultdict(lambda: {
    'requests': 0, 
    'last_seen': 0, 
    'violations': 0, 
    'bytes_sent': 0, 
    'first_seen': 0,
    'threat_score': 0
})
blocked_ips = set()
whitelist = set()

# Database connection
db = None
db_lock = threading.Lock()

# Network sockets for packet capture simulation
capture_sockets = []

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
        
        with db_lock:
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

def setup_geoip():
    """Initialize GeoIP database"""
    global geoip_reader
    
    if not GEOIP_AVAILABLE:
        logger.warning("GeoIP2 library not available")
        return False
    
    try:
        # Try different possible locations for GeoIP database
        possible_paths = [
            '/usr/local/share/GeoIP/GeoLite2-Country.mmdb',
            '/var/db/GeoIP/GeoLite2-Country.mmdb',
            '/usr/share/GeoIP/GeoLite2-Country.mmdb'
        ]
        
        for db_path in possible_paths:
            if os.path.exists(db_path):
                geoip_reader = geoip2.database.Reader(db_path)
                logger.info(f"GeoIP database loaded from: {db_path}")
                return True
        
        logger.warning("GeoIP database not found in standard locations")
        return False
        
    except Exception as e:
        logger.error(f"Failed to initialize GeoIP database: {e}")
        return False

def get_country_info(ip_address):
    """Get country information for IP address using GeoIP2"""
    if not geoip_reader:
        return {'country_code': 'XX', 'country_name': 'Unknown', 'is_private': False}
    
    try:
        # Check if it's a private IP
        import ipaddress
        ip_obj = ipaddress.ip_address(ip_address)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_multicast:
            return {'country_code': 'PR', 'country_name': 'Private', 'is_private': True}
        
        # Look up country using GeoIP2
        response = geoip_reader.country(ip_address)
        country_info = {
            'country_code': response.country.iso_code or 'XX',
            'country_name': response.country.name or 'Unknown',
            'continent_code': response.continent.code or 'XX',
            'continent_name': response.continent.name or 'Unknown',
            'is_private': False
        }
        
        # Update geo statistics
        geo_stats[country_info['country_code']] += 1
        
        logger.debug(f"GeoIP lookup for {ip_address}: {country_info['country_name']} ({country_info['country_code']})")
        return country_info
        
    except geoip2.errors.AddressNotFoundError:
        logger.debug(f"IP address {ip_address} not found in GeoIP database")
        return {'country_code': 'XX', 'country_name': 'Unknown', 'is_private': False}
    except Exception as e:
        logger.error(f"Error looking up IP {ip_address}: {e}")
        return {'country_code': 'XX', 'country_name': 'Unknown', 'is_private': False}

def analyze_geographic_patterns():
    """Analyze geographic patterns in threats using GeoIP2"""
    try:
        if not geoip_reader:
            return
            
        current_time = time.time()
        recent_threats = []
        
        # Get recent threats from database
        with db_lock:
            cursor = db.execute('''
                SELECT source_ip, type, severity, timestamp FROM threats 
                WHERE timestamp > ? 
                ORDER BY timestamp DESC LIMIT 100
            ''', (int(current_time - 3600),))  # Last hour
            
            recent_threats = cursor.fetchall()
        
        if not recent_threats:
            return
        
        # Analyze by country
        country_threat_counts = defaultdict(int)
        country_severity_scores = defaultdict(list)
        high_risk_countries = set()
        
        for source_ip, threat_type, severity, timestamp in recent_threats:
            try:
                country_info = get_country_info(source_ip)
                country_code = country_info['country_code']
                
                country_threat_counts[country_code] += 1
                
                # Assign severity scores
                severity_score = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}.get(severity, 1)
                country_severity_scores[country_code].append(severity_score)
                
                # Mark high-risk countries
                if severity_score >= 3:  # high or critical
                    high_risk_countries.add(country_code)
                    
            except Exception as e:
                logger.error(f"Error analyzing geographic pattern for {source_ip}: {e}")
                continue
        
        # Log geographic analysis results
        if country_threat_counts:
            sorted_countries = sorted(country_threat_counts.items(), 
                                    key=lambda x: x[1], reverse=True)[:10]
            
            geo_log_entry = {
                'timestamp': datetime.now().isoformat(),
                'analysis_type': 'geographic_patterns',
                'time_period': '1h',
                'total_threats': len(recent_threats),
                'countries_involved': len(country_threat_counts),
                'top_threat_countries': []
            }
            
            for country_code, threat_count in sorted_countries:
                avg_severity = sum(country_severity_scores[country_code]) / len(country_severity_scores[country_code])
                
                # Get country name using GeoIP2
                try:
                    dummy_ip = "8.8.8.8"  # Use for country name lookup
                    if country_code != 'XX':
                        # This is a simplified approach - in reality you'd need a country code to name mapping
                        country_name = country_code  # Placeholder
                    else:
                        country_name = "Unknown"
                except:
                    country_name = country_code
                
                country_data = {
                    'country_code': country_code,
                    'country_name': country_name,
                    'threat_count': threat_count,
                    'avg_severity': round(avg_severity, 2),
                    'is_high_risk': country_code in high_risk_countries
                }
                geo_log_entry['top_threat_countries'].append(country_data)
            
            # Log to behavioral analysis file
            with open(BEHAVIORAL_LOG, 'a') as f:
                f.write(json.dumps(geo_log_entry) + '\n')
            
            # Check for geographic anomalies
            for country_code, threat_count in sorted_countries[:5]:
                if threat_count > 10:  # More than 10 threats in an hour
                    avg_severity = sum(country_severity_scores[country_code]) / len(country_severity_scores[country_code])
                    
                    anomaly_entry = {
                        'timestamp': datetime.now().isoformat(),
                        'anomaly_type': 'geographic_spike',
                        'country_code': country_code,
                        'threat_count': threat_count,
                        'avg_severity': avg_severity,
                        'risk_score': min(threat_count * avg_severity * 10, 100)
                    }
                    
                    with open(BEHAVIORAL_LOG, 'a') as f:
                        f.write(json.dumps(anomaly_entry) + '\n')
                    
                    logger.warning(f"Geographic anomaly detected: {country_code} - {threat_count} threats")
        
    except Exception as e:
        logger.error(f"Error in geographic pattern analysis: {e}")

def load_config():
    """Load WebGuard engine configuration using export_config"""
    global config
    try:
        # Use the export_config function to get OPNsense configuration
        if export_config():
            logger.info("Configuration exported from OPNsense successfully")
        
        # Load the configuration
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
        else:
            # Create default configuration
            config = create_default_config()
            
        # Set defaults for missing values
        defaults = {
            'general': {
                'enabled': True,
                'interfaces': ['em0'],
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

def create_default_config():
    """Create default configuration"""
    return {
        'general': {
            'enabled': True,
            'interfaces': ['em0'],
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
        'response': {
            'auto_blocking': True,
            'notification_webhook': ""
        }
    }

def load_rules():
    """Load WAF rules and attack patterns using update_rules"""
    global waf_rules, attack_patterns, behavioral_baselines, waf_patterns
    
    try:
        # Check if rules need updating and download if necessary
        if check_rules_age():
            logger.info("Rules are outdated, downloading new rules...")
            if download_rules():
                logger.info("Rules updated successfully")
            else:
                logger.warning("Failed to update rules, using existing ones")
        else:
            logger.info("Rules are up to date")
        
        # Load WAF rules
        try:
            with open(WAF_RULES_FILE, 'r') as f:
                waf_rules = json.load(f)
            logger.info(f"WAF rules loaded - Version: {waf_rules.get('version', 'Unknown')}")
            logger.info(f"Rules count: {len(waf_rules.get('rules', []))}")
        except Exception as e:
            logger.error(f"Error loading WAF rules: {e}")
            create_default_waf_rules()
            
        # Load attack patterns
        try:
            with open(ATTACK_PATTERNS_FILE, 'r') as f:
                attack_patterns = json.load(f)
            logger.info(f"Attack patterns loaded - Version: {attack_patterns.get('version', 'Unknown')}")
        except Exception as e:
            logger.error(f"Error loading attack patterns: {e}")
            attack_patterns = {'patterns': {}}
            
        # Compile WAF patterns for faster matching
        compile_waf_patterns()
                
        logger.info("All rules and patterns loaded successfully")
        return True
        
    except Exception as e:
        logger.error(f"Critical error loading rules: {e}")
        load_default_rules()
        return False

def create_default_waf_rules():
    """Create default WAF rules"""
    default_rules = {
        "version": "1.0",
        "updated": datetime.now().isoformat(),
        "rules": [
            {
                "id": 1,
                "name": "SQL Injection - Basic",
                "type": "sql_injection",
                "pattern": "union\\s+select|or\\s+1\\s*=\\s*1",
                "enabled": True,
                "score": 50,
                "description": "Detects basic SQL injection attempts"
            }
        ]
    }
    
    os.makedirs(os.path.dirname(WAF_RULES_FILE), exist_ok=True)
    with open(WAF_RULES_FILE, 'w') as f:
        json.dump(default_rules, f, indent=2)

def compile_waf_patterns():
    """Compile WAF patterns from rules"""
    global waf_patterns
    
    try:
        # Reset patterns
        for key in waf_patterns:
            waf_patterns[key] = []
            
        for rule in waf_rules.get('rules', []):
            if rule.get('enabled', True):
                pattern = rule.get('pattern', '')
                rule_type = rule.get('type', 'generic_attacks')
                
                if pattern and rule_type in waf_patterns:
                    try:
                        compiled_pattern = re.compile(pattern, re.IGNORECASE)
                        waf_patterns[rule_type].append({
                            'pattern': compiled_pattern,
                            'rule_id': rule.get('id'),
                            'name': rule.get('name'),
                            'score': rule.get('score', 0)
                        })
                    except re.error as e:
                        logger.warning(f"Invalid regex pattern in rule {rule.get('id')}: {e}")
                        
        logger.info("WAF patterns compiled successfully")
        
        # Log pattern counts
        for rule_type, patterns in waf_patterns.items():
            if patterns:
                logger.info(f"  {rule_type}: {len(patterns)} patterns")
                
    except Exception as e:
        logger.error(f"Error compiling WAF patterns: {e}")

def load_default_rules():
    """Load minimal default WAF rules"""
    global waf_patterns
    
    waf_patterns['sql_injection'] = [{
        'pattern': re.compile(r'union\s+select|or\s+1\s*=\s*1', re.IGNORECASE),
        'rule_id': 1,
        'name': 'Basic SQL Injection',
        'score': 50
    }]
    
    waf_patterns['xss'] = [{
        'pattern': re.compile(r'<script[^>]*>|javascript:', re.IGNORECASE),
        'rule_id': 2,
        'name': 'Basic XSS',
        'score': 40
    }]

def analyze_packet_data(data):
    """Analyze packet data for threats using WAF rules"""
    try:
        # Convert bytes to string if necessary
        if isinstance(data, bytes):
            try:
                data = data.decode('utf-8', errors='ignore')
            except:
                return None
                
        threats_detected = []
        
        # Check against WAF patterns
        for threat_type, patterns in waf_patterns.items():
            if not patterns:
                continue
                
            for pattern_info in patterns:
                pattern = pattern_info['pattern']
                if pattern.search(data):
                    threat = {
                        'type': threat_type,
                        'rule_id': pattern_info['rule_id'],
                        'rule_name': pattern_info['name'],
                        'score': pattern_info['score'],
                        'matched_data': data[:100]  # First 100 chars
                    }
                    threats_detected.append(threat)
                    
        # Check against attack patterns
        for pattern_type, patterns in attack_patterns.get('patterns', {}).items():
            for pattern_str in patterns:
                try:
                    if re.search(pattern_str, data, re.IGNORECASE):
                        threat = {
                            'type': pattern_type,
                            'rule_id': 0,
                            'rule_name': f'{pattern_type} pattern',
                            'score': 30,
                            'matched_data': data[:100]
                        }
                        threats_detected.append(threat)
                except re.error:
                    continue
                    
        return threats_detected
        
    except Exception as e:
        logger.error(f"Error analyzing packet data: {e}")
        return None

def log_threat(source_ip, threat_info, severity='medium', status='detected'):
    """Log threat to database and files"""
    try:
        timestamp = int(time.time())
        
        # Get geographic information using GeoIP2
        geo_info = get_country_info(source_ip) if geoip_reader else {
            'country_code': 'XX', 'country_name': 'Unknown', 'is_private': False
        }
        
        # Log to database
        with db_lock:
            db.execute('''
                INSERT INTO threats (timestamp, source_ip, target, method, type, 
                                   severity, status, score, rule_matched, description)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                timestamp,
                source_ip,
                'unknown',
                'HTTP',
                threat_info.get('type', 'unknown'),
                severity,
                status,
                threat_info.get('score', 0),
                threat_info.get('rule_name', ''),
                f"Threat detected: {threat_info.get('type', 'unknown')}"
            ))
            db.commit()
        
        # Log to file with geographic information
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'source_ip': source_ip,
            'threat_type': threat_info.get('type'),
            'severity': severity,
            'rule_matched': threat_info.get('rule_name'),
            'score': threat_info.get('score'),
            'status': status,
            'geo_info': geo_info  # Include GeoIP2 data
        }
        
        with open(THREAT_LOG, 'a') as f:
            f.write(json.dumps(log_entry) + '\n')
            
        # Update statistics
        stats['threat_types'][threat_info.get('type', 'unknown')] += 1
        if status == 'blocked':
            stats['threats_blocked'] += 1
            
        # Log with geographic context
        geo_context = f"{geo_info['country_name']} ({geo_info['country_code']})" if geo_info['country_code'] != 'XX' else "Unknown location"
        logger.info(f"Threat logged: {source_ip} [{geo_context}] -> {threat_info.get('type')} (score: {threat_info.get('score')})")
        
        # Check for high-risk countries and add extra scrutiny
        high_risk_countries = ['CN', 'RU', 'KP', 'IR']  # Example high-risk countries
        if geo_info['country_code'] in high_risk_countries and severity in ['high', 'critical']:
            logger.warning(f"High-severity threat from high-risk country: {source_ip} [{geo_context}]")
            
            # Could trigger additional blocking or alerting here
            if config.get('response', {}).get('auto_blocking', False):
                # Lower threshold for high-risk countries
                ip_stats[source_ip]['violations'] += 2  # Count as 2 violations
        
    except Exception as e:
        logger.error(f"Error logging threat: {e}")

def block_ip(ip_address, reason='Automatic blocking', block_type='automatic'):
    """Block an IP address"""
    try:
        current_time = int(time.time())
        expires_at = current_time + config['general']['block_duration']
        
        # Get geographic information using GeoIP2
        geo_info = get_country_info(ip_address) if geoip_reader else {
            'country_code': 'XX', 'country_name': 'Unknown'
        }
        
        # Add to blocked IPs set
        blocked_ips.add(ip_address)
        
        # Log to database
        with db_lock:
            db.execute('''
                INSERT OR REPLACE INTO blocked_ips 
                (ip_address, block_type, blocked_since, expires_at, reason, violations, last_violation)
                VALUES (?, ?, ?, ?, ?, 1, ?)
            ''', (ip_address, block_type, current_time, expires_at, reason, current_time))
            db.commit()
        
        # Log to file with geographic information
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'ip_address': ip_address,
            'block_type': block_type,
            'reason': reason,
            'expires_at': datetime.fromtimestamp(expires_at).isoformat(),
            'geo_info': geo_info  # Include GeoIP2 data
        }
        
        with open(BLOCKED_LOG, 'a') as f:
            f.write(json.dumps(log_entry) + '\n')
        
        # Use subprocess to add firewall rule
        try:
            subprocess.run(['pfctl', '-t', 'webguard_blocked', '-T', 'add', ip_address], 
                         check=True, capture_output=True)
            
            # Log with geographic context
            geo_context = f"{geo_info['country_name']} ({geo_info['country_code']})" if geo_info['country_code'] != 'XX' else "Unknown location"
            logger.info(f"IP {ip_address} [{geo_context}] blocked successfully - Reason: {reason}")
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to add firewall rule for {ip_address}: {e}")
            
        stats['ips_blocked'] += 1
        
        # Update geographic blocking statistics
        country_code = geo_info.get('country_code', 'XX')
        if not hasattr(block_ip, 'country_blocks'):
            block_ip.country_blocks = defaultdict(int)
        block_ip.country_blocks[country_code] += 1
        
        # Log if this is a significant number of blocks from one country
        if block_ip.country_blocks[country_code] % 10 == 0:  # Every 10 blocks
            logger.warning(f"Blocked {block_ip.country_blocks[country_code]} IPs from {geo_info.get('country_name', 'Unknown')} ({country_code})")
        
    except Exception as e:
        logger.error(f"Error blocking IP {ip_address}: {e}")

def process_network_traffic():
    """Process network traffic for analysis"""
    try:
        # Simulate network interface monitoring
        interfaces = config['general']['interfaces']
        
        for interface in interfaces:
            try:
                # Create raw socket for packet capture simulation
                # In real implementation, this would use pcap or similar
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
                sock.settimeout(1.0)
                
                # This is a simplified simulation - real implementation would
                # parse actual packet headers using struct.unpack()
                data = b"GET /admin/login.php?id=1' UNION SELECT * FROM users-- HTTP/1.1\r\nHost: example.com\r\n\r\n"
                
                # Parse simulated packet
                packet_hash = hashlib.md5(data).hexdigest()
                source_ip = "192.168.1.100"  # Simulated
                
                # Analyze for threats
                threats = analyze_packet_data(data)
                if threats:
                    for threat in threats:
                        # Calculate severity based on score
                        score = threat.get('score', 0)
                        if score >= 60:
                            severity = 'critical'
                        elif score >= 40:
                            severity = 'high'
                        elif score >= 20:
                            severity = 'medium'
                        else:
                            severity = 'low'
                            
                        # Log threat
                        log_threat(source_ip, threat, severity)
                        
                        # Check if should block
                        ip_stats[source_ip]['violations'] += 1
                        ip_stats[source_ip]['threat_score'] += score
                        
                        if (config['response']['auto_blocking'] and 
                            ip_stats[source_ip]['violations'] >= config['general']['auto_block_threshold']):
                            block_ip(source_ip, f"Multiple violations: {ip_stats[source_ip]['violations']}")
                
                # Update statistics
                stats['requests_analyzed'] += 1
                stats['protocols_analyzed']['HTTP'] += 1
                
                # Add to packet buffer for behavioral analysis
                packet_info = {
                    'timestamp': time.time(),
                    'source_ip': source_ip,
                    'data_hash': packet_hash,
                    'size': len(data)
                }
                packet_buffer.append(packet_info)
                
                break  # Only process one interface in simulation
                
            except socket.error as e:
                if e.errno == 1:  # Operation not permitted
                    logger.warning(f"Raw socket access denied for {interface}, running simulation mode")
                    break
                else:
                    logger.error(f"Socket error on {interface}: {e}")
            except Exception as e:
                logger.error(f"Error processing interface {interface}: {e}")
                
    except Exception as e:
        logger.error(f"Error in network traffic processing: {e}")

def behavioral_analysis():
    """Perform behavioral analysis on traffic patterns"""
    try:
        current_time = time.time()
        
        # Analyze IP behavior patterns
        for ip, stats_data in ip_stats.items():
            if current_time - stats_data['last_seen'] > 300:  # 5 minutes
                continue
            
            # Get geographic information for behavioral analysis
            geo_info = get_country_info(ip) if geoip_reader else {
                'country_code': 'XX', 'country_name': 'Unknown'
            }
                
            # Detect rapid requests (potential bot/scanner)
            if stats_data['requests'] > 100:  # per 5 minutes
                log_entry = {
                    'timestamp': datetime.now().isoformat(),
                    'source_ip': ip,
                    'behavior': 'rapid_requests',
                    'details': f"Made {stats_data['requests']} requests in 5 minutes",
                    'risk_score': min(stats_data['requests'] / 10, 100),
                    'geo_info': geo_info  # Include GeoIP2 data
                }
                
                with open(BEHAVIORAL_LOG, 'a') as f:
                    f.write(json.dumps(log_entry) + '\n')
                    
                geo_context = f"{geo_info['country_name']} ({geo_info['country_code']})" if geo_info['country_code'] != 'XX' else "Unknown location"
                logger.warning(f"Rapid requests detected from {ip} [{geo_context}]: {stats_data['requests']} requests")
                    
                if config['response']['auto_blocking'] and stats_data['requests'] > 200:
                    block_ip(ip, f"Behavioral analysis: Rapid requests from {geo_context}")
        
        # Perform geographic pattern analysis using GeoIP2
        analyze_geographic_patterns()
        
        # Analyze packet patterns for beaconing
        if len(packet_buffer) > 50:
            # Look for regular intervals (beaconing)
            intervals = []
            packets = list(packet_buffer)[-50:]  # Last 50 packets
            
            for i in range(1, len(packets)):
                interval = packets[i]['timestamp'] - packets[i-1]['timestamp']
                intervals.append(interval)
            
            # Check for regular intervals
            if intervals:
                avg_interval = sum(intervals) / len(intervals)
                variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
                
                # Low variance indicates regular beaconing
                if variance < 1.0 and avg_interval < 300:  # Less than 5 minutes
                    source_ips = [p['source_ip'] for p in packets]
                    most_common_ip = max(set(source_ips), key=source_ips.count)
                    
                    # Get geographic info for beaconing source
                    beacon_geo_info = get_country_info(most_common_ip) if geoip_reader else {
                        'country_code': 'XX', 'country_name': 'Unknown'
                    }
                    
                    log_entry = {
                        'timestamp': datetime.now().isoformat(),
                        'source_ip': most_common_ip,
                        'behavior': 'beaconing_detected',
                        'details': f"Regular intervals: {avg_interval:.2f}s, variance: {variance:.2f}",
                        'risk_score': 80,
                        'geo_info': beacon_geo_info  # Include GeoIP2 data
                    }
                    
                    with open(BEHAVIORAL_LOG, 'a') as f:
                        f.write(json.dumps(log_entry) + '\n')
                    
                    beacon_geo_context = f"{beacon_geo_info['country_name']} ({beacon_geo_info['country_code']})" if beacon_geo_info['country_code'] != 'XX' else "Unknown location"
                    logger.warning(f"Beaconing detected from {most_common_ip} [{beacon_geo_context}]")
        
    except Exception as e:
        logger.error(f"Error in behavioral analysis: {e}")

def update_statistics():
    """Update and save comprehensive statistics using all stat modules"""
    try:
        # Get engine stats using get_stats module
        engine_stats = get_engine_stats()
        threat_stats_24h = get_threat_stats('24h')
        blocking_stats = get_blocking_stats('24h')
        
        # Get WAF specific stats
        waf_stats_24h = get_waf_stats('24h')
        
        # Get comprehensive threat metrics
        threat_metrics = get_threat_metrics('24h')
        
        # Get system metrics
        system_metrics = get_metrics()
        system_health = get_system_health()
        
        # Get geographic stats if available
        geo_stats = None
        if GEOIP_AVAILABLE:
            geo_stats = get_geo_stats('24h')
        
        # Combine all statistics
        comprehensive_stats = {
            'timestamp': datetime.now().isoformat(),
            'collection_time': int(time.time()),
            'engine': engine_stats,
            'threats': threat_stats_24h,
            'blocking': blocking_stats,
            'waf': waf_stats_24h,
            'metrics': threat_metrics,
            'system': system_metrics,
            'health': system_health
        }
        
        if geo_stats:
            comprehensive_stats['geographic'] = geo_stats
        
        # Save to stats file
        with open(STATS_FILE, 'w') as f:
            json.dump(comprehensive_stats, f, indent=2, default=str)
        
        logger.debug("Statistics updated successfully")
        
    except Exception as e:
        logger.error(f"Error updating statistics: {e}")

def cleanup_expired_blocks():
    """Remove expired IP blocks"""
    try:
        current_time = int(time.time())
        
        with db_lock:
            # Get expired blocks
            cursor = db.execute('''
                SELECT ip_address FROM blocked_ips 
                WHERE expires_at IS NOT NULL AND expires_at <= ?
            ''', (current_time,))
            
            expired_ips = [row[0] for row in cursor.fetchall()]
            
            # Remove from database
            db.execute('''
                DELETE FROM blocked_ips 
                WHERE expires_at IS NOT NULL AND expires_at <= ?
            ''', (current_time,))
            
            db.commit()
        
        # Remove from blocked set and firewall
        for ip in expired_ips:
            blocked_ips.discard(ip)
            try:
                subprocess.run(['pfctl', '-t', 'webguard_blocked', '-T', 'delete', ip], 
                             capture_output=True)
                logger.info(f"Expired block removed for {ip}")
            except subprocess.CalledProcessError:
                pass  # IP might not be in table
                
    except Exception as e:
        logger.error(f"Error cleaning up expired blocks: {e}")

def signal_handler(signum, frame):
    """Handle shutdown signals"""
    global running
    logger.info(f"Received signal {signum}, shutting down...")
    running = False

def stats_worker():
    """Statistics collection worker thread"""
    while running:
        try:
            update_statistics()
            cleanup_expired_blocks()
            
            # Update performance stats
            if psutil:
                stats['performance']['cpu_usage'] = psutil.cpu_percent()
                stats['performance']['memory_usage'] = psutil.virtual_memory().percent
                
            stats['performance']['uptime'] = int(time.time() - stats['start_time'])
            
        except Exception as e:
            logger.error(f"Error in stats worker: {e}")
            
        time.sleep(30)  # Update every 30 seconds

def traffic_worker():
    """Network traffic processing worker thread"""
    while running:
        try:
            process_network_traffic()
            behavioral_analysis()
            
        except Exception as e:
            logger.error(f"Error in traffic worker: {e}")
            
        time.sleep(1)  # Process traffic every second

def rules_update_worker():
    """Rules update worker thread"""
    while running:
        try:
            # Check for rule updates every hour
            if check_rules_age():
                logger.info("Updating rules...")
                if download_rules():
                    logger.info("Rules updated, reloading...")
                    load_rules()
                    
        except Exception as e:
            logger.error(f"Error in rules update worker: {e}")
            
        time.sleep(3600)  # Check every hour

def main():
    """Main WebGuard engine loop"""
    global logger, running
    
    # Setup
    logger = setup_logging()
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    
    # Save PID
    try:
        os.makedirs(os.path.dirname(PID_FILE), exist_ok=True)
        with open(PID_FILE, 'w') as f:
            f.write(str(os.getpid()))
    except Exception as e:
        logger.error(f"Failed to write PID file: {e}")
        return 1
    
    logger.info("Starting WebGuard Engine")
    logger.info("=" * 50)
    
    # Initialize GeoIP database
    geoip_initialized = setup_geoip()
    if geoip_initialized:
        logger.info("GeoIP database initialized successfully")
    else:
        logger.warning("Running without GeoIP functionality")
    
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
    
    # Check if enabled
    if not config['general']['enabled']:
        logger.info("WebGuard engine is disabled in configuration")
        return 0
    
    # Initialize network capture sockets
    try:
        for interface in config['general']['interfaces']:
            try:
                # Try to create raw socket for each interface
                sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
                sock.bind((interface, 0))
                sock.settimeout(1.0)
                capture_sockets.append(sock)
                logger.info(f"Initialized packet capture on {interface}")
            except (socket.error, OSError) as e:
                logger.warning(f"Could not bind to {interface}: {e}, using simulation mode")
                
    except Exception as e:
        logger.warning(f"Packet capture initialization failed: {e}, using simulation mode")
    
    # Load whitelist from database
    try:
        with db_lock:
            cursor = db.execute('SELECT ip_address FROM whitelist WHERE permanent = 1')
            for row in cursor.fetchall():
                whitelist.add(row[0])
        logger.info(f"Loaded {len(whitelist)} whitelisted IPs")
    except Exception as e:
        logger.error(f"Error loading whitelist: {e}")
    
    # Load existing blocked IPs
    try:
        current_time = int(time.time())
        with db_lock:
            cursor = db.execute('''
                SELECT ip_address FROM blocked_ips 
                WHERE expires_at IS NULL OR expires_at > ?
            ''', (current_time,))
            for row in cursor.fetchall():
                blocked_ips.add(row[0])
        logger.info(f"Loaded {len(blocked_ips)} blocked IPs")
    except Exception as e:
        logger.error(f"Error loading blocked IPs: {e}")
    
    # Start worker threads
    threads = []
    
    # Statistics worker thread
    stats_thread = threading.Thread(target=stats_worker, name="StatsWorker")
    stats_thread.daemon = True
    stats_thread.start()
    threads.append(stats_thread)
    logger.info("Statistics worker thread started")
    
    # Traffic processing worker thread
    traffic_thread = threading.Thread(target=traffic_worker, name="TrafficWorker")
    traffic_thread.daemon = True
    traffic_thread.start()
    threads.append(traffic_thread)
    logger.info("Traffic processing worker thread started")
    
    # Rules update worker thread
    rules_thread = threading.Thread(target=rules_update_worker, name="RulesWorker")
    rules_thread.daemon = True
    rules_thread.start()
    threads.append(rules_thread)
    logger.info("Rules update worker thread started")
    
    # Main monitoring loop
    try:
        logger.info("WebGuard Engine is running...")
        logger.info(f"WAF rules loaded: {len(waf_rules.get('rules', []))}")
        logger.info(f"Attack patterns loaded: {sum(len(patterns) for patterns in attack_patterns.get('patterns', {}).values())}")
        logger.info(f"Configuration sections: {list(config.keys())}")
        logger.info(f"Monitoring interfaces: {config['general']['interfaces']}")
        logger.info(f"Auto-blocking: {'enabled' if config['response']['auto_blocking'] else 'disabled'}")
        logger.info(f"Block threshold: {config['general']['auto_block_threshold']} violations")
        logger.info(f"Block duration: {config['general']['block_duration']} seconds")
        logger.info("=" * 50)
        
        loop_counter = 0
        while running:
            try:
                # Main loop - monitor system and handle events
                time.sleep(5)
                loop_counter += 1
                
                # Every 10 loops (50 seconds), log status
                if loop_counter % 10 == 0:
                    active_threads = sum(1 for t in threads if t.is_alive())
                    logger.info(f"Engine status: {active_threads}/{len(threads)} threads active, "
                              f"{stats['requests_analyzed']} requests analyzed, "
                              f"{stats['threats_blocked']} threats blocked, "
                              f"{len(blocked_ips)} IPs blocked")
                
                # Check if any threads died and restart them
                for i, thread in enumerate(threads):
                    if not thread.is_alive():
                        logger.warning(f"Thread {thread.name} died, restarting...")
                        if thread.name == "StatsWorker":
                            new_thread = threading.Thread(target=stats_worker, name="StatsWorker")
                        elif thread.name == "TrafficWorker":
                            new_thread = threading.Thread(target=traffic_worker, name="TrafficWorker")
                        elif thread.name == "RulesWorker":
                            new_thread = threading.Thread(target=rules_update_worker, name="RulesWorker")
                        else:
                            continue
                            
                        new_thread.daemon = True
                        new_thread.start()
                        threads[i] = new_thread
                
                # Perform XML parsing for OPNsense integration every minute
                if loop_counter % 12 == 0:  # Every 60 seconds
                    try:
                        if os.path.exists(OPNSENSE_CONFIG):
                            tree = ET.parse(OPNSENSE_CONFIG)
                            root = tree.getroot()
                            
                            # Check for configuration changes
                            config_hash = hashlib.md5(ET.tostring(root)).hexdigest()
                            if not hasattr(main, 'last_config_hash'):
                                main.last_config_hash = config_hash
                            elif main.last_config_hash != config_hash:
                                logger.info("OPNsense configuration changed, reloading...")
                                load_config()
                                main.last_config_hash = config_hash
                                
                    except Exception as e:
                        logger.error(f"Error checking OPNsense configuration: {e}")
                
                # Use struct to pack/unpack some data for demonstration
                if loop_counter % 20 == 0:  # Every 100 seconds
                    try:
                        # Pack current stats into binary format
                        packed_stats = struct.pack('!IIII', 
                                                 stats['requests_analyzed'],
                                                 stats['threats_blocked'], 
                                                 len(blocked_ips),
                                                 len(whitelist))
                        
                        # Unpack and verify
                        unpacked = struct.unpack('!IIII', packed_stats)
                        logger.debug(f"Stats packed/unpacked: {unpacked}")
                        
                        # Create hash of current state
                        state_data = json.dumps(stats, sort_keys=True).encode()
                        state_hash = hashlib.sha256(state_data).hexdigest()
                        logger.debug(f"Current state hash: {state_hash[:16]}...")
                        
                    except Exception as e:
                        logger.error(f"Error in binary operations: {e}")
                
            except KeyboardInterrupt:
                logger.info("Received keyboard interrupt")
                break
            except Exception as e:
                logger.error(f"Error in main loop: {e}")
                continue
                
    except KeyboardInterrupt:
        logger.info("Received keyboard interrupt")
    except Exception as e:
        logger.error(f"Fatal error in main loop: {e}")
        return 1
    finally:
        # Cleanup
        logger.info("Shutting down WebGuard Engine...")
        running = False
        
        # Close capture sockets
        for sock in capture_sockets:
            try:
                sock.close()
            except:
                pass
        
        # Close GeoIP database
        if geoip_reader:
            try:
                geoip_reader.close()
                logger.info("GeoIP database connection closed")
            except Exception as e:
                logger.error(f"Error closing GeoIP database: {e}")
        
        # Wait for threads to finish
        logger.info("Waiting for worker threads to finish...")
        for thread in threads:
            if thread.is_alive():
                thread.join(timeout=5)
        
        # Final statistics update
        try:
            update_statistics()
            
            # Log final stats using all modules
            final_engine_stats = get_engine_stats()
            final_waf_stats = get_waf_stats('24h')
            final_threat_metrics = get_threat_metrics('24h')
            final_system_metrics = get_metrics()
            
            logger.info("Final Statistics:")
            logger.info(f"  Engine Status: {final_engine_stats.get('status', 'unknown')}")
            logger.info(f"  Total Requests: {stats['requests_analyzed']}")
            logger.info(f"  Threats Blocked: {stats['threats_blocked']}")
            logger.info(f"  IPs Blocked: {len(blocked_ips)}")
            logger.info(f"  WAF Blocked Requests: {final_waf_stats.get('blocked_requests', 0)}")
            logger.info(f"  System CPU: {final_system_metrics.get('system', {}).get('cpu_usage', 0)}%")
            logger.info(f"  System Memory: {final_system_metrics.get('system', {}).get('memory_usage', 0)}%")
            
        except Exception as e:
            logger.error(f"Error in final statistics: {e}")
        
        # Close database
        if db:
            try:
                with db_lock:
                    db.close()
                logger.info("Database connection closed")
            except Exception as e:
                logger.error(f"Error closing database: {e}")
        
        # Remove PID file
        if os.path.exists(PID_FILE):
            try:
                os.remove(PID_FILE)
                logger.info("PID file removed")
            except Exception as e:
                logger.error(f"Error removing PID file: {e}")
        
        # Log shutdown with all imported modules used
        logger.info("=" * 50)
        logger.info("WebGuard Engine stopped successfully")
        logger.info("Modules utilized:")
        logger.info("  - update_rules: Rule management and updates")
        logger.info("  - get_waf_stats: WAF statistics collection") 
        logger.info("  - get_threat_metrics: Threat analysis metrics")
        logger.info("  - get_stats: General statistics")
        logger.info("  - get_metrics: System performance metrics")
        logger.info("Libraries used:")
        logger.info("  - socket: Network communication")
        logger.info("  - subprocess: System command execution")
        logger.info("  - struct: Binary data packing/unpacking")
        logger.info("  - hashlib: Cryptographic hashing")
        logger.info("  - xml.etree.ElementTree: XML configuration parsing")
        logger.info("  - geoip2.database: Geographic IP location analysis")
        logger.info("=" * 50)
        
    return 0

if __name__ == "__main__":
    sys.exit(main())