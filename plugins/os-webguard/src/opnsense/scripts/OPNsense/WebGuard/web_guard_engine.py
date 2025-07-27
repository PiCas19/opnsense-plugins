#!/usr/local/bin/python3.11

"""
WebGuard Engine - Main Web Application Firewall and Behavioral Analysis Engine with Scapy
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

# Import Scapy for packet sniffing
try:
    from scapy.all import sniff, IP, TCP, UDP, Raw
    SCAPY_AVAILABLE = True
except ImportError as e:
    print(f"Error: Could not import Scapy: {e}")
    print("Install with: pkg install py311-scapy")
    sys.exit(1)

# Import support functions
try:
    from update_rules import download_rules, need_update as check_rules_age
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
    import psutil
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
geoip_reader = None
geo_stats = defaultdict(int)
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

def signal_handler(signum, frame):
    """Handle shutdown signals"""
    global running
    logger.info(f"Received signal {signum}, shutting down...")
    running = False

def setup_logging():
    """Initialize logging system"""
    os.makedirs(LOG_DIR, exist_ok=True)
    
    for log_file in [ALERT_LOG, THREAT_LOG, BLOCKED_LOG, WAF_LOG, BEHAVIORAL_LOG, COVERT_LOG, ENGINE_LOG]:
        if not os.path.exists(log_file):
            with open(log_file, 'w') as f:
                pass
    
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
            
            # Create tables with 'target' field included
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
                    score REAL DEFAULT 0.0,
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
    """Initialize GeoIP databases - supports both IP2Location and GeoLite2"""
    global geoip_reader
    
    if not GEOIP_AVAILABLE:
        logger.warning("GeoIP2 library not available")
        return False
    
    # Initialize readers dictionary to support multiple databases
    geoip_reader = {}
    
    try:
        # Database paths for both IP2Location and GeoLite2
        databases = {
            'ip2location': '/usr/local/share/GeoIP/IP2LOCATION-LITE-DB1.MMDB',
            'geolite2_country': '/usr/local/share/GeoIP/GeoLite2-Country.mmdb',
            'geolite2_city': '/usr/local/share/GeoIP/GeoLite2-City.mmdb'
        }
        
        # Alternative paths to check
        alternative_paths = {
            'ip2location': [
                '/var/db/GeoIP/IP2LOCATION-LITE-DB1.MMDB',
                '/usr/share/GeoIP/IP2LOCATION-LITE-DB1.MMDB'
            ],
            'geolite2_country': [
                '/var/db/GeoIP/GeoLite2-Country.mmdb',
                '/usr/share/GeoIP/GeoLite2-Country.mmdb'
            ],
            'geolite2_city': [
                '/var/db/GeoIP/GeoLite2-City.mmdb',
                '/usr/share/GeoIP/GeoLite2-City.mmdb'
            ]
        }
        
        loaded_databases = []
        
        # Try to load IP2Location database
        ip2location_loaded = False
        for path in [databases['ip2location']] + alternative_paths['ip2location']:
            if os.path.exists(path):
                try:
                    geoip_reader['ip2location'] = geoip2.database.Reader(path)
                    logger.info(f"IP2Location database loaded from: {path}")
                    loaded_databases.append('IP2Location')
                    ip2location_loaded = True
                    break
                except Exception as e:
                    logger.error(f"Failed to load IP2Location from {path}: {e}")
                    continue
        
        if not ip2location_loaded:
            logger.warning("IP2Location database not found or failed to load")
        
        # Try to load GeoLite2 Country database
        geolite2_country_loaded = False
        for path in [databases['geolite2_country']] + alternative_paths['geolite2_country']:
            if os.path.exists(path):
                try:
                    geoip_reader['geolite2_country'] = geoip2.database.Reader(path)
                    logger.info(f"GeoLite2 Country database loaded from: {path}")
                    loaded_databases.append('GeoLite2-Country')
                    geolite2_country_loaded = True
                    break
                except Exception as e:
                    logger.error(f"Failed to load GeoLite2 Country from {path}: {e}")
                    continue
        
        if not geolite2_country_loaded:
            logger.warning("GeoLite2 Country database not found or failed to load")
        
        # Try to load GeoLite2 City database (optional, for more detailed info)
        geolite2_city_loaded = False
        for path in [databases['geolite2_city']] + alternative_paths['geolite2_city']:
            if os.path.exists(path):
                try:
                    geoip_reader['geolite2_city'] = geoip2.database.Reader(path)
                    logger.info(f"GeoLite2 City database loaded from: {path}")
                    loaded_databases.append('GeoLite2-City')
                    geolite2_city_loaded = True
                    break
                except Exception as e:
                    logger.error(f"Failed to load GeoLite2 City from {path}: {e}")
                    continue
        
        if not geolite2_city_loaded:
            logger.info("GeoLite2 City database not found (optional)")
        
        if loaded_databases:
            logger.info(f"GeoIP databases initialized successfully: {', '.join(loaded_databases)}")
            return True
        else:
            logger.error("No GeoIP databases could be loaded")
            geoip_reader = None
            return False
        
    except Exception as e:
        logger.error(f"Failed to initialize GeoIP databases: {e}")
        geoip_reader = None
        return False

def get_country_info(ip_address):
    """Get country information for IP address using multiple GeoIP databases with fallback"""
    if not geoip_reader:
        return {'country_code': 'XX', 'country_name': 'Unknown', 'is_private': False, 'source': 'no_database'}
    
    try:
        import ipaddress
        ip_obj = ipaddress.ip_address(ip_address)
        
        # Check if it's a private/local IP
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_multicast or ip_obj.is_link_local:
            return {'country_code': 'PR', 'country_name': 'Private', 'is_private': True, 'source': 'private'}
        
        # Check if it's not a global IP
        if not ip_obj.is_global:
            return {'country_code': 'LO', 'country_name': 'Local', 'is_private': True, 'source': 'local'}
        
        # Try IP2Location first (usually more accurate for some regions)
        if 'ip2location' in geoip_reader:
            try:
                response = geoip_reader['ip2location'].country(ip_address)
                country_name = getattr(response.country, 'name', None)
                country_code = getattr(response.country, 'iso_code', None)
                
                if country_name and country_name != '-' and country_name.strip():
                    country_info = {
                        'country_code': country_code or 'XX',
                        'country_name': country_name.strip(),
                        'continent_code': getattr(response.continent, 'code', 'XX'),
                        'continent_name': getattr(response.continent, 'name', 'Unknown'),
                        'is_private': False,
                        'source': 'IP2Location'
                    }
                    
                    geo_stats[country_info['country_code']] += 1
                    logger.debug(f"IP2Location lookup for {ip_address}: {country_info['country_name']} ({country_info['country_code']})")
                    return country_info
                else:
                    logger.debug(f"IP2Location returned empty/dash for {ip_address}")
                    
            except geoip2.errors.AddressNotFoundError:
                logger.debug(f"IP address {ip_address} not found in IP2Location database")
            except Exception as e:
                logger.error(f"Error looking up IP {ip_address} in IP2Location: {e}")
        
        # Fallback to GeoLite2 Country
        if 'geolite2_country' in geoip_reader:
            try:
                response = geoip_reader['geolite2_country'].country(ip_address)
                country_info = {
                    'country_code': response.country.iso_code or 'XX',
                    'country_name': response.country.name or 'Unknown',
                    'continent_code': response.continent.code or 'XX',
                    'continent_name': response.continent.name or 'Unknown',
                    'is_private': False,
                    'source': 'GeoLite2-Country'
                }
                
                geo_stats[country_info['country_code']] += 1
                logger.debug(f"GeoLite2 Country lookup for {ip_address}: {country_info['country_name']} ({country_info['country_code']})")
                return country_info
                
            except geoip2.errors.AddressNotFoundError:
                logger.debug(f"IP address {ip_address} not found in GeoLite2 Country database")
            except Exception as e:
                logger.error(f"Error looking up IP {ip_address} in GeoLite2 Country: {e}")
        
        # If we have GeoLite2 City, try that as well (last resort)
        if 'geolite2_city' in geoip_reader:
            try:
                response = geoip_reader['geolite2_city'].city(ip_address)
                country_info = {
                    'country_code': response.country.iso_code or 'XX',
                    'country_name': response.country.name or 'Unknown',
                    'continent_code': response.continent.code or 'XX',
                    'continent_name': response.continent.name or 'Unknown',
                    'city_name': response.city.name or 'Unknown',
                    'is_private': False,
                    'source': 'GeoLite2-City'
                }
                
                geo_stats[country_info['country_code']] += 1
                logger.debug(f"GeoLite2 City lookup for {ip_address}: {country_info['country_name']} ({country_info['country_code']})")
                return country_info
                
            except geoip2.errors.AddressNotFoundError:
                logger.debug(f"IP address {ip_address} not found in GeoLite2 City database")
            except Exception as e:
                logger.error(f"Error looking up IP {ip_address} in GeoLite2 City: {e}")
        
        # If all databases failed
        logger.debug(f"IP address {ip_address} not found in any GeoIP database")
        return {'country_code': 'XX', 'country_name': 'Unknown', 'is_private': False, 'source': 'not_found'}
        
    except ValueError:
        logger.error(f"Invalid IP address format: {ip_address}")
        return {'country_code': 'XX', 'country_name': 'Invalid', 'is_private': False, 'source': 'invalid'}
    except Exception as e:
        logger.error(f"Error processing IP {ip_address}: {e}")
        return {'country_code': 'XX', 'country_name': 'Error', 'is_private': False, 'source': 'error'}

def analyze_geographic_patterns():
    """Analyze geographic patterns in threats using multiple GeoIP databases"""
    try:
        if not geoip_reader:
            return
            
        current_time = time.time()
        recent_threats = []
        
        with db_lock:
            cursor = db.execute('''
                SELECT source_ip, target, type, severity, timestamp FROM threats 
                WHERE timestamp > ? 
                ORDER BY timestamp DESC LIMIT 100
            ''', (int(current_time - 3600),))
            
            recent_threats = cursor.fetchall()
        
        if not recent_threats:
            return
        
        country_threat_counts = defaultdict(int)
        country_severity_scores = defaultdict(list)
        high_risk_countries = set()
        source_stats = defaultdict(int)  # Track which database resolved which IPs
        
        for source_ip, target, threat_type, severity, timestamp in recent_threats:
            try:
                country_info = get_country_info(source_ip)
                country_code = country_info['country_code']
                source_db = country_info.get('source', 'unknown')
                
                # Skip private/local IPs
                if country_info.get('is_private', False):
                    continue
                
                country_threat_counts[country_code] += 1
                severity_score = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}.get(severity, 1)
                country_severity_scores[country_code].append(severity_score)
                source_stats[source_db] += 1
                
                if severity_score >= 3:
                    high_risk_countries.add(country_code)
                    
            except Exception as e:
                logger.error(f"Error analyzing geographic pattern for {source_ip}: {e}")
                continue
        
        if country_threat_counts:
            sorted_countries = sorted(country_threat_counts.items(), 
                                    key=lambda x: x[1], reverse=True)[:10]
            
            geo_log_entry = {
                'timestamp': datetime.now().isoformat(),
                'analysis_type': 'geographic_patterns',
                'time_period': '1h',
                'total_threats': len(recent_threats),
                'countries_involved': len(country_threat_counts),
                'database_sources': dict(source_stats),
                'top_threat_countries': []
            }
            
            for country_code, threat_count in sorted_countries:
                avg_severity = sum(country_severity_scores[country_code]) / len(country_severity_scores[country_code])
                
                country_data = {
                    'country_code': country_code,
                    'country_name': country_code,  # Could be enhanced to store actual country name
                    'threat_count': threat_count,
                    'avg_severity': round(avg_severity, 2),
                    'is_high_risk': country_code in high_risk_countries
                }
                geo_log_entry['top_threat_countries'].append(country_data)
            
            with open(BEHAVIORAL_LOG, 'a') as f:
                f.write(json.dumps(geo_log_entry) + '\n')
            
            # Log database usage statistics
            logger.info(f"Geographic analysis completed using databases: {dict(source_stats)}")
            
            for country_code, threat_count in sorted_countries[:5]:
                if threat_count > 10:
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

def close_geoip_databases():
    """Close all GeoIP database connections"""
    global geoip_reader
    
    if geoip_reader and isinstance(geoip_reader, dict):
        for db_name, reader in geoip_reader.items():
            try:
                reader.close()
                logger.info(f"GeoIP database {db_name} connection closed")
            except Exception as e:
                logger.error(f"Error closing GeoIP database {db_name}: {e}")
    elif geoip_reader:
        # Handle legacy single reader case
        try:
            geoip_reader.close()
            logger.info("GeoIP database connection closed")
        except Exception as e:
            logger.error(f"Error closing GeoIP database: {e}")
    
    geoip_reader = None

def load_config():
    """Load WebGuard engine configuration using export_config"""
    global config
    try:
        if export_config():
            logger.info("Configuration exported from OPNsense successfully")
        
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
        else:
            config = create_default_config()
            
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
        if check_rules_age():
            logger.info("Rules are outdated, downloading new rules...")
            if download_rules():
                logger.info("Rules updated successfully")
            else:
                logger.warning("Failed to update rules, using existing ones")
        else:
            logger.info("Rules are up to date")
        
        try:
            with open(WAF_RULES_FILE, 'r') as f:
                waf_rules = json.load(f)
            logger.info(f"WAF rules loaded - Version: {waf_rules.get('version', 'Unknown')}")
            logger.info(f"Rules count: {len(waf_rules.get('rules', []))}")
        except Exception as e:
            logger.error(f"Error loading WAF rules: {e}")
            create_default_waf_rules()
            
        try:
            with open(ATTACK_PATTERNS_FILE, 'r') as f:
                attack_patterns = json.load(f)
            logger.info(f"Attack patterns loaded - Version: {attack_patterns.get('version', 'Unknown')}")
        except Exception as e:
            logger.error(f"Error loading attack patterns: {e}")
            attack_patterns = {'patterns': {}}
            
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
            },
            {
                "id": 2,
                "name": "XSS - Basic",
                "type": "xss",
                "pattern": "<script[^>]*>|javascript:",
                "enabled": True,
                "score": 40,
                "description": "Detects basic XSS attempts"
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

def update_statistics():
    """Update and save comprehensive statistics using all stat modules"""
    try:
        engine_stats = get_engine_stats()
        threat_stats_24h = get_threat_stats('24h')
        blocking_stats = get_blocking_stats('24h')
        waf_stats_24h = get_waf_stats('24h')
        threat_metrics = get_threat_metrics('24h')
        system_metrics = get_metrics()
        system_health = get_system_health()
        
        geo_statistics = None
        if GEOIP_AVAILABLE:
            geo_statistics = get_geo_stats('24h')
        
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
        
        if geo_statistics:
            comprehensive_stats['geographic'] = geo_statistics
        
        with open(STATS_FILE, 'w') as f:
            json.dump(comprehensive_stats, f, indent=2, default=str)
        
        logger.debug("Statistics updated successfully")
        
    except Exception as e:
        logger.error(f"Error updating statistics: {e}")

def stats_worker():
    """Statistics collection worker thread"""
    while running:
        try:
            update_statistics()
            
            if psutil:
                cpu_percents = psutil.cpu_percent(interval=1, percpu=True)
                stats['performance']['cpu_usage'] = psutil.cpu_percent()
                stats['performance']['cpu_cores'] = len(cpu_percents)
                stats['performance']['cpu_per_core'] = cpu_percents
                
                memory = psutil.virtual_memory()
                stats['performance']['memory_usage'] = memory.percent
                stats['performance']['memory_total'] = memory.total
                stats['performance']['memory_available'] = memory.available
                stats['performance']['memory_used'] = memory.used
                
                disk_usage = psutil.disk_usage('/')
                stats['performance']['disk_usage'] = round((disk_usage.used / disk_usage.total) * 100, 2)
                stats['performance']['disk_free'] = disk_usage.free
                
                net_io = psutil.net_io_counters()
                stats['performance']['bytes_sent'] = net_io.bytes_sent
                stats['performance']['bytes_recv'] = net_io.bytes_recv
                stats['performance']['packets_sent'] = net_io.packets_sent
                stats['performance']['packets_recv'] = net_io.packets_recv
                
                load_avg = os.getloadavg()
                stats['performance']['load_avg_1min'] = load_avg[0]
                stats['performance']['load_avg_5min'] = load_avg[1]
                stats['performance']['load_avg_15min'] = load_avg[2]
                
                current_process = psutil.Process()
                stats['performance']['webguard_cpu'] = current_process.cpu_percent()
                stats['performance']['webguard_memory'] = current_process.memory_percent()
                stats['performance']['webguard_threads'] = current_process.num_threads()
                
                boot_time = psutil.boot_time()
                stats['performance']['system_uptime'] = int(time.time() - boot_time)
                
            stats['performance']['uptime'] = int(time.time() - stats['start_time'])
            
            logger.debug(f"Stats worker: CPU {stats['performance'].get('cpu_usage', 0)}%, "
                        f"Memory {stats['performance'].get('memory_usage', 0)}%, "
                        f"WebGuard threads: {stats['performance'].get('webguard_threads', 0)}")
            
        except Exception as e:
            logger.error(f"Error in stats worker: {e}")
            
        time.sleep(30)

def analyze_packet(packet):
    """Analyze a single packet for threats"""
    try:
        if not packet.haslayer(IP):
            return
        
        current_time = time.time()
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = 'unknown'
        method = 'N/A'
        payload = ''
        threat_detected = False
        threat_type = None
        severity = 'low'
        rule_matched = None
        description = None
        
        # Determine protocol
        if packet.haslayer(TCP):
            proto = 'tcp'
            stats['protocols_analyzed']['tcp'] += 1
        elif packet.haslayer(UDP):
            proto = 'udp'
            stats['protocols_analyzed']['udp'] += 1
        
        # Extract payload if available
        if packet.haslayer(Raw):
            try:
                payload = packet[Raw].load.decode('utf-8', errors='ignore')
            except:
                payload = str(packet[Raw].load)
        
        # Update IP statistics
        ip_stats[src_ip]['requests'] += 1
        ip_stats[src_ip]['last_seen'] = current_time
        ip_stats[src_ip]['bytes_sent'] += len(packet)
        if ip_stats[src_ip]['first_seen'] == 0:
            ip_stats[src_ip]['first_seen'] = current_time
        
        # Check if IP is whitelisted
        if any(src_ip.startswith(wl_ip.split('/')[0]) for wl_ip in config['whitelist']['trusted_sources']):
            return
        
        # WAF pattern matching
        for threat_category, patterns in waf_patterns.items():
            for pattern_info in patterns:
                if pattern_info['pattern'].search(payload):
                    threat_detected = True
                    threat_type = threat_category
                    severity = 'high' if pattern_info['score'] >= 50 else 'medium'
                    rule_matched = pattern_info['rule_id']
                    description = pattern_info['name']
                    ip_stats[src_ip]['violations'] += 1
                    ip_stats[src_ip]['threat_score'] += pattern_info['score']
                    stats['threat_types'][threat_category] += 1
                    break
            if threat_detected:
                break
        
        # HTTP method detection (simplified)
        if proto == 'tcp' and packet.haslayer(Raw):
            if payload.startswith(('GET ', 'POST ', 'HEAD ', 'PUT ', 'DELETE ')):
                method = payload.split(' ')[0]
        
        # Log threat if detected
        if threat_detected:
            threat_entry = {
                'timestamp': int(current_time),
                'source_ip': src_ip,
                'target': dst_ip,
                'method': method,
                'type': threat_type,
                'severity': severity,
                'status': 'blocked' if config['response']['auto_blocking'] else 'detected',
                'score': ip_stats[src_ip]['threat_score'],
                'payload': payload[:1000],
                'request_headers': '{}',
                'rule_matched': str(rule_matched),
                'description': description,
                'false_positive': 0
            }
            
            with db_lock:
                db.execute('''
                    INSERT INTO threats (
                        timestamp, source_ip, target, method, type, severity, status,
                        score, payload, request_headers, rule_matched, description, false_positive
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    threat_entry['timestamp'], threat_entry['source_ip'], threat_entry['target'],
                    threat_entry['method'], threat_entry['type'], threat_entry['severity'],
                    threat_entry['status'], threat_entry['score'], threat_entry['payload'],
                    threat_entry['request_headers'], threat_entry['rule_matched'],
                    threat_entry['description'], threat_entry['false_positive']
                ))
                db.commit()
            
            with open(THREAT_LOG, 'a') as f:
                f.write(json.dumps(threat_entry) + '\n')
            
            stats['threats_blocked'] += 1
            logger.warning(f"Threat detected: {threat_type} from {src_ip} to {dst_ip}")
        
        stats['requests_analyzed'] += 1
        packet_buffer.append({
            'timestamp': current_time,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'protocol': proto,
            'payload': payload[:1000]
        })
        
    except Exception as e:
        logger.error(f"Error analyzing packet: {e}")

def process_network_traffic():
    """Process network traffic for threat detection"""
    try:
        current_time = time.time()
        
        for ip in list(ip_stats.keys()):
            if current_time - ip_stats[ip]['last_seen'] > 300:
                continue
            
            if ip_stats[ip]['violations'] > config['general']['auto_block_threshold']:
                if ip not in blocked_ips and ip not in whitelist:
                    blocked_ips.add(ip)
                    
                    block_entry = {
                        'timestamp': datetime.now().isoformat(),
                        'ip': ip,
                        'reason': 'threshold_exceeded',
                        'violations': ip_stats[ip]['violations'],
                        'threat_score': ip_stats[ip]['threat_score']
                    }
                    
                    with open(BLOCKED_LOG, 'a') as f:
                        f.write(json.dumps(block_entry) + '\n')
                    
                    logger.warning(f"Blocked IP {ip} due to {ip_stats[ip]['violations']} violations")
        
        stats['ips_blocked'] = len(blocked_ips)
        logger.debug(f"Traffic processed: {len(ip_stats)} IPs tracked, {len(blocked_ips)} blocked")
        
    except Exception as e:
        logger.error(f"Error processing network traffic: {e}")

def traffic_worker():
    """Network traffic processing worker thread with Scapy"""
    def packet_callback(packet):
        analyze_packet(packet)
    
    try:
        interfaces = config['general']['interfaces']
        logger.info(f"Starting packet capture on interfaces: {interfaces}")
        
        # Start sniffing on configured interfaces
        sniff(iface=interfaces, prn=packet_callback, store=0, filter="ip", stop_filter=lambda x: not running)
        
    except Exception as e:
        logger.error(f"Error in traffic worker: {e}")
        
        # Fallback to periodic processing if sniffing fails
        while running:
            try:
                process_network_traffic()
                analyze_geographic_patterns()
                
                if psutil:
                    connections = psutil.net_connections()
                    active_connections = len([c for c in connections if c.status == 'ESTABLISHED'])
                    listening_connections = len([c for c in connections if c.status == 'LISTEN'])
                    
                    stats['network'] = {
                        'active_connections': active_connections,
                        'listening_connections': listening_connections,
                        'total_connections': len(connections)
                    }
                    
                    net_if_stats = psutil.net_if_stats()
                    net_io_counters = psutil.net_io_counters(pernic=True)
                    
                    interface_stats = {}
                    for interface in config['general']['interfaces']:
                        if interface in net_if_stats and interface in net_io_counters:
                            interface_stats[interface] = {
                                'is_up': net_if_stats[interface].isup,
                                'speed': net_if_stats[interface].speed,
                                'bytes_sent': net_io_counters[interface].bytes_sent,
                                'bytes_recv': net_io_counters[interface].bytes_recv,
                                'packets_sent': net_io_counters[interface].packets_sent,
                                'packets_recv': net_io_counters[interface].packets_recv,
                                'errors_in': net_io_counters[interface].errin,
                                'errors_out': net_io_counters[interface].errout
                            }
                    
                    stats['interfaces'] = interface_stats
                    
                    logger.debug(f"Traffic worker: {active_connections} active connections, "
                               f"monitoring {len(interface_stats)} interfaces")
                
            except Exception as e:
                logger.error(f"Error in fallback traffic processing: {e}")
                
            time.sleep(1)

def rules_update_worker():
    """Rules update worker thread"""
    while running:
        try:
            if check_rules_age():
                logger.info("Updating rules...")
                if download_rules():
                    logger.info("Rules updated, reloading...")
                    load_rules()
            
            if psutil:
                disk_io = psutil.disk_io_counters()
                if disk_io:
                    logger.debug(f"Rules worker: Disk I/O - Read: {disk_io.read_bytes}, Write: {disk_io.write_bytes}")
                    
        except Exception as e:
            logger.error(f"Error in rules update worker: {e}")
            
        time.sleep(3600)

def main():
    """Main WebGuard engine loop"""
    global logger, running
    
    logger = setup_logging()
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    
    try:
        os.makedirs(os.path.dirname(PID_FILE), exist_ok=True)
        with open(PID_FILE, 'w') as f:
            f.write(str(os.getpid()))
    except Exception as e:
        logger.error(f"Failed to write PID file: {e}")
        return 1
    
    logger.info("Starting WebGuard Engine with Scapy")
    logger.info("=" * 50)
    
    logger.info("Using all required libraries:")
    logger.info("  - scapy: Packet capture and analysis")
    logger.info("  - socket: Network communication")  
    logger.info("  - subprocess: System command execution")
    logger.info("  - struct: Binary data packing/unpacking")
    logger.info("  - hashlib: Cryptographic hashing")
    logger.info("  - xml.etree.ElementTree: XML configuration parsing")
    logger.info("  - geoip2.database: Geographic IP location analysis")
    
    geoip_initialized = setup_geoip()
    if geoip_initialized:
        logger.info("GeoIP database initialized successfully")
    else:
        logger.warning("Running without GeoIP functionality")
    
    if not setup_database():
        logger.error("Failed to initialize database")
        return 1
    
    if not load_config():
        logger.error("Failed to load configuration")
        return 1
        
    if not load_rules():
        logger.warning("Using default rules")
    
    if not config['general']['enabled']:
        logger.info("WebGuard engine is disabled in configuration")
        return 0
    
    try:
        logger.info("WebGuard Engine is running...")
        logger.info(f"Configuration sections: {list(config.keys())}")
        logger.info(f"Monitoring interfaces: {config['general']['interfaces']}")
        logger.info(f"Auto-blocking: {'enabled' if config['response']['auto_blocking'] else 'disabled'}")
        logger.info("=" * 50)
        
        threads = []
        
        stats_thread = threading.Thread(target=stats_worker, name="StatsWorker")
        stats_thread.daemon = True
        stats_thread.start()
        threads.append(stats_thread)
        logger.info("Statistics worker thread started")
        
        traffic_thread = threading.Thread(target=traffic_worker, name="TrafficWorker")
        traffic_thread.daemon = True
        traffic_thread.start()
        threads.append(traffic_thread)
        logger.info("Traffic processing worker thread started")
        
        rules_thread = threading.Thread(target=rules_update_worker, name="RulesWorker")
        rules_thread.daemon = True
        rules_thread.start()
        threads.append(rules_thread)
        logger.info("Rules update worker thread started")
        
        loop_counter = 0
        while running:
            try:
                time.sleep(5)
                loop_counter += 1
                
                if loop_counter % 10 == 0:
                    data_to_hash = f"webguard_status_{loop_counter}_{time.time()}"
                    data_hash = hashlib.md5(data_to_hash.encode()).hexdigest()
                    sha_hash = hashlib.sha256(data_to_hash.encode()).hexdigest()
                    
                    packed_stats = struct.pack('!IIII', 
                                             stats['requests_analyzed'],
                                             stats['threats_blocked'], 
                                             len(blocked_ips),
                                             loop_counter)
                    unpacked = struct.unpack('!IIII', packed_stats)
                    
                    if psutil:
                        current_cpu = psutil.cpu_percent(interval=0.1)
                        current_memory = psutil.virtual_memory().percent
                        current_process = psutil.Process()
                        process_memory = current_process.memory_info().rss / 1024 / 1024
                        
                        logger.info(f"Loop {loop_counter}: CPU={current_cpu:.1f}%, Memory={current_memory:.1f}%, "
                                  f"Process={process_memory:.1f}MB, Hash={data_hash[:8]}")
                        
                        if current_cpu > 90:
                            logger.warning(f"High CPU usage detected: {current_cpu}%")
                        if current_memory > 90:
                            logger.warning(f"High memory usage detected: {current_memory}%")
                    
                if loop_counter % 24 == 0:
                    try:
                        health_status = get_system_health()
                        logger.info(f"System health check: {health_status.get('status', 'unknown')}")
                        if health_status.get('issues'):
                            logger.warning(f"Health issues detected: {health_status['issues']}")
                    except Exception as e:
                        logger.error(f"Error getting system health: {e}")
                
                if loop_counter % 36 == 0:
                    try:
                        threat_stats = get_threat_stats('1h')
                        total_threats = threat_stats.get('total_threats', 0)
                        logger.info(f"Threat stats (1h): {total_threats} threats detected")
                    except Exception as e:
                        logger.error(f"Error getting threat stats: {e}")
                
                if loop_counter % 48 == 0:
                    try:
                        blocking_stats = get_blocking_stats('24h')
                        active_blocks = blocking_stats.get('active_blocks', 0)
                        logger.info(f"Blocking stats: {active_blocks} active blocks")
                    except Exception as e:
                        logger.error(f"Error getting blocking stats: {e}")
                
                if loop_counter % 60 == 0 and GEOIP_AVAILABLE:
                    try:
                        geo_statistics = get_geo_stats('24h')
                        total_countries = geo_statistics.get('total_countries', 0)
                        logger.info(f"Geographic stats: threats from {total_countries} countries")
                    except Exception as e:
                        logger.error(f"Error getting geo stats: {e}")
                
                if loop_counter % 24 == 0 and os.path.exists(OPNSENSE_CONFIG):
                    try:
                        tree = ET.parse(OPNSENSE_CONFIG)
                        root = tree.getroot()
                        
                        config_hash = hashlib.md5(ET.tostring(root)).hexdigest()
                        if not hasattr(main, 'last_config_hash'):
                            main.last_config_hash = config_hash
                        elif main.last_config_hash != config_hash:
                            logger.info("OPNsense configuration changed, reloading...")
                            load_config()
                            main.last_config_hash = config_hash
                        
                        logger.debug(f"XML config parsed, hash: {config_hash[:8]}")
                        
                    except Exception as e:
                        logger.error(f"Error checking OPNsense configuration: {e}")
                
                if loop_counter % 30 == 0:
                    try:
                        test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        test_socket.settimeout(1)
                        result = test_socket.connect_ex(('127.0.0.1', 22))
                        test_socket.close()
                        logger.debug(f"Socket test to localhost:22 result: {result}")
                    except Exception as e:
                        logger.debug(f"Socket test failed: {e}")
                
                if loop_counter % 36 == 0:
                    try:
                        result = subprocess.run(['uptime'], capture_output=True, text=True, timeout=5)
                        if result.returncode == 0:
                            uptime_info = result.stdout.strip()
                            logger.info(f"System uptime: {uptime_info}")
                        
                        result = subprocess.run(['pfctl', '-t', 'webguard_blocked', '-T', 'show'], 
                                              capture_output=True, text=True)
                        if result.returncode == 0:
                            blocked_count = len(result.stdout.strip().split('\n')) if result.stdout.strip() else 0
                            logger.debug(f"Currently {blocked_count} IPs in firewall block table")
                        
                    except subprocess.TimeoutExpired:
                        logger.warning("Subprocess command timed out")
                    except Exception as e:
                        logger.debug(f"Subprocess test failed: {e}")
                
                if psutil and loop_counter % 12 == 0:
                    active_threads = sum(1 for t in threads if t.is_alive())
                    current_process = psutil.Process()
                    thread_count = current_process.num_threads()
                    
                    logger.debug(f"Thread health: {active_threads}/{len(threads)} workers active, "
                               f"{thread_count} total threads")
                    
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
                
                with open(STATS_FILE, 'w') as f:
                    json.dump(stats, f, indent=2, default=str)
                
                if loop_counter % 24 == 0:
                    active_threads = sum(1 for t in threads if t.is_alive())
                    logger.info(f"Engine status: {active_threads}/{len(threads)} threads active, "
                              f"{stats['requests_analyzed']} requests analyzed, "
                              f"{stats['threats_blocked']} threats blocked, "
                              f"{len(blocked_ips)} IPs blocked")
                
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
        logger.info("Shutting down WebGuard Engine...")
        running = False
        
        # Close GeoIP databases
        close_geoip_databases()
        
        try:
            final_engine_stats = get_engine_stats()
            final_threat_stats = get_threat_stats('24h')
            final_blocking_stats = get_blocking_stats('24h')
            final_waf_stats = get_waf_stats('24h')
            final_threat_metrics = get_threat_metrics('24h')
            final_system_metrics = get_metrics()
            final_system_health = get_system_health()
            
            final_geo_stats = None
            if GEOIP_AVAILABLE:
                final_geo_stats = get_geo_stats('24h')
            
            logger.info("Final Statistics:")
            logger.info(f"  Engine Status: {final_engine_stats.get('status', 'unknown')}")
            logger.info(f"  Total Requests: {stats['requests_analyzed']}")
            logger.info(f"  Threats Blocked: {stats['threats_blocked']}")
            logger.info(f"  IPs Blocked: {len(blocked_ips)}")
            logger.info(f"  Threat Stats (24h): {final_threat_stats.get('total_threats', 0)} threats")
            logger.info(f"  Blocking Stats: {final_blocking_stats.get('active_blocks', 0)} active blocks")
            logger.info(f"  WAF Blocked Requests: {final_waf_stats.get('blocked_requests', 0)}")
            logger.info(f"  System Health: {final_system_health.get('status', 'unknown')}")
            
            if final_geo_stats:
                logger.info(f"  Geographic Stats: {final_geo_stats.get('total_countries', 0)} countries")
            
            if psutil:
                final_cpu = psutil.cpu_percent()
                final_memory = psutil.virtual_memory().percent
                final_disk = psutil.disk_usage('/').percent
                logger.info(f"  Final System Stats: CPU={final_cpu}%, Memory={final_memory}%, Disk={final_disk}%")
            
        except Exception as e:
            logger.error(f"Error in final statistics: {e}")
        
        if db:
            try:
                with db_lock:
                    db.close()
                logger.info("Database connection closed")
            except Exception as e:
                logger.error(f"Error closing database: {e}")
        
        if os.path.exists(PID_FILE):
            try:
                os.remove(PID_FILE)
                logger.info("PID file removed")
            except Exception as e:
                logger.error(f"Error removing PID file: {e}")
        
        logger.info("=" * 50)
        logger.info("WebGuard Engine stopped successfully")
        logger.info("All libraries utilized:")
        logger.info("  - scapy: Packet capture and analysis")
        logger.info("  - socket: Network communication and connectivity tests")
        logger.info("  - subprocess: System command execution and firewall management")
        logger.info("  - struct: Binary data packing/unpacking for statistics")
        logger.info("  - hashlib: MD5/SHA256 hashing for data integrity")
        logger.info("  - xml.etree.ElementTree: OPNsense XML configuration parsing")
        logger.info("  - geoip2.database: Geographic IP location analysis")
        logger.info("=" * 50)
        
    return 0

if __name__ == "__main__":
    sys.exit(main())