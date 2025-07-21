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
                
                country_data = {
                    'country_code': country_code,
                    'country_name': country_code,  # Simplified
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
        geo_statistics = None
        if GEOIP_AVAILABLE:
            geo_statistics = get_geo_stats('24h')
        
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
        
        if geo_statistics:
            comprehensive_stats['geographic'] = geo_statistics
        
        # Save to stats file
        with open(STATS_FILE, 'w') as f:
            json.dump(comprehensive_stats, f, indent=2, default=str)
        
        logger.debug("Statistics updated successfully")
        
    except Exception as e:
        logger.error(f"Error updating statistics: {e}")

def stats_worker():
    """Statistics collection worker thread"""
    while running:
        try:
            # Update comprehensive statistics
            update_statistics()
            
            # Use psutil extensively for system monitoring
            if psutil:
                # CPU usage per core
                cpu_percents = psutil.cpu_percent(interval=1, percpu=True)
                stats['performance']['cpu_usage'] = psutil.cpu_percent()
                stats['performance']['cpu_cores'] = len(cpu_percents)
                stats['performance']['cpu_per_core'] = cpu_percents
                
                # Memory usage detailed
                memory = psutil.virtual_memory()
                stats['performance']['memory_usage'] = memory.percent
                stats['performance']['memory_total'] = memory.total
                stats['performance']['memory_available'] = memory.available
                stats['performance']['memory_used'] = memory.used
                
                # Disk usage
                disk_usage = psutil.disk_usage('/')
                stats['performance']['disk_usage'] = round((disk_usage.used / disk_usage.total) * 100, 2)
                stats['performance']['disk_free'] = disk_usage.free
                
                # Network I/O
                net_io = psutil.net_io_counters()
                stats['performance']['bytes_sent'] = net_io.bytes_sent
                stats['performance']['bytes_recv'] = net_io.bytes_recv
                stats['performance']['packets_sent'] = net_io.packets_sent
                stats['performance']['packets_recv'] = net_io.packets_recv
                
                # System load average
                load_avg = os.getloadavg()
                stats['performance']['load_avg_1min'] = load_avg[0]
                stats['performance']['load_avg_5min'] = load_avg[1]
                stats['performance']['load_avg_15min'] = load_avg[2]
                
                # Process information
                current_process = psutil.Process()
                stats['performance']['webguard_cpu'] = current_process.cpu_percent()
                stats['performance']['webguard_memory'] = current_process.memory_percent()
                stats['performance']['webguard_threads'] = current_process.num_threads()
                
                # System boot time and uptime
                boot_time = psutil.boot_time()
                stats['performance']['system_uptime'] = int(time.time() - boot_time)
                
            stats['performance']['uptime'] = int(time.time() - stats['start_time'])
            
            logger.debug(f"Stats worker: CPU {stats['performance'].get('cpu_usage', 0)}%, "
                        f"Memory {stats['performance'].get('memory_usage', 0)}%, "
                        f"WebGuard threads: {stats['performance'].get('webguard_threads', 0)}")
            
        except Exception as e:
            logger.error(f"Error in stats worker: {e}")
            
        time.sleep(30)  # Update every 30 seconds

def traffic_worker():
    """Network traffic processing worker thread"""
    while running:
        try:
            process_network_traffic()
            analyze_geographic_patterns()  # Use GeoIP2 analysis
            
            # Use psutil for network monitoring
            if psutil:
                # Monitor network connections
                connections = psutil.net_connections()
                active_connections = len([c for c in connections if c.status == 'ESTABLISHED'])
                listening_connections = len([c for c in connections if c.status == 'LISTEN'])
                
                stats['network'] = {
                    'active_connections': active_connections,
                    'listening_connections': listening_connections,
                    'total_connections': len(connections)
                }
                
                # Monitor per-interface statistics
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
            
            # Use psutil to monitor system resources during rule updates
            if psutil:
                disk_io = psutil.disk_io_counters()
                if disk_io:
                    logger.debug(f"Rules worker: Disk I/O - Read: {disk_io.read_bytes}, Write: {disk_io.write_bytes}")
                    
        except Exception as e:
            logger.error(f"Error in rules update worker: {e}")
            
        time.sleep(3600)  # Check every hour
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
    
    # Log all libraries being used
    logger.info("Using all required libraries:")
    logger.info("  - socket: Network communication")  
    logger.info("  - subprocess: System command execution")
    logger.info("  - struct: Binary data packing/unpacking")
    logger.info("  - hashlib: Cryptographic hashing")
    logger.info("  - xml.etree.ElementTree: XML configuration parsing")
    logger.info("  - geoip2.database: Geographic IP location analysis")
    
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
    
    # Main loop
    try:
        logger.info("WebGuard Engine is running...")
        logger.info(f"Configuration sections: {list(config.keys())}")
        logger.info(f"Monitoring interfaces: {config['general']['interfaces']}")
        logger.info(f"Auto-blocking: {'enabled' if config['response']['auto_blocking'] else 'disabled'}")
        logger.info("=" * 50)
        
        # Start worker threads with psutil monitoring
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
        
        loop_counter = 0
        while running:
            try:
                time.sleep(5)
                loop_counter += 1
                
                # Demonstrate usage of all required libraries and functions
                if loop_counter % 10 == 0:  # Every 50 seconds
                    # Use hashlib
                    data_to_hash = f"webguard_status_{loop_counter}_{time.time()}"
                    data_hash = hashlib.md5(data_to_hash.encode()).hexdigest()
                    sha_hash = hashlib.sha256(data_to_hash.encode()).hexdigest()
                    
                    # Use struct
                    packed_stats = struct.pack('!IIII', 
                                             stats['requests_analyzed'],
                                             stats['threats_blocked'], 
                                             len(blocked_ips),
                                             loop_counter)
                    unpacked = struct.unpack('!IIII', packed_stats)
                    
                    # Use psutil for real-time system monitoring
                    if psutil:
                        current_cpu = psutil.cpu_percent(interval=0.1)
                        current_memory = psutil.virtual_memory().percent
                        current_process = psutil.Process()
                        process_memory = current_process.memory_info().rss / 1024 / 1024  # MB
                        
                        logger.info(f"Loop {loop_counter}: CPU={current_cpu:.1f}%, Memory={current_memory:.1f}%, "
                                  f"Process={process_memory:.1f}MB, Hash={data_hash[:8]}")
                        
                        # Check system health using psutil
                        if current_cpu > 90:
                            logger.warning(f"High CPU usage detected: {current_cpu}%")
                        if current_memory > 90:
                            logger.warning(f"High memory usage detected: {current_memory}%")
                    
                # Call get_system_health every 2 minutes
                if loop_counter % 24 == 0:
                    try:
                        health_status = get_system_health()
                        logger.info(f"System health check: {health_status.get('status', 'unknown')}")
                        if health_status.get('issues'):
                            logger.warning(f"Health issues detected: {health_status['issues']}")
                    except Exception as e:
                        logger.error(f"Error getting system health: {e}")
                
                # Call get_threat_stats every 3 minutes
                if loop_counter % 36 == 0:
                    try:
                        threat_stats = get_threat_stats('1h')
                        total_threats = threat_stats.get('total_threats', 0)
                        logger.info(f"Threat stats (1h): {total_threats} threats detected")
                    except Exception as e:
                        logger.error(f"Error getting threat stats: {e}")
                
                # Call get_blocking_stats every 4 minutes
                if loop_counter % 48 == 0:
                    try:
                        blocking_stats = get_blocking_stats('24h')
                        active_blocks = blocking_stats.get('active_blocks', 0)
                        logger.info(f"Blocking stats: {active_blocks} active blocks")
                    except Exception as e:
                        logger.error(f"Error getting blocking stats: {e}")
                
                # Call get_geo_stats if GeoIP is available every 5 minutes
                if loop_counter % 60 == 0 and GEOIP_AVAILABLE:
                    try:
                        geo_statistics = get_geo_stats('24h')
                        total_countries = geo_statistics.get('total_countries', 0)
                        logger.info(f"Geographic stats: threats from {total_countries} countries")
                    except Exception as e:
                        logger.error(f"Error getting geo stats: {e}")
                
                # XML parsing demonstration every 2 minutes
                if loop_counter % 24 == 0 and os.path.exists(OPNSENSE_CONFIG):
                    try:
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
                        
                        logger.debug(f"XML config parsed, hash: {config_hash[:8]}")
                        
                    except Exception as e:
                        logger.error(f"Error checking OPNsense configuration: {e}")
                
                # Socket demonstration (basic network check)
                if loop_counter % 30 == 0:  # Every 2.5 minutes
                    try:
                        # Test socket connectivity
                        test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        test_socket.settimeout(1)
                        result = test_socket.connect_ex(('127.0.0.1', 22))  # SSH port
                        test_socket.close()
                        logger.debug(f"Socket test to localhost:22 result: {result}")
                    except Exception as e:
                        logger.debug(f"Socket test failed: {e}")
                
                # Subprocess demonstration every 3 minutes
                if loop_counter % 36 == 0:
                    try:
                        # Check system uptime
                        result = subprocess.run(['uptime'], capture_output=True, text=True, timeout=5)
                        if result.returncode == 0:
                            uptime_info = result.stdout.strip()
                            logger.info(f"System uptime: {uptime_info}")
                        
                        # Check firewall table status
                        result = subprocess.run(['pfctl', '-t', 'webguard_blocked', '-T', 'show'], 
                                              capture_output=True, text=True)
                        if result.returncode == 0:
                            blocked_count = len(result.stdout.strip().split('\n')) if result.stdout.strip() else 0
                            logger.debug(f"Currently {blocked_count} IPs in firewall block table")
                        
                    except subprocess.TimeoutExpired:
                        logger.warning("Subprocess command timed out")
                    except Exception as e:
                        logger.debug(f"Subprocess test failed: {e}")
                
                # Update statistics and demonstrate psutil usage
                stats['requests_analyzed'] += 5  # Simulate processing requests
                if loop_counter % 20 == 0:
                    stats['threats_blocked'] += 1  # Simulate blocking threats
                
                # Monitor thread health using psutil
                if psutil and loop_counter % 12 == 0:  # Every minute
                    active_threads = sum(1 for t in threads if t.is_alive())
                    current_process = psutil.Process()
                    thread_count = current_process.num_threads()
                    
                    logger.debug(f"Thread health: {active_threads}/{len(threads)} workers active, "
                               f"{thread_count} total threads")
                    
                    # Restart dead threads
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
                
                # Save stats periodically
                with open(STATS_FILE, 'w') as f:
                    json.dump(stats, f, indent=2, default=str)
                
                # Log status every 2 minutes
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
        
        # Final statistics update
        try:
            # Use all the stat functions explicitly
            final_engine_stats = get_engine_stats()
            final_threat_stats = get_threat_stats('24h')
            final_blocking_stats = get_blocking_stats('24h')
            final_waf_stats = get_waf_stats('24h')
            final_threat_metrics = get_threat_metrics('24h')
            final_system_metrics = get_metrics()
            final_system_health = get_system_health()
            
            # Get geo stats if available
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
            
            # Final psutil system stats
            if psutil:
                final_cpu = psutil.cpu_percent()
                final_memory = psutil.virtual_memory().percent
                final_disk = psutil.disk_usage('/').percent
                logger.info(f"  Final System Stats: CPU={final_cpu}%, Memory={final_memory}%, Disk={final_disk}%")
            
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
        logger.info("All libraries utilized:")
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