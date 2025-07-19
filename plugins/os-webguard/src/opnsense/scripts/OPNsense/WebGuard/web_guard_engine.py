#!/usr/local/bin/python3

"""
WebGuard Engine - Main Web Application Firewall and Behavioral Analysis Engine
Copyright (C) 2024 OPNsense WebGuard Plugin
All rights reserved.
"""

import sys
import os
import json
import time
import logging
import threading
import sqlite3
import re
import hashlib
import geoip2.database
from datetime import datetime, timedelta
from collections import defaultdict, deque
from ipaddress import ip_address, ip_network
import requests
import numpy as np
from scapy.all import *
import signal
import argparse

# Configuration
CONFIG_FILE = '/usr/local/etc/webguard/config.json'
DB_FILE = '/var/db/webguard/webguard.db'
LOG_DIR = '/var/log/webguard'

class WebGuardEngine:
    def __init__(self, config_file=CONFIG_FILE):
        self.config_file = config_file
        self.config = {}
        self.running = False
        self.stats = {
            'requests_analyzed': 0,
            'threats_blocked': 0,
            'ips_blocked': 0,
            'start_time': time.time(),
            'cpu_usage': 0,
            'memory_usage': 0
        }
        
        # Initialize components
        self.db = None
        self.logger = None
        self.waf_engine = None
        self.behavioral_engine = None
        self.covert_channel_detector = None
        self.response_engine = None
        
        # Traffic analysis
        self.traffic_buffer = deque(maxlen=10000)
        self.ip_stats = defaultdict(lambda: {'requests': 0, 'last_seen': 0, 'violations': 0})
        self.blocked_ips = set()
        self.whitelist = set()
        
        # Behavioral baselines
        self.behavioral_baselines = {}
        self.learning_mode = True
        self.learning_start_time = time.time()
        
        # Initialize
        self.load_config()
        self.setup_logging()
        self.setup_database()
        self.load_rules()
        self.load_geoip()
        
    def load_config(self):
        """Load configuration from file"""
        try:
            with open(self.config_file, 'r') as f:
                self.config = json.load(f)
            
            # Set learning mode based on config
            learning_period = self.config.get('general', {}).get('learning_period', 168) * 3600
            if time.time() - self.learning_start_time < learning_period:
                self.learning_mode = True
            else:
                self.learning_mode = False
                
        except Exception as e:
            print(f"Error loading config: {e}")
            sys.exit(1)
    
    def setup_logging(self):
        """Setup logging configuration"""
        os.makedirs(LOG_DIR, exist_ok=True)
        
        log_level = self.config.get('general', {}).get('log_level', 'info').upper()
        
        # Main engine log
        self.logger = logging.getLogger('webguard')
        self.logger.setLevel(getattr(logging, log_level))
        
        handler = logging.FileHandler(f'{LOG_DIR}/engine.log')
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        
        # Setup specialized loggers
        self.waf_logger = self.setup_specialized_logger('waf')
        self.behavioral_logger = self.setup_specialized_logger('behavioral')
        self.covert_logger = self.setup_specialized_logger('covert_channels')
        self.blocked_logger = self.setup_specialized_logger('blocked')
        
    def setup_specialized_logger(self, name):
        """Setup specialized logger for different components"""
        logger = logging.getLogger(f'webguard.{name}')
        handler = logging.FileHandler(f'{LOG_DIR}/{name}.log')
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        return logger
    
    def setup_database(self):
        """Initialize SQLite database"""
        os.makedirs(os.path.dirname(DB_FILE), exist_ok=True)
        
        self.db = sqlite3.connect(DB_FILE, check_same_thread=False)
        self.db.execute('PRAGMA journal_mode=WAL')
        
        # Create tables
        self.db.executescript('''
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
        
        self.db.commit()
        self.load_blocked_ips()
        self.load_whitelist()
    
    def load_rules(self):
        """Load WAF rules and attack patterns"""
        try:
            # Load WAF rules
            with open('/usr/local/etc/webguard/waf_rules.json', 'r') as f:
                self.waf_rules = json.load(f)
                
            # Load attack patterns
            with open('/usr/local/etc/webguard/attack_patterns.json', 'r') as f:
                self.attack_patterns = json.load(f)
                
            # Load behavioral baselines
            try:
                with open('/usr/local/etc/webguard/behavioral_baseline.json', 'r') as f:
                    self.behavioral_baselines = json.load(f)
            except FileNotFoundError:
                self.behavioral_baselines = {}
                
            self.logger.info("Rules and patterns loaded successfully")
            
        except Exception as e:
            self.logger.error(f"Error loading rules: {e}")
            self.waf_rules = {'rules': []}
            self.attack_patterns = {'patterns': []}
    
    def load_geoip(self):
        """Load GeoIP database"""
        try:
            self.geoip_reader = geoip2.database.Reader('/usr/local/share/GeoIP/GeoLite2-Country.mmdb')
            self.logger.info("GeoIP database loaded successfully")
        except Exception as e:
            self.logger.warning(f"Could not load GeoIP database: {e}")
            self.geoip_reader = None
    
    def load_blocked_ips(self):
        """Load blocked IPs from database"""
        cursor = self.db.execute('''
            SELECT ip_address FROM blocked_ips 
            WHERE expires_at IS NULL OR expires_at > ?
        ''', (int(time.time()),))
        
        self.blocked_ips = set(row[0] for row in cursor.fetchall())
        self.logger.info(f"Loaded {len(self.blocked_ips)} blocked IPs")
    
    def load_whitelist(self):
        """Load whitelist from database"""
        cursor = self.db.execute('''
            SELECT ip_address FROM whitelist 
            WHERE expires_at IS NULL OR expires_at > ?
        ''', (int(time.time()),))
        
        self.whitelist = set(row[0] for row in cursor.fetchall())
        self.logger.info(f"Loaded {len(self.whitelist)} whitelisted IPs")
    
    def start(self):
        """Start the WebGuard engine"""
        self.logger.info("Starting WebGuard Engine")
        self.running = True
        
        # Start monitoring threads
        threading.Thread(target=self.packet_monitor, daemon=True).start()
        threading.Thread(target=self.behavioral_analyzer, daemon=True).start()
        threading.Thread(target=self.covert_channel_monitor, daemon=True).start()
        threading.Thread(target=self.stats_updater, daemon=True).start()
        threading.Thread(target=self.cleanup_worker, daemon=True).start()
        
        # Main loop
        try:
            while self.running:
                time.sleep(1)
                self.update_stats()
        except KeyboardInterrupt:
            self.stop()
    
    def stop(self):
        """Stop the WebGuard engine"""
        self.logger.info("Stopping WebGuard Engine")
        self.running = False
        
        if self.db:
            self.db.close()
        
        if self.geoip_reader:
            self.geoip_reader.close()
    
    def packet_monitor(self):
        """Monitor network packets for threats"""
        if not self.config.get('general', {}).get('enabled', False):
            return
            
        interfaces = self.config.get('general', {}).get('interfaces', [])
        
        try:
            sniff(iface=interfaces, prn=self.analyze_packet, store=0)
        except Exception as e:
            self.logger.error(f"Error in packet monitor: {e}")
    
    def analyze_packet(self, packet):
        """Analyze individual packet for threats"""
        try:
            if not packet.haslayer(IP):
                return
            
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            # Check if source IP is whitelisted
            if self.is_whitelisted(src_ip):
                return
            
            # Check if source IP is blocked
            if self.is_blocked(src_ip):
                self.stats['threats_blocked'] += 1
                return
            
            # Analyze HTTP traffic
            if packet.haslayer(TCP) and packet[TCP].dport in [80, 443, 8080]:
                self.analyze_http_traffic(packet)
            
            # Analyze DNS traffic for tunneling
            if packet.haslayer(DNS):
                self.analyze_dns_traffic(packet)
            
            # Update traffic statistics
            self.update_traffic_stats(src_ip, packet)
            self.stats['requests_analyzed'] += 1
            
        except Exception as e:
            self.logger.error(f"Error analyzing packet: {e}")
    
    def analyze_http_traffic(self, packet):
        """Analyze HTTP traffic for web application attacks"""
        if not self.config.get('waf', {}).get('sql_injection_protection', True):
            return
        
        try:
            # Extract HTTP payload
            if packet.haslayer(Raw):
                payload = packet[Raw].load.decode('utf-8', errors='ignore')
                
                # Analyze payload with WAF rules
                threat = self.waf_analyze(packet[IP].src, payload, packet)
                if threat:
                    self.handle_threat(threat)
                    
        except Exception as e:
            self.logger.error(f"Error analyzing HTTP traffic: {e}")
    
    def analyze_dns_traffic(self, packet):
        """Analyze DNS traffic for tunneling attempts"""
        if not self.config.get('covert_channels', {}).get('dns_tunneling_detection', True):
            return
        
        try:
            dns = packet[DNS]
            
            # Check for suspicious DNS queries
            if dns.qr == 0:  # Query
                query_name = dns.qd.qname.decode('utf-8', errors='ignore')
                
                # Detect DNS tunneling patterns
                if self.detect_dns_tunneling(query_name, packet[IP].src):
                    threat = {
                        'timestamp': int(time.time()),
                        'source_ip': packet[IP].src,
                        'target': query_name,
                        'method': 'DNS',
                        'type': 'dns_tunneling',
                        'severity': 'high',
                        'status': 'detected',
                        'payload': query_name,
                        'description': 'Suspicious DNS tunneling detected'
                    }
                    self.handle_threat(threat)
                    
        except Exception as e:
            self.logger.error(f"Error analyzing DNS traffic: {e}")
    
    def waf_analyze(self, src_ip, payload, packet):
        """Analyze payload with WAF rules"""
        threat_score = 0
        matched_rules = []
        
        for rule in self.waf_rules.get('rules', []):
            if rule.get('enabled', True):
                pattern = rule.get('pattern', '')
                if re.search(pattern, payload, re.IGNORECASE):
                    threat_score += rule.get('score', 10)
                    matched_rules.append(rule.get('name', 'Unknown'))
        
        # Check severity based on score
        if threat_score >= 50:
            severity = 'critical'
        elif threat_score >= 30:
            severity = 'high'
        elif threat_score >= 15:
            severity = 'medium'
        elif threat_score >= 5:
            severity = 'low'
        else:
            return None
        
        # Determine attack type
        attack_type = self.classify_attack(payload)
        
        return {
            'timestamp': int(time.time()),
            'source_ip': src_ip,
            'target': packet[IP].dst,
            'method': 'HTTP',
            'type': attack_type,
            'severity': severity,
            'status': 'detected',
            'score': threat_score,
            'payload': payload[:1000],  # Limit payload size
            'rule_matched': ', '.join(matched_rules),
            'description': f'{attack_type} attack detected with score {threat_score}'
        }
    
    def classify_attack(self, payload):
        """Classify the type of attack based on payload"""
        payload_lower = payload.lower()
        
        if any(sql_pattern in payload_lower for sql_pattern in ['union select', 'or 1=1', 'drop table', '; insert', '; delete']):
            return 'sql_injection'
        elif any(xss_pattern in payload_lower for xss_pattern in ['<script', 'javascript:', 'onerror=', 'onload=']):
            return 'xss'
        elif 'csrf' in payload_lower or 'authenticity_token' in payload_lower:
            return 'csrf'
        elif any(lfi_pattern in payload_lower for lfi_pattern in ['../../../', '..\\..\\..\\', '/etc/passwd', '\\windows\\system32']):
            return 'lfi'
        elif 'http://' in payload_lower or 'https://' in payload_lower:
            return 'rfi'
        else:
            return 'generic'
    
    def detect_dns_tunneling(self, query_name, src_ip):
        """Detect DNS tunneling based on query patterns"""
        # Check for suspicious characteristics
        suspicious_indicators = 0
        
        # Unusually long subdomain
        if len(query_name) > 100:
            suspicious_indicators += 1
        
        # High entropy (random-looking data)
        entropy = self.calculate_entropy(query_name)
        if entropy > 4.5:
            suspicious_indicators += 1
        
        # Base64-like patterns
        if re.search(r'[A-Za-z0-9+/]{20,}=*', query_name):
            suspicious_indicators += 1
        
        # Frequent queries from same IP
        current_time = time.time()
        if src_ip not in self.ip_stats:
            self.ip_stats[src_ip] = {'dns_queries': 0, 'last_dns_query': 0}
        
        if current_time - self.ip_stats[src_ip]['last_dns_query'] < 10:
            self.ip_stats[src_ip]['dns_queries'] += 1
        else:
            self.ip_stats[src_ip]['dns_queries'] = 1
        
        self.ip_stats[src_ip]['last_dns_query'] = current_time
        
        if self.ip_stats[src_ip]['dns_queries'] > 10:
            suspicious_indicators += 1
        
        return suspicious_indicators >= 2
    
    def calculate_entropy(self, data):
        """Calculate Shannon entropy of data"""
        if not data:
            return 0
        
        counts = defaultdict(int)
        for char in data:
            counts[char] += 1
        
        entropy = 0
        length = len(data)
        for count in counts.values():
            p = count / length
            entropy -= p * np.log2(p)
        
        return entropy
    
    def behavioral_analyzer(self):
        """Analyze behavioral patterns"""
        while self.running:
            try:
                if self.config.get('behavioral', {}).get('anomaly_detection', True):
                    self.analyze_behavioral_anomalies()
                time.sleep(30)  # Analyze every 30 seconds
            except Exception as e:
                self.logger.error(f"Error in behavioral analyzer: {e}")
                time.sleep(60)
    
    def analyze_behavioral_anomalies(self):
        """Analyze traffic for behavioral anomalies"""
        current_time = time.time()
        
        for ip, stats in self.ip_stats.items():
            if current_time - stats['last_seen'] > 300:  # Skip old entries
                continue
            
            # Check for beaconing patterns
            if self.detect_beaconing(ip, stats):
                threat = {
                    'timestamp': int(current_time),
                    'source_ip': ip,
                    'target': 'multiple',
                    'method': 'BEHAVIORAL',
                    'type': 'beaconing',
                    'severity': 'high',
                    'status': 'detected',
                    'description': 'Suspicious beaconing pattern detected'
                }
                self.handle_threat(threat)
            
            # Check for data exfiltration
            if self.detect_data_exfiltration(ip, stats):
                threat = {
                    'timestamp': int(current_time),
                    'source_ip': ip,
                    'target': 'multiple',
                    'method': 'BEHAVIORAL',
                    'type': 'data_exfiltration',
                    'severity': 'critical',
                    'status': 'detected',
                    'description': 'Potential data exfiltration detected'
                }
                self.handle_threat(threat)
    
    def detect_beaconing(self, ip, stats):
        """Detect C2 beaconing patterns"""
        if not self.config.get('behavioral', {}).get('beaconing_detection', True):
            return False
        
        # Simplified beaconing detection
        request_count = stats.get('requests', 0)
        time_span = time.time() - stats.get('first_seen', time.time())
        
        if time_span > 0 and request_count > 10:
            frequency = request_count / time_span
            # Regular intervals might indicate beaconing
            return 0.05 < frequency < 0.5
        
        return False
    
    def detect_data_exfiltration(self, ip, stats):
        """Detect potential data exfiltration"""
        if not self.config.get('behavioral', {}).get('data_exfiltration_detection', True):
            return False
        
        # Check for unusual data volumes
        bytes_sent = stats.get('bytes_sent', 0)
        requests = stats.get('requests', 0)
        
        if requests > 0:
            avg_bytes_per_request = bytes_sent / requests
            # Unusually large amounts of data per request
            return avg_bytes_per_request > 50000
        
        return False
    
    def covert_channel_monitor(self):
        """Monitor for covert channels"""
        while self.running:
            try:
                if self.config.get('covert_channels', {}).get('protocol_anomaly_detection', True):
                    self.detect_protocol_anomalies()
                time.sleep(60)  # Check every minute
            except Exception as e:
                self.logger.error(f"Error in covert channel monitor: {e}")
                time.sleep(120)
    
    def detect_protocol_anomalies(self):
        """Detect protocol anomalies that might indicate covert channels"""
        # This is a simplified implementation
        # In practice, this would involve deep packet inspection
        pass
    
    def handle_threat(self, threat):
        """Handle detected threat"""
        try:
            # Log threat
            self.log_threat(threat)
            
            # Store in database
            self.store_threat(threat)
            
            # Take response action
            if self.config.get('response', {}).get('auto_blocking', True):
                self.auto_block_ip(threat['source_ip'], threat)
            
            # Send notifications
            self.send_notifications(threat)
            
            self.stats['threats_blocked'] += 1
            
        except Exception as e:
            self.logger.error(f"Error handling threat: {e}")
    
    def log_threat(self, threat):
        """Log threat to appropriate logger"""
        message = f"THREAT DETECTED - IP: {threat['source_ip']}, Type: {threat['type']}, Severity: {threat['severity']}"
        
        if threat['type'] in ['sql_injection', 'xss', 'csrf', 'lfi', 'rfi']:
            self.waf_logger.warning(message)
        elif threat['type'] in ['beaconing', 'data_exfiltration']:
            self.behavioral_logger.warning(message)
        elif threat['type'] in ['dns_tunneling']:
            self.covert_logger.warning(message)
        
        self.logger.warning(message)
    
    def store_threat(self, threat):
        """Store threat in database"""
        self.db.execute('''
            INSERT INTO threats (timestamp, source_ip, target, method, type, severity, status, score, payload, rule_matched, description)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            threat['timestamp'],
            threat['source_ip'],
            threat['target'],
            threat['method'],
            threat['type'],
            threat['severity'],
            threat['status'],
            threat.get('score', 0),
            threat.get('payload', ''),
            threat.get('rule_matched', ''),
            threat.get('description', '')
        ))
        self.db.commit()
    
    def auto_block_ip(self, ip, threat):
        """Automatically block IP based on threat"""
        if self.is_whitelisted(ip):
            return
        
        # Update violation count
        self.ip_stats[ip]['violations'] += 1
        violations = self.ip_stats[ip]['violations']
        
        threshold = self.config.get('general', {}).get('auto_block_threshold', 5)
        
        if violations >= threshold:
            block_duration = self.config.get('general', {}).get('block_duration', 3600)
            expires_at = int(time.time() + block_duration) if block_duration > 0 else None
            
            self.block_ip(ip, 'automatic', f"Auto-blocked after {violations} violations", expires_at)
    
    def block_ip(self, ip, block_type, reason, expires_at=None):
        """Block an IP address"""
        try:
            current_time = int(time.time())
            
            self.db.execute('''
                INSERT OR REPLACE INTO blocked_ips 
                (ip_address, block_type, blocked_since, expires_at, reason, violations, last_violation)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (ip, block_type, current_time, expires_at, reason, 1, current_time))
            
            self.db.commit()
            self.blocked_ips.add(ip)
            
            self.blocked_logger.info(f"BLOCKED IP: {ip}, Type: {block_type}, Reason: {reason}")
            self.stats['ips_blocked'] += 1
            
        except Exception as e:
            self.logger.error(f"Error blocking IP {ip}: {e}")
    
    def is_blocked(self, ip):
        """Check if IP is blocked"""
        return ip in self.blocked_ips
    
    def is_whitelisted(self, ip):
        """Check if IP is whitelisted"""
        if ip in self.whitelist:
            return True
        
        # Check if IP is in whitelisted networks
        for trusted_network in self.config.get('whitelist', {}).get('trusted_sources', []):
            try:
                if ip_address(ip) in ip_network(trusted_network, strict=False):
                    return True
            except:
                pass
        
        return False
    
    def send_notifications(self, threat):
        """Send threat notifications"""
        webhook_url = self.config.get('response', {}).get('notification_webhook', '')
        
        if webhook_url:
            try:
                payload = {
                    'type': 'threat_detected',
                    'threat': threat,
                    'timestamp': datetime.now().isoformat()
                }
                
                requests.post(webhook_url, json=payload, timeout=10)
                
            except Exception as e:
                self.logger.error(f"Error sending notification: {e}")
    
    def update_traffic_stats(self, src_ip, packet):
        """Update traffic statistics"""
        current_time = time.time()
        
        if src_ip not in self.ip_stats:
            self.ip_stats[src_ip] = {
                'requests': 0,
                'first_seen': current_time,
                'last_seen': current_time,
                'violations': 0,
                'bytes_sent': 0
            }
        
        stats = self.ip_stats[src_ip]
        stats['requests'] += 1
        stats['last_seen'] = current_time
        
        if packet.haslayer(Raw):
            stats['bytes_sent'] += len(packet[Raw].load)
    
    def stats_updater(self):
        """Update engine statistics"""
        while self.running:
            try:
                self.update_stats()
                time.sleep(5)
            except Exception as e:
                self.logger.error(f"Error updating stats: {e}")
                time.sleep(10)
    
    def update_stats(self):
        """Update engine statistics"""
        self.stats['uptime'] = int(time.time() - self.stats['start_time'])
        
        # Update CPU and memory usage (simplified)
        try:
            import psutil
            process = psutil.Process()
            self.stats['cpu_usage'] = process.cpu_percent()
            self.stats['memory_usage'] = process.memory_percent()
        except:
            pass
    
    def cleanup_worker(self):
        """Cleanup expired entries and old data"""
        while self.running:
            try:
                self.cleanup_expired_blocks()
                self.cleanup_old_threats()
                time.sleep(3600)  # Run every hour
            except Exception as e:
                self.logger.error(f"Error in cleanup worker: {e}")
                time.sleep(1800)
    
    def cleanup_expired_blocks(self):
        """Remove expired IP blocks"""
        current_time = int(time.time())
        
        cursor = self.db.execute('''
            SELECT ip_address FROM blocked_ips 
            WHERE expires_at IS NOT NULL AND expires_at <= ?
        ''', (current_time,))
        
        expired_ips = [row[0] for row in cursor.fetchall()]
        
        if expired_ips:
            self.db.execute('''
                DELETE FROM blocked_ips 
                WHERE expires_at IS NOT NULL AND expires_at <= ?
            ''', (current_time,))
            
            self.db.commit()
            
            for ip in expired_ips:
                self.blocked_ips.discard(ip)
            
            self.logger.info(f"Cleaned up {len(expired_ips)} expired blocks")
    
    def cleanup_old_threats(self):
        """Remove old threat records"""
        # Keep threats for 30 days by default
        cutoff_time = int(time.time() - (30 * 24 * 3600))
        
        cursor = self.db.execute('SELECT COUNT(*) FROM threats WHERE timestamp < ?', (cutoff_time,))
        old_count = cursor.fetchone()[0]
        
        if old_count > 0:
            # Keep critical threats longer
            self.db.execute('''
                DELETE FROM threats 
                WHERE timestamp < ? AND severity != 'critical'
            ''', (cutoff_time,))
            
            self.db.commit()
            self.logger.info(f"Cleaned up {old_count} old threat records")
    
    def get_stats(self):
        """Get current engine statistics"""
        return self.stats.copy()

def signal_handler(signum, frame):
    """Handle shutdown signals"""
    print("\nShutdown signal received, stopping WebGuard Engine...")
    global engine
    if engine:
        engine.stop()
    sys.exit(0)

def main():
    parser = argparse.ArgumentParser(description='WebGuard Engine')
    parser.add_argument('--config', default=CONFIG_FILE, help='Configuration file path')
    parser.add_argument('--daemon', action='store_true', help='Run as daemon')
    
    args = parser.parse_args()
    
    # Setup signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Create and start engine
    global engine
    engine = WebGuardEngine(args.config)
    
    if args.daemon:
        # Daemonize process
        import daemon
        with daemon.DaemonContext():
            engine.start()
    else:
        engine.start()

if __name__ == '__main__':
    main()