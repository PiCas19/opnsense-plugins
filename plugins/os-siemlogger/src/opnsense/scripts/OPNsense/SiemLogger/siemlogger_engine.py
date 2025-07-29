#!/usr/local/bin/python3.11

"""
SiemLogger Engine - Autonomous SIEM Logger for Access Logging and Event Export
Copyright (C) 2025 OPNsense SiemLogger Plugin
All rights reserved.

This is a TRUE ENGINE that runs continuously and autonomously.
It monitors logs in real-time, processes events, and exports to SIEM/NDR systems.
"""

import sys
import os
import json
import time
import signal
import threading
import logging
import sqlite3
import re
import subprocess
import select
from collections import deque

# Import modules
try:
    from settings_logger import load_config
except ImportError as e:
    print(f"FATAL: Could not import settings_logger: {e}")
    sys.exit(1)

try:
    from export_events import export_to_siem
except ImportError as e:
    print(f"FATAL: Could not import export_events: {e}")
    sys.exit(1)

# Optional GeoIP support
try:
    import geoip2.database
    import ipaddress
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False

# Configuration paths
LOG_DIR = "/var/log/siemlogger"
EVENT_LOG = f"{LOG_DIR}/events.log"
AUDIT_LOG = f"{LOG_DIR}/audit.log"
ENGINE_LOG = f"{LOG_DIR}/engine.log"
STATS_FILE = f"{LOG_DIR}/stats.json"
DB_FILE = "/var/db/siemlogger/siemlogger.db"
PID_FILE = "/var/run/siemlogger.pid"

# Global state
running = True
config = {}
event_buffer = deque(maxlen=10000)
geoip_reader = None
db = None
db_lock = threading.Lock()

# Statistics tracking
stats = {
    'engine_start_time': time.time(),
    'events_processed': 0,
    'events_exported': 0,
    'threats_detected': 0,
    'failed_login_attempts': 0,
    'successful_logins': 0,
    'configuration_changes': 0,
    'network_events': 0,
    'firewall_blocks': 0,
    'vpn_connections': 0,
    'last_export_time': 0,
    'last_config_reload': time.time(),
    'export_failures': 0,
    'suspicious_activity': {},
    'performance': {
        'events_per_second': 0,
        'avg_processing_time': 0,
        'memory_usage': 0
    }
}

class SiemLoggerEngine:
    """Main SIEM Logger Engine Class"""
    
    def __init__(self):
        self.logger = None
        self.log_watchers = {}
        self.export_thread = None
        self.stats_thread = None
        self.config_reload_thread = None
        
    def setup_logging(self):
        """Initialize logging system"""
        os.makedirs(LOG_DIR, exist_ok=True)
        
        # Ensure all log files exist
        for log_file in [EVENT_LOG, AUDIT_LOG, ENGINE_LOG]:
            if not os.path.exists(log_file):
                with open(log_file, 'w'):
                    pass
        
        # Configure logging
        log_level = getattr(logging, config.get('general', {}).get('log_level', 'INFO'), logging.INFO)
        
        # Create formatter
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        
        # File handler
        file_handler = logging.FileHandler(ENGINE_LOG)
        file_handler.setFormatter(formatter)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        
        # Setup logger
        self.logger = logging.getLogger('SiemLoggerEngine')
        self.logger.setLevel(log_level)
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
        
        self.logger.info("SiemLogger Engine logging initialized")
        
    def setup_database(self):
        """Initialize SQLite database for event storage"""
        global db
        try:
            os.makedirs(os.path.dirname(DB_FILE), exist_ok=True)
            
            with db_lock:
                db = sqlite3.connect(DB_FILE, check_same_thread=False)
                db.execute('PRAGMA journal_mode=WAL')
                db.execute('PRAGMA synchronous=NORMAL')
                db.execute('PRAGMA cache_size=10000')
                
                # Create tables
                db.executescript('''
                    CREATE TABLE IF NOT EXISTS events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp INTEGER NOT NULL,
                        source_ip TEXT,
                        user TEXT,
                        event_type TEXT NOT NULL,
                        description TEXT,
                        details TEXT,
                        severity TEXT NOT NULL,
                        source_log TEXT,
                        country_code TEXT,
                        processed INTEGER DEFAULT 0,
                        exported INTEGER DEFAULT 0
                    );
                    
                    CREATE TABLE IF NOT EXISTS audit_trail (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp INTEGER NOT NULL,
                        user TEXT,
                        action TEXT,
                        resource TEXT,
                        result TEXT,
                        details TEXT
                    );
                    
                    CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
                    CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip);
                    CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
                    CREATE INDEX IF NOT EXISTS idx_events_processed ON events(processed);
                    CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_trail(timestamp);
                ''')
                
                db.commit()
                
            self.logger.info("Database initialized successfully")
            return True
        except Exception as e:
            self.logger.error(f"Failed to initialize database: {e}")
            return False
    
    def setup_geoip(self):
        """Initialize GeoIP database for IP geolocation"""
        global geoip_reader
        if not GEOIP_AVAILABLE:
            self.logger.warning("GeoIP2 library not available. Install with: pkg install py311-geoip2")
            return False
        
        geoip_paths = [
            '/usr/local/share/GeoIP/GeoLite2-Country.mmdb',
            '/var/db/GeoIP/GeoLite2-Country.mmdb',
            '/usr/share/GeoIP/GeoLite2-Country.mmdb'
        ]
        
        for path in geoip_paths:
            try:
                if os.path.exists(path):
                    geoip_reader = geoip2.database.Reader(path)
                    self.logger.info(f"GeoIP database initialized: {path}")
                    return True
            except Exception as e:
                self.logger.debug(f"Failed to load GeoIP from {path}: {e}")
        
        self.logger.warning("GeoIP database not found. IP geolocation disabled.")
        return False
    
    def get_country_info(self, ip_address):
        """Get country information for IP address"""
        if not geoip_reader or not GEOIP_AVAILABLE:
            return {'country_code': 'XX', 'country_name': 'Unknown'}
        
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            if ip_obj.is_private or ip_obj.is_loopback:
                return {'country_code': 'PR', 'country_name': 'Private'}
            
            response = geoip_reader.country(ip_address)
            return {
                'country_code': response.country.iso_code or 'XX',
                'country_name': response.country.name or 'Unknown'
            }
        except Exception:
            return {'country_code': 'XX', 'country_name': 'Unknown'}
    
    def parse_log_line(self, line, source_log):
        """Parse a log line and extract event information"""
        try:
            timestamp = int(time.time())
            event_type = 'unknown'
            source_ip = None  # CORREZIONE: None invece di stringa vuota
            user = None       # CORREZIONE: None invece di 'unknown'
            description = 'System event'
            severity = 'info'
            details = {'log_line': line.strip()}
            
            # Skip empty lines
            if not line.strip():
                return None
            
            logging_rules = config.get('logging_rules', {})
            
            # SSH Authentication Events
            if logging_rules.get('log_authentication', True):
                # SSH successful login
                ssh_success = re.search(r'sshd.*Accepted .* for (\w+) from ([\d\.]+)', line, re.IGNORECASE)
                if ssh_success:
                    user = ssh_success.group(1)
                    source_ip = ssh_success.group(2)
                    event_type = 'authentication'
                    description = 'SSH login successful'
                    severity = 'info'
                    stats['successful_logins'] += 1
                    
                # SSH failed login
                ssh_failed = re.search(r'sshd.*Failed .* for (\w+) from ([\d\.]+)', line, re.IGNORECASE)
                if ssh_failed:
                    user = ssh_failed.group(1)
                    source_ip = ssh_failed.group(2)
                    event_type = 'authentication'
                    description = 'SSH login failed'
                    severity = 'warning'
                    stats['failed_login_attempts'] += 1
                    stats['threats_detected'] += 1
                
                # Web GUI login
                webgui_match = re.search(r'webgui.*action=login.*user=([^\s]+).*src_ip=([^\s]+).*result=(\w+)', line, re.IGNORECASE)
                if webgui_match:
                    user = webgui_match.group(1)
                    source_ip = webgui_match.group(2)
                    result = webgui_match.group(3)
                    event_type = 'authentication'
                    if result.lower() == 'success':
                        description = 'Web GUI login successful'
                        severity = 'info'
                        stats['successful_logins'] += 1
                    else:
                        description = 'Web GUI login failed'
                        severity = 'warning'
                        stats['failed_login_attempts'] += 1
                        stats['threats_detected'] += 1
            
            # Authorization Events
            if logging_rules.get('log_authorization', True):
                sudo_match = re.search(r'sudo.*user=([^\s]+).*command=(.+)', line, re.IGNORECASE)
                if sudo_match:
                    user = sudo_match.group(1)
                    command = sudo_match.group(2)
                    event_type = 'authorization'
                    description = f'Sudo command executed: {command}'
                    severity = 'info'
                    details['command'] = command
            
            # Configuration Changes (MIGLIORATO per OPNsense)
            if logging_rules.get('log_configuration_changes', True):
                # Pattern più specifici per OPNsense
                config_patterns = [
                    r'configd.*user[=:]([^\s]+).*changed',
                    r'config.*user[=:]([^\s]+).*reload',
                    r'webgui.*action=save.*user=([^\s]+)',
                    r'system.*configuration.*changed.*user[=:]([^\s]+)'
                ]
                
                for pattern in config_patterns:
                    config_match = re.search(pattern, line, re.IGNORECASE)
                    if config_match:
                        user = config_match.group(1)
                        event_type = 'configuration'
                        description = 'Configuration change detected'
                        severity = 'info'
                        stats['configuration_changes'] += 1
                        break
            
            # Network Events
            if logging_rules.get('log_network_events', True):
                # VPN connections
                vpn_match = re.search(r'(openvpn|wireguard).*client ([\d\.]+)', line, re.IGNORECASE)
                if vpn_match:
                    source_ip = vpn_match.group(2)
                    event_type = 'network'
                    description = f'{vpn_match.group(1).upper()} client connected'
                    severity = 'info'
                    stats['vpn_connections'] += 1
                    stats['network_events'] += 1
            
            # Firewall Events
            if logging_rules.get('log_firewall_events', True):
                fw_match = re.search(r'filterlog.*src=([\d\.]+).*blocked', line, re.IGNORECASE)
                if fw_match:
                    source_ip = fw_match.group(1)
                    event_type = 'firewall'
                    description = 'Traffic blocked by firewall'
                    severity = 'warning'
                    stats['firewall_blocks'] += 1
                    stats['threats_detected'] += 1
            
            # PATTERN AGGIUNTIVI PER OPNSENSE - MIGLIORA IL PARSING
            
            # Pattern per log di sistema generici
            if event_type == 'unknown':
                # Prova a estrarre IP da vari formati
                ip_patterns = [
                    r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
                    r'from\s+([\d\.]+)',
                    r'src[=:\s]+([\d\.]+)',
                    r'client\s+([\d\.]+)'
                ]
                
                for ip_pattern in ip_patterns:
                    ip_match = re.search(ip_pattern, line)
                    if ip_match:
                        potential_ip = ip_match.group(1)
                        # Verifica che sia un IP valido
                        try:
                            ipaddress.ip_address(potential_ip)
                            if not source_ip:  # Solo se non già trovato
                                source_ip = potential_ip
                            break
                        except ValueError:
                            continue
                
                # Prova a estrarre username da vari formati
                user_patterns = [
                    r'user[=:\s]+([^\s,]+)',
                    r'for\s+([^\s]+)\s+from',
                    r'login[=:\s]+([^\s]+)'
                ]
                
                for user_pattern in user_patterns:
                    user_match = re.search(user_pattern, line)
                    if user_match:
                        potential_user = user_match.group(1)
                        if not user:  # Solo se non già trovato
                            user = potential_user
                        break
                
                # Classifica il tipo di evento basato sul contenuto
                if any(keyword in line.lower() for keyword in ['login', 'auth', 'ssh', 'webgui']):
                    event_type = 'authentication'
                elif any(keyword in line.lower() for keyword in ['config', 'reload', 'save']):
                    event_type = 'configuration'
                elif any(keyword in line.lower() for keyword in ['firewall', 'filter', 'block']):
                    event_type = 'firewall'
                elif any(keyword in line.lower() for keyword in ['vpn', 'openvpn', 'wireguard']):
                    event_type = 'network'
                else:
                    event_type = 'system'
            
            # Get geolocation if available
            geo_info = {}
            if source_ip:
                geo_info = self.get_country_info(source_ip)
            
            details.update(geo_info)
            
            # Check for suspicious activity
            if self.is_suspicious_activity(event_type, source_ip, user, description):
                severity = 'critical'
                stats['threats_detected'] += 1
            
            # CORREZIONE FINALE: Gestire valori None/vuoti correttamente
            event = {
                'timestamp': timestamp,
                'source_ip': source_ip if source_ip else None,        # None se vuoto
                'user': user if user else None,                      # None se vuoto
                'event_type': event_type,
                'description': description,
                'details': json.dumps(details),
                'severity': severity,
                'source_log': source_log,
                'country_code': geo_info.get('country_code', 'XX')
            }
            
            return event
        except Exception as e:
            self.logger.error(f"Error parsing log line: {line} - {e}")
            return None
    
    def is_suspicious_activity(self, event_type, source_ip, user, description):
        """Detect suspicious activity patterns"""
        if not config.get('audit_settings', {}).get('audit_enabled', True):
            return False
        
        threshold = config.get('audit_settings', {}).get('suspicious_activity_threshold', 5)
        key = f"{source_ip or 'unknown'}:{user or 'unknown'}"
        
        # Track failed login attempts
        if event_type == 'authentication' and 'failed' in description.lower():
            if key not in stats['suspicious_activity']:
                stats['suspicious_activity'][key] = {'count': 0, 'first_seen': time.time()}
            
            stats['suspicious_activity'][key]['count'] += 1
            
            if stats['suspicious_activity'][key]['count'] >= threshold:
                self.logger.warning(f"Suspicious activity detected: {key} - {stats['suspicious_activity'][key]['count']} failed attempts")
                return True
        
        return False
    
    def store_event(self, event):
        """Store event in database and log files"""
        try:
            # Store in database
            with db_lock:
                db.execute('''
                    INSERT INTO events (
                        timestamp, source_ip, user, event_type, description, 
                        details, severity, source_log, country_code
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    event['timestamp'], event['source_ip'], event['user'], 
                    event['event_type'], event['description'], event['details'],
                    event['severity'], event['source_log'], event['country_code']
                ))
                db.commit()
            
            # Store in log file
            with open(EVENT_LOG, 'a') as f:
                f.write(json.dumps(event) + '\n')
            
            # Add to buffer for real-time processing
            event_buffer.append(event)
            stats['events_processed'] += 1
            
            self.logger.debug(f"Event stored: {event['event_type']} from {event.get('source_ip', 'N/A')}")
            
        except Exception as e:
            self.logger.error(f"Error storing event: {e}")
    
    def start_log_watcher(self, log_file):
        """Start monitoring a log file in real-time"""
        def watch_log():
            self.logger.info(f"Starting log watcher for: {log_file}")
            try:
                # Use tail -F to follow log file
                process = subprocess.Popen(
                    ['tail', '-F', log_file], 
                    stdout=subprocess.PIPE, 
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1
                )
                
                while running:
                    # Use select to check for available data
                    ready, _, _ = select.select([process.stdout], [], [], 1.0)
                    
                    if ready:
                        line = process.stdout.readline()
                        if line:
                            event = self.parse_log_line(line.strip(), log_file)
                            if event:
                                self.store_event(event)
                    
                    # Check if process is still alive
                    if process.poll() is not None:
                        self.logger.warning(f"Log watcher process died for {log_file}")
                        break
                
                process.terminate()
                
            except Exception as e:
                self.logger.error(f"Error in log watcher for {log_file}: {e}")
        
        # Start watcher thread
        thread = threading.Thread(target=watch_log, name=f"LogWatcher-{os.path.basename(log_file)}")
        thread.daemon = True
        thread.start()
        self.log_watchers[log_file] = thread
        return thread
    
    def export_worker(self):
        """Background worker for exporting events to SIEM/NDR"""
        self.logger.info("Export worker started")
        
        while running:
            try:
                if not config.get('siem_export', {}).get('export_enabled', False):
                    time.sleep(60)
                    continue
                
                export_interval = config.get('siem_export', {}).get('export_interval', 60)
                batch_size = config.get('siem_export', {}).get('batch_size', 100)
                
                # Get unprocessed events
                with db_lock:
                    cursor = db.execute('''
                        SELECT * FROM events 
                        WHERE exported = 0 
                        ORDER BY timestamp ASC 
                        LIMIT ?
                    ''', (batch_size,))
                    
                    events = []
                    event_ids = []
                    for row in cursor.fetchall():
                        event_dict = dict(zip([c[0] for c in cursor.description], row))
                        events.append(event_dict)
                        event_ids.append(event_dict['id'])
                
                if events:
                    self.logger.info(f"Exporting {len(events)} events to SIEM/NDR")
                    
                    # Export events
                    result = export_to_siem(events, config)
                    
                    if result.get('status') == 'ok':
                        # Mark events as exported
                        with db_lock:
                            placeholders = ','.join(['?'] * len(event_ids))
                            db.execute(f'UPDATE events SET exported = 1 WHERE id IN ({placeholders})', event_ids)
                            db.commit()
                        
                        stats['events_exported'] += len(events)
                        stats['last_export_time'] = time.time()
                        self.logger.info(f"Successfully exported {len(events)} events")
                    else:
                        stats['export_failures'] += 1
                        self.logger.error(f"Export failed: {result.get('message', 'Unknown error')}")
                
                time.sleep(export_interval)
                
            except Exception as e:
                self.logger.error(f"Error in export worker: {e}")
                stats['export_failures'] += 1
                time.sleep(60)  # Wait before retrying
    
    def stats_worker(self):
        """Background worker for statistics and maintenance"""
        self.logger.info("Statistics worker started")
        
        while running:
            try:
                # Update statistics
                current_time = time.time()
                uptime = current_time - stats['engine_start_time']
                
                # Calculate events per second
                if uptime > 0:
                    stats['performance']['events_per_second'] = stats['events_processed'] / uptime
                
                # Save statistics
                with open(STATS_FILE, 'w') as f:
                    json.dump(stats, f, indent=2)
                
                # Clean old events (retention policy)
                retention_days = config.get('general', {}).get('event_retention_days', 30)
                retention_seconds = retention_days * 86400
                cutoff_time = current_time - retention_seconds
                
                with db_lock:
                    cursor = db.execute('DELETE FROM events WHERE timestamp < ?', (cutoff_time,))
                    deleted_count = cursor.rowcount
                    db.commit()
                
                if deleted_count > 0:
                    self.logger.info(f"Cleaned {deleted_count} old events (retention: {retention_days} days)")
                
                # Clean old suspicious activity tracking
                for key in list(stats['suspicious_activity'].keys()):
                    if current_time - stats['suspicious_activity'][key]['first_seen'] > 3600:  # 1 hour
                        del stats['suspicious_activity'][key]
                
                time.sleep(30)  # Update every 30 seconds
                
            except Exception as e:
                self.logger.error(f"Error in stats worker: {e}")
                time.sleep(60)
    
    def config_reload_worker(self):
        """Background worker for configuration reloading"""
        self.logger.info("Configuration reload worker started")
        
        while running:
            try:
                # Reload configuration every 5 minutes
                time.sleep(300)
                
                global config
                new_config = load_config()
                if new_config != config:
                    self.logger.info("Configuration changed, reloading...")
                    config = new_config
                    stats['last_config_reload'] = time.time()
                    
                    # Update logging level if changed
                    new_level = getattr(logging, config.get('general', {}).get('log_level', 'INFO'), logging.INFO)
                    self.logger.setLevel(new_level)
                
            except Exception as e:
                self.logger.error(f"Error in config reload worker: {e}")
    
    def start(self):
        """Start the SIEM Logger Engine"""
        global config, running
        
        # Load configuration
        config = load_config()
        if not config:
            print("FATAL: Could not load configuration")
            return 1
        
        # Setup logging
        self.setup_logging()
        self.logger.info("=" * 50)
        self.logger.info("SIEM Logger Engine Starting")
        self.logger.info("=" * 50)
        
        # Check if enabled
        if not config.get('general', {}).get('enabled', True):
            self.logger.info("SIEM Logger Engine is disabled in configuration")
            return 0
        
        # Setup database
        if not self.setup_database():
            self.logger.error("Failed to initialize database")
            return 1
        
        # Setup GeoIP
        self.setup_geoip()
        
        # Write PID file
        try:
            os.makedirs(os.path.dirname(PID_FILE), exist_ok=True)
            with open(PID_FILE, 'w') as f:
                f.write(str(os.getpid()))
            self.logger.info(f"PID file written: {PID_FILE}")
        except Exception as e:
            self.logger.error(f"Failed to write PID file: {e}")
            return 1
        
        # Start log watchers for all configured log sources
        log_sources = config.get('general', {}).get('log_sources', ['/var/log/system/latest.log'])
        custom_logs = config.get('logging_rules', {}).get('custom_log_paths', [])
        all_log_sources = log_sources + custom_logs
        
        self.logger.info(f"Starting log watchers for {len(all_log_sources)} log sources")
        for log_file in all_log_sources:
            if os.path.exists(log_file):
                self.start_log_watcher(log_file)
                self.logger.info(f"Watching: {log_file}")
            else:
                self.logger.warning(f"Log file does not exist: {log_file}")
        
        # Start background workers
        self.export_thread = threading.Thread(target=self.export_worker, name="ExportWorker")
        self.export_thread.daemon = True
        self.export_thread.start()
        
        self.stats_thread = threading.Thread(target=self.stats_worker, name="StatsWorker")
        self.stats_thread.daemon = True
        self.stats_thread.start()
        
        self.config_reload_thread = threading.Thread(target=self.config_reload_worker, name="ConfigReloadWorker")
        self.config_reload_thread.daemon = True
        self.config_reload_thread.start()
        
        self.logger.info("All workers started successfully")
        self.logger.info("SIEM Logger Engine is now running")
        
        # Main loop - just keep the engine alive
        try:
            while running:
                time.sleep(5)
                
                # Basic health check
                if not any(t.is_alive() for t in [self.export_thread, self.stats_thread, self.config_reload_thread]):
                    self.logger.error("All worker threads have died, shutting down")
                    break
                    
        except KeyboardInterrupt:
            self.logger.info("Received keyboard interrupt")
        except Exception as e:
            self.logger.error(f"Error in main loop: {e}")
        
        return self.shutdown()
    
    def shutdown(self):
        """Shutdown the SIEM Logger Engine"""
        global running
        running = False
        
        self.logger.info("Shutting down SIEM Logger Engine...")
        
        # Wait for threads to finish
        for thread_name, thread in [
            ("Export", self.export_thread),
            ("Stats", self.stats_thread),
            ("Config", self.config_reload_thread)
        ]:
            if thread and thread.is_alive():
                self.logger.info(f"Waiting for {thread_name} worker to finish...")
                thread.join(timeout=10)
                if thread.is_alive():
                    self.logger.warning(f"{thread_name} worker did not finish gracefully")
        
        # Close database
        if db:
            try:
                with db_lock:
                    db.close()
                self.logger.info("Database connection closed")
            except Exception as e:
                self.logger.error(f"Error closing database: {e}")
        
        # Close GeoIP
        if geoip_reader:
            try:
                geoip_reader.close()
                self.logger.info("GeoIP database closed")
            except Exception as e:
                self.logger.error(f"Error closing GeoIP: {e}")
        
        # Remove PID file
        try:
            if os.path.exists(PID_FILE):
                os.remove(PID_FILE)
                self.logger.info("PID file removed")
        except Exception as e:
            self.logger.error(f"Error removing PID file: {e}")
        
        # Final statistics
        uptime = time.time() - stats['engine_start_time']
        self.logger.info("=" * 50)
        self.logger.info("SIEM Logger Engine Shutdown Complete")
        self.logger.info(f"Uptime: {uptime:.2f} seconds")
        self.logger.info(f"Events processed: {stats['events_processed']}")
        self.logger.info(f"Events exported: {stats['events_exported']}")
        self.logger.info(f"Threats detected: {stats['threats_detected']}")
        self.logger.info("=" * 50)
        
        return 0

def signal_handler(signum, frame):
    """Handle shutdown signals"""
    global running
    print(f"\nReceived signal {signum}, initiating shutdown...")
    running = False

def main():
    """Main entry point"""
    # Setup signal handlers
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    
    # Create and start engine
    engine = SiemLoggerEngine()
    return engine.start()

if __name__ == "__main__":
    sys.exit(main())