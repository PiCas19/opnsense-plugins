#!/usr/local/bin/python3.11

"""
SiemLogger Engine - SIEM Logger for Access Logging and Event Export
Copyright (C) 2025 OPNsense SiemLogger Plugin
All rights reserved.
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
from collections import deque

# Import settings_logger
try:
    from settings_logger import load_config
except ImportError as e:
    print(f"Error: Could not import settings_logger: {e}")
    print("Please ensure settings_logger.py is installed in /usr/local/opnsense/scripts/OPNsense/SiemLogger/")
    sys.exit(1)

# Import export_to_siem from export_events
try:
    from export_events import export_to_siem
except ImportError as e:
    print(f"Error: Could not import export_events: {e}")
    print("Please ensure export_events.py is installed in /usr/local/opnsense/scripts/OPNsense/SiemLogger/")
    sys.exit(1)

# Optional GeoIP support for enhanced logging
try:
    import geoip2.database
    import ipaddress
    GEOIP_AVAILABLE = True
except ImportError:
    print("Warning: GeoIP2 library not installed. Install with: pkg install py311-geoip2")
    GEOIP_AVAILABLE = False

# Configuration and logging
LOG_DIR = "/var/log/siemlogger"
EVENT_LOG = f"{LOG_DIR}/events.log"
AUDIT_LOG = f"{LOG_DIR}/audit.log"
ENGINE_LOG = f"{LOG_DIR}/engine.log"
STATS_FILE = f"{LOG_DIR}/stats.json"
DB_FILE = "/var/db/siemlogger/siemlogger.db"
PID_FILE = "/var/run/siemlogger.pid"
OPNSENSE_LOG = "/var/log/system/latest.log"  # Default system log

# Global state
running = True
config = {}
event_buffer = deque(maxlen=10000)
stats = {
    'events_processed': 0,
    'events_exported': 0,
    'threats_detected': 0,
    'start_time': time.time(),
    'last_export': 0,
    'suspicious_activity_count': {}  # Per tracciare attività sospette per IP/utente
}
geoip_reader = None
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
    
    for log_file in [EVENT_LOG, AUDIT_LOG, ENGINE_LOG]:
        if not os.path.exists(log_file):
            with open(log_file, 'w'):
                pass
    
    log_level = getattr(logging, config['general']['log_level'], logging.INFO)
    logging.basicConfig(
        level=log_level,
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
                    source_log TEXT
                );
                
                CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
                CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip);
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
        geoip_reader = geoip2.database.Reader('/usr/local/share/GeoIP/GeoLite2-Country.mmdb')
        logger.info("GeoIP database initialized successfully")
        return True
    except Exception as e:
        logger.error(f"Failed to initialize GeoIP database: {e}")
        geoip_reader = None
        return False

def get_country_info(ip_address):
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
    except Exception as e:
        logger.debug(f"Error looking up IP {ip_address}: {e}")
        return {'country_code': 'XX', 'country_name': 'Unknown'}

def check_suspicious_activity(event):
    """Check for suspicious activity based on audit settings"""
    if not config['audit_settings']['audit_enabled']:
        return False

    threshold = config['audit_settings']['suspicious_activity_threshold']
    key = f"{event['source_ip']}:{event['user']}"
    
    if event['event_type'] in ['authentication', 'authorization'] and 'failed' in event['description'].lower():
        stats['suspicious_activity_count'].setdefault(key, 0)
        stats['suspicious_activity_count'][key] += 1
        
        if stats['suspicious_activity_count'][key] >= threshold:
            logger.warning(f"Suspicious activity detected for {key}: {stats['suspicious_activity_count'][key]} attempts")
            if config['notifications']['alert_on_suspicious_activity']:
                # TODO: Implement send_notification
                pass
            return True
    
    return False

def parse_system_log(line, source_log):
    """Parse a system log line to extract event details"""
    try:
        timestamp = int(time.time())
        event_type = 'unknown'
        source_ip = ''
        user = 'unknown'
        description = 'System event'
        severity = 'info'
        details = line.strip()

        # Apply logging rules
        logging_rules = config['logging_rules']
        
        if logging_rules['log_authentication'] and 'sshd' in line.lower():
            if 'accepted' in line.lower():
                event_type = 'authentication'
                severity = 'info'
                user_match = re.search(r'for (\w+) from', line)
                ip_match = re.search(r'from ([\d\.]+)', line)
                user = user_match.group(1) if user_match else 'unknown'
                source_ip = ip_match.group(1) if ip_match else ''
                description = 'Successful SSH login'
            elif 'failed' in line.lower():
                event_type = 'authentication'
                severity = 'warning'
                user_match = re.search(r'for (\w+) from', line)
                ip_match = re.search(r'from ([\d\.]+)', line)
                user = user_match.group(1) if user_match else 'unknown'
                source_ip = ip_match.group(1) if ip_match else ''
                description = 'Failed SSH login attempt'
                stats['threats_detected'] += 1
        
        elif logging_rules['log_authentication'] and 'webgui' in line.lower() and 'action=login' in line.lower():
            event_type = 'authentication'
            severity = 'info' if 'result=success' in line.lower() else 'warning'
            user_match = re.search(r'user=([^\s]+)', line)
            ip_match = re.search(r'src_ip=([^\s]+)', line)
            user = user_match.group(1) if user_match else 'unknown'
            source_ip = ip_match.group(1) if ip_match else ''
            description = 'Web GUI login attempt' if 'result=success' in line.lower() else 'Failed Web GUI login attempt'
            if 'result=success' not in line.lower():
                stats['threats_detected'] += 1
        
        elif logging_rules['log_vpn_events'] and ('openvpn' in line.lower() or 'wireguard' in line.lower()):
            event_type = 'network'
            severity = 'info'
            ip_match = re.search(r'client ([\d\.]+)', line) or re.search(r'from ([\d\.]+)', line)
            source_ip = ip_match.group(1) if ip_match else ''
            description = 'VPN connection event'
        
        elif logging_rules['log_firewall_events'] and ('filterlog' in line.lower() or 'blocked' in line.lower()):
            event_type = 'firewall'
            severity = 'warning'
            ip_match = re.search(r'src=([\d\.]+)', line) or re.search(r'from ([\d\.]+)', line)
            source_ip = ip_match.group(1) if ip_match else ''
            description = 'Firewall event (blocked)'
            stats['threats_detected'] += 1
        
        elif logging_rules['log_system_events'] and 'system' in line.lower():
            event_type = 'system'
            severity = 'info'
            description = 'Generic system event'
        
        elif logging_rules['log_configuration_changes'] and 'configd' in line.lower():
            event_type = 'configuration'
            severity = 'info'
            user_match = re.search(r'user=([^\s]+)', line)
            user = user_match.group(1) if user_match else 'unknown'
            description = 'Configuration change'
        
        elif logging_rules['log_authorization'] and 'sudo' in line.lower():
            event_type = 'authorization'
            severity = 'info' if 'success' in line.lower() else 'warning'
            user_match = re.search(r'user=([^\s]+)', line)
            user = user_match.group(1) if user_match else 'unknown'
            description = 'Authorization attempt'
            if 'success' not in line.lower():
                stats['threats_detected'] += 1

        # Audit settings
        if config['audit_settings']['audit_enabled']:
            if config['audit_settings']['audit_failed_logins'] and 'failed' in description.lower():
                severity = 'warning'
            if config['audit_settings']['audit_admin_actions'] and user in ['root', 'admin']:
                severity = 'info'
            if config['audit_settings']['audit_privilege_escalation'] and 'sudo' in line.lower():
                severity = 'warning'

        # Check for suspicious activity
        geo_info = get_country_info(source_ip) if source_ip and config.get('siem', {}).get('geoip_enabled', False) else {}
        details = json.dumps({'log_line': line.strip(), 'geo': geo_info})
        
        event = {
            'timestamp': timestamp,
            'source_ip': source_ip,
            'user': user,
            'event_type': event_type,
            'description': description,
            'details': details,
            'severity': severity,
            'source_log': source_log
        }
        
        if check_suspicious_activity(event):
            event['severity'] = 'critical'
        
        return event
    except Exception as e:
        logger.error(f"Error parsing log line: {line} - {e}")
        return None

def log_event(event):
    """Log event to database and file"""
    try:
        with db_lock:
            db.execute('''
                INSERT INTO events (
                    timestamp, source_ip, user, event_type, description, details, severity, source_log
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                event['timestamp'], event['source_ip'], event['user'], event['event_type'],
                event['description'], event['details'], event['severity'], event['source_log']
            ))
            db.commit()
        
        with open(EVENT_LOG, 'a') as f:
            f.write(json.dumps(event) + '\n')
        
        event_buffer.append(event)
        stats['events_processed'] += 1
        logger.debug(f"Logged event: {event['event_type']} from {event['source_ip']}")
        
        # Check log size
        if os.path.getsize(EVENT_LOG) / (1024 * 1024) > config['general']['max_log_size']:
            logger.warning(f"Event log size exceeds {config['general']['max_log_size']} MB")
            # TODO: Implement log rotation
    except Exception as e:
        logger.error(f"Error logging event: {e}")

def export_events(format='json'):
    """Export events to SIEM/NDR using export_to_siem from export_events.py"""
    try:
        with db_lock:
            cursor = db.execute('SELECT * FROM events WHERE timestamp > ? ORDER BY timestamp DESC LIMIT ?',
                             (stats['last_export'], config['siem_export']['batch_size']))
            events = [dict(zip([c[0] for c in cursor.description], row)) for row in cursor.fetchall()]
        
        if not events:
            return {'status': 'ok', 'message': 'No new events to export'}
        
        config['siem_export']['export_format'] = format
        result = export_to_siem(events, config)
        
        if result['status'] == 'ok':
            stats['events_exported'] += len(events)
            stats['last_export'] = int(time.time())
            export_file = f"{LOG_DIR}/export_{format}.log"
            with open(export_file, 'a') as f:
                for event in events:
                    f.write(json.dumps(event) + '\n')
        
        return result
    except Exception as e:
        logger.error(f"Error exporting events: {e}")
        return {'status': 'error', 'message': str(e)}

def clear_logs():
    """Clear event logs from database and file"""
    try:
        with db_lock:
            db.execute('DELETE FROM events')
            db.commit()
        
        for log_file in [EVENT_LOG, AUDIT_LOG]:
            with open(log_file, 'w'):
                pass
        
        logger.info("Event logs cleared successfully")
        return {'status': 'ok', 'message': 'Event logs cleared'}
    except Exception as e:
        logger.error(f"Error clearing logs: {e}")
        return {'status': 'error', 'message': str(e)}

def test_export(format='json'):
    """Test export functionality with a sample event"""
    try:
        test_event = {
            'timestamp': int(time.time()),
            'source_ip': '127.0.0.1',
            'user': 'test_user',
            'event_type': 'test',
            'description': 'Test export event',
            'details': json.dumps({'log_line': 'Test event', 'geo': {}}),
            'severity': 'info',
            'source_log': 'test'
        }
        config['siem_export']['export_format'] = format
        result = export_to_siem([test_event], config)
        logger.info(f"Test export result: {result['message']}")
        return result
    except Exception as e:
        logger.error(f"Error testing export: {e}")
        return {'status': 'error', 'message': str(e)}

def update_statistics():
    """Update and save statistics"""
    try:
        with open(STATS_FILE, 'w') as f:
            json.dump(stats, f, indent=2)
        logger.debug("Statistics updated successfully")
    except Exception as e:
        logger.error(f"Error updating statistics: {e}")

def log_watcher():
    """Monitor system logs for events"""
    try:
        log_sources = config['general']['log_sources'] + config['logging_rules']['custom_log_paths']
        processes = []
        for log_file in log_sources:
            if os.path.exists(log_file):
                process = subprocess.Popen(['tail', '-F', log_file], stdout=subprocess.PIPE, text=True)
                processes.append((process, log_file))
            else:
                logger.warning(f"Log file {log_file} does not exist")
        
        while running:
            for process, log_file in processes:
                line = process.stdout.readline().strip()
                if line:
                    event = parse_system_log(line, log_file)
                    if event:
                        log_event(event)
                time.sleep(0.1)
    except Exception as e:
        logger.error(f"Error in log watcher: {e}")

def export_worker():
    """Periodic export worker"""
    while running:
        try:
            for format in config['siem_export']['enabled_formats']:
                result = export_events(format)
                logger.info(result['message'])
            time.sleep(config['siem_export']['export_interval'])
        except Exception as e:
            logger.error(f"Error in export worker: {e}")
            time.sleep(60)

def stats_worker():
    """Statistics collection worker"""
    while running:
        try:
            update_statistics()
            # Clean old events
            retention_seconds = config['general']['event_retention_days'] * 86400
            with db_lock:
                db.execute('DELETE FROM events WHERE timestamp < ?', (int(time.time()) - retention_seconds,))
                db.commit()
            time.sleep(30)
        except Exception as e:
            logger.error(f"Error in stats worker: {e}")

def get_stats(type='summary'):
    """Get statistics"""
    try:
        if type == 'summary':
            return {
                'status': 'ok',
                'events_processed': stats['events_processed'],
                'events_exported': stats['events_exported'],
                'threats_detected': stats['threats_detected'],
                'uptime': int(time.time() - stats['start_time'])
            }
        elif type == 'detailed':
            return {'status': 'ok', 'stats': stats}
        elif type == 'threats':
            return {'status': 'ok', 'threats_detected': stats['threats_detected']}
        else:
            return {'status': 'error', 'message': f"Unsupported stats type: {type}"}
    except Exception as e:
        logger.error(f"Error getting stats: {e}")
        return {'status': 'error', 'message': str(e)}

def get_logs(page=1, limit=50):
    """Get log entries with pagination"""
    try:
        offset = (int(page) - 1) * int(limit)
        with db_lock:
            cursor = db.execute('SELECT * FROM events ORDER BY timestamp DESC LIMIT ? OFFSET ?', (int(limit), offset))
            events = [dict(zip([c[0] for c in cursor.description], row)) for row in cursor.fetchall()]
            cursor = db.execute('SELECT COUNT(*) FROM events')
            total = cursor.fetchone()[0]
        
        return {
            'status': 'ok',
            'events': events,
            'total': total,
            'page': int(page),
            'limit': int(limit)
        }
    except Exception as e:
        logger.error(f"Error getting logs: {e}")
        return {'status': 'error', 'message': str(e)}

def main():
    """Main SiemLogger engine loop"""
    global logger, running, config
    
    config = load_config()
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
    
    logger.info("Starting SiemLogger Engine")
    
    if not setup_database():
        logger.error("Failed to initialize database")
        return 1
    
    if not config['general']['enabled']:
        logger.info("SiemLogger engine is disabled in configuration")
        return 0
    
    if config.get('siem', {}).get('geoip_enabled', False):
        setup_geoip()
    
    threads = []
    
    log_thread = threading.Thread(target=log_watcher, name="LogWatcher")
    log_thread.daemon = True
    log_thread.start()
    threads.append(log_thread)
    
    export_thread = threading.Thread(target=export_worker, name="ExportWorker")
    export_thread.daemon = True
    export_thread.start()
    threads.append(export_thread)
    
    stats_thread = threading.Thread(target=stats_worker, name="StatsWorker")
    stats_thread.daemon = True
    stats_thread.start()
    threads.append(stats_thread)
    
    while running:
        try:
            time.sleep(5)
        except KeyboardInterrupt:
            logger.info("Received keyboard interrupt")
            break
        except Exception as e:
            logger.error(f"Error in main loop: {e}")
    
    logger.info("Shutting down SiemLogger Engine...")
    running = False
    
    if geoip_reader:
        try:
            geoip_reader.close()
            logger.info("GeoIP database connection closed")
        except Exception as e:
            logger.error(f"Error closing GeoIP database: {e}")
    
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
    
    logger.info("SiemLogger Engine stopped successfully")
    return 0

if __name__ == "__main__":
    if len(sys.argv) > 1:
        command = sys.argv[1]
        if command == "export":
            format = sys.argv[2] if len(sys.argv) > 2 else 'json'
            print(json.dumps(export_events(format)))
        elif command == "stats":
            type = sys.argv[2] if len(sys.argv) > 2 else 'summary'
            print(json.dumps(get_stats(type)))
        elif command == "logs":
            page = sys.argv[2] if len(sys.argv) > 2 else 1
            limit = sys.argv[3] if len(sys.argv) > 3 else 50
            print(json.dumps(get_logs(page, limit)))
        elif command == "clear_logs":
            print(json.dumps(clear_logs()))
        elif command == "test":
            print("Testing SiemLogger Engine...")
            config = load_config()
            print(f"Config: /conf/config.xml")
            print(f"Logs: {LOG_DIR}")
            print(f"Database: {DB_FILE}")
            print("Test complete")
        elif command == "test_export":
            format = sys.argv[2] if len(sys.argv) > 2 else 'json'
            print(json.dumps(test_export(format)))
        elif command == "configure":
            logger.info("Configuration reloaded")
            print(json.dumps({'status': 'ok', 'message': 'Configuration reloaded'}))
        else:
            print(f"Unknown command: {command}")
            sys.exit(1)
    else:
        sys.exit(main())