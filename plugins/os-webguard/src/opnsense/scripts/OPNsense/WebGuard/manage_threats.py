#!/usr/local/bin/python3.11

"""
WebGuard Threat Management Script
Copyright (C) 2024 OPNsense WebGuard Plugin
All rights reserved.
"""

import sys
import json
import sqlite3
import os
import time
from datetime import datetime

DB_FILE = '/var/db/webguard/webguard.db'

def init_database():
    """Initialize database connection with auto-creation"""
    try:
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(DB_FILE), exist_ok=True)
        
        conn = sqlite3.connect(DB_FILE)
        
        # Create tables if they don't exist
        conn.execute('''
            CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER,
                source_ip TEXT,
                type TEXT,
                severity TEXT,
                description TEXT,
                false_positive INTEGER DEFAULT 0,
                payload TEXT,
                method TEXT
            )
        ''')
        
        conn.execute('''
            CREATE TABLE IF NOT EXISTS blocked_ips (
                ip_address TEXT PRIMARY KEY,
                block_type TEXT DEFAULT 'manual',
                blocked_since INTEGER,
                expires_at INTEGER,
                reason TEXT,
                violations INTEGER DEFAULT 1,
                last_violation INTEGER
            )
        ''')
        
        conn.execute('''
            CREATE TABLE IF NOT EXISTS whitelist (
                ip_address TEXT PRIMARY KEY,
                description TEXT,
                added_at INTEGER,
                expires_at INTEGER,
                permanent INTEGER DEFAULT 1
            )
        ''')
        
        conn.commit()
        return conn
        
    except Exception as e:
        print(f"ERROR: Database initialization failed: {e}")
        return None

def get_threats(page=1):
    """Get threats with pagination"""
    try:
        conn = init_database()
        if not conn:
            return False
        
        limit = 50
        offset = (int(page) - 1) * limit
        
        # Get total count
        cursor = conn.execute('SELECT COUNT(*) FROM threats WHERE false_positive = 0')
        total = cursor.fetchone()[0]
        
        # Get threats with pagination
        cursor = conn.execute('''
            SELECT id, timestamp, source_ip, type, severity, description, payload, method
            FROM threats 
            WHERE false_positive = 0
            ORDER BY timestamp DESC
            LIMIT ? OFFSET ?
        ''', (limit, offset))
        
        threats = []
        for row in cursor.fetchall():
            threat_id, timestamp, source_ip, threat_type, severity, description, payload, method = row
            
            threats.append({
                'id': threat_id,
                'ip_address': source_ip,
                'threat_type': threat_type,
                'severity': severity,
                'description': description,
                'payload': payload,
                'method': method,
                'first_seen': timestamp,
                'first_seen_iso': datetime.fromtimestamp(timestamp).isoformat(),
                'last_seen': timestamp,
                'last_seen_iso': datetime.fromtimestamp(timestamp).isoformat()
            })
        
        result = {
            'threats': threats,
            'total': total,
            'page': int(page),
            'limit': limit,
            'pages': (total + limit - 1) // limit
        }
        
        print(json.dumps(result, indent=2))
        conn.close()
        return True
        
    except Exception as e:
        print(f"ERROR: Failed to get threats: {e}")
        return False

def mark_false_positive(threat_id, reason=''):
    """Mark a threat as false positive"""
    try:
        conn = init_database()
        if not conn:
            return False
        
        # Check if threat exists
        cursor = conn.execute('SELECT COUNT(*) FROM threats WHERE id = ?', (threat_id,))
        if cursor.fetchone()[0] == 0:
            print(f"ERROR: Threat {threat_id} not found")
            conn.close()
            return False
        
        # Mark as false positive
        conn.execute('''
            UPDATE threats 
            SET false_positive = 1, description = description || ? 
            WHERE id = ?
        ''', (f' [FALSE POSITIVE: {reason}]' if reason else ' [FALSE POSITIVE]', threat_id))
        
        conn.commit()
        conn.close()
        
        print(f"OK: Threat {threat_id} marked as false positive")
        return True
        
    except Exception as e:
        print(f"ERROR: Failed to mark false positive: {e}")
        return False

def whitelist_ip_from_threat(threat_id, description='Added from threat', permanent='1'):
    """Add IP to whitelist from threat"""
    try:
        conn = init_database()
        if not conn:
            return False
        
        # Get threat IP
        cursor = conn.execute('SELECT source_ip FROM threats WHERE id = ?', (threat_id,))
        row = cursor.fetchone()
        if not row:
            print(f"ERROR: Threat {threat_id} not found")
            conn.close()
            return False
        
        ip_address = row[0]
        current_time = int(time.time())
        
        # Add to whitelist
        conn.execute('''
            INSERT OR REPLACE INTO whitelist 
            (ip_address, description, added_at, expires_at, permanent)
            VALUES (?, ?, ?, ?, ?)
        ''', (ip_address, description, current_time, None, 1 if permanent == '1' else 0))
        
        conn.commit()
        conn.close()
        
        print(f"OK: {ip_address} added to whitelist from threat {threat_id}")
        return True
        
    except Exception as e:
        print(f"ERROR: Failed to whitelist IP: {e}")
        return False

def block_ip_from_threat(threat_id, duration=3600, reason='Blocked from threat'):
    """Block IP from threat"""
    try:
        conn = init_database()
        if not conn:
            return False
        
        # Get threat IP
        cursor = conn.execute('SELECT source_ip FROM threats WHERE id = ?', (threat_id,))
        row = cursor.fetchone()
        if not row:
            print(f"ERROR: Threat {threat_id} not found")
            conn.close()
            return False
        
        ip_address = row[0]
        current_time = int(time.time())
        expires_at = current_time + int(duration) if int(duration) > 0 else None
        
        # Add to blocked IPs
        conn.execute('''
            INSERT OR REPLACE INTO blocked_ips 
            (ip_address, block_type, blocked_since, expires_at, reason, violations, last_violation)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (ip_address, 'threat', current_time, expires_at, reason, 1, current_time))
        
        conn.commit()
        conn.close()
        
        print(f"OK: {ip_address} blocked from threat {threat_id}")
        return True
        
    except Exception as e:
        print(f"ERROR: Failed to block IP: {e}")
        return False

def create_rule_from_threat(threat_id, rule_name, rule_type='custom', enabled='1'):
    """Create custom WAF rule from threat"""
    try:
        conn = init_database()
        if not conn:
            return False
        
        # Get threat details
        cursor = conn.execute('''
            SELECT source_ip, payload, type, method FROM threats WHERE id = ?
        ''', (threat_id,))
        row = cursor.fetchone()
        if not row:
            print(f"ERROR: Threat {threat_id} not found")
            conn.close()
            return False
        
        source_ip, payload, threat_type, method = row
        
        # Create rule pattern from payload
        if payload:
            # Simple pattern creation (in production, this would be more sophisticated)
            pattern = payload[:100].replace('(', '\\(').replace(')', '\\)').replace('[', '\\[').replace(']', '\\]')
        else:
            pattern = f"threat_type_{threat_type}"
        
        # Save rule (simplified - would integrate with WAF rules system)
        rule_data = {
            'id': int(time.time()),
            'name': rule_name,
            'type': rule_type,
            'pattern': pattern,
            'enabled': enabled == '1',
            'source_threat_id': threat_id,
            'created_at': datetime.now().isoformat()
        }
        
        # In production, this would be saved to WAF rules file
        rules_file = f"/tmp/custom_rule_{threat_id}.json"
        with open(rules_file, 'w') as f:
            json.dump(rule_data, f, indent=2)
        
        conn.close()
        
        print(f"OK: Custom rule created from threat {threat_id}: {rules_file}")
        return True
        
    except Exception as e:
        print(f"ERROR: Failed to create rule: {e}")
        return False

def clear_old_threats(days=30, severity='low'):
    """Clear old threats based on age and severity"""
    try:
        conn = init_database()
        if not conn:
            return False
        
        cutoff_time = int(time.time() - (int(days) * 86400))
        
        # Get count before deletion
        cursor = conn.execute('''
            SELECT COUNT(*) FROM threats 
            WHERE timestamp < ? AND severity = ?
        ''', (cutoff_time, severity))
        
        old_count = cursor.fetchone()[0]
        
        if old_count > 0:
            # Delete old threats
            conn.execute('''
                DELETE FROM threats 
                WHERE timestamp < ? AND severity = ?
            ''', (cutoff_time, severity))
            
            conn.commit()
            print(f"OK: Removed {old_count} old {severity} threats older than {days} days")
        else:
            print(f"OK: No old {severity} threats found older than {days} days")
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"ERROR: Failed to clear old threats: {e}")
        return False

def add_sample_threats():
    """Add some sample threats for testing"""
    try:
        conn = init_database()
        if not conn:
            return False
        
        current_time = int(time.time())
        
        sample_threats = [
            ('192.168.1.100', 'SQL Injection', 'high', 'SQL injection attempt detected', "' OR 1=1 --", 'POST'),
            ('10.0.0.50', 'XSS Attack', 'medium', 'Cross-site scripting attempt', '<script>alert("xss")</script>', 'GET'),
            ('172.16.0.25', 'Path Traversal', 'medium', 'Directory traversal attempt', '../../../etc/passwd', 'GET'),
            ('203.0.113.100', 'Brute Force', 'low', 'Multiple failed login attempts', 'admin:password123', 'POST'),
            ('198.51.100.200', 'Bot Activity', 'low', 'Suspicious bot behavior detected', 'User-Agent: BadBot/1.0', 'GET')
        ]
        
        for source_ip, threat_type, severity, description, payload, method in sample_threats:
            conn.execute('''
                INSERT OR IGNORE INTO threats 
                (timestamp, source_ip, type, severity, description, payload, method, false_positive)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (current_time - (len(sample_threats) * 3600), source_ip, threat_type, severity, description, payload, method, 0))
        
        conn.commit()
        conn.close()
        
        print(f"OK: Added {len(sample_threats)} sample threats")
        return True
        
    except Exception as e:
        print(f"ERROR: Failed to add sample threats: {e}")
        return False

def get_recent_threats(limit=10):
    """Get recent threats for dashboard"""
    try:
        conn = init_database()
        if not conn:
            return False
        
        # Get recent threats
        cursor = conn.execute('''
            SELECT id, timestamp, source_ip, type, severity, description, payload, method
            FROM threats 
            WHERE false_positive = 0
            ORDER BY timestamp DESC
            LIMIT ?
        ''', (int(limit),))
        
        threats = []
        for row in cursor.fetchall():
            threat_id, timestamp, source_ip, threat_type, severity, description, payload, method = row
            
            threats.append({
                'id': threat_id,
                'timestamp': datetime.fromtimestamp(timestamp).isoformat() + 'Z',
                'source_ip': source_ip,
                'threat_type': threat_type,
                'severity': severity,
                'url': f"/target-{threat_id}",  # You might want to store actual URL
                'method': method or 'GET',
                'status': 'detected'
            })
        
        result = {
            'status': 'ok',
            'recent': threats
        }
        
        print(json.dumps(result))
        conn.close()
        return True
        
    except Exception as e:
        print(f'{{"status": "error", "message": "Failed to get recent threats: {e}"}}')
        return False

def get_threat_feed(since_id=0, limit=50):
    """Get threat feed since a specific ID"""
    try:
        conn = init_database()
        if not conn:
            return False
        
        # Get threats since specific ID
        cursor = conn.execute('''
            SELECT id, timestamp, source_ip, type, severity, description, method
            FROM threats 
            WHERE false_positive = 0 AND id > ?
            ORDER BY id DESC
            LIMIT ?
        ''', (int(since_id), int(limit)))
        
        feed = []
        last_id = int(since_id)
        
        for row in cursor.fetchall():
            threat_id, timestamp, source_ip, threat_type, severity, description, method = row
            
            feed.append({
                'id': threat_id,
                'timestamp': datetime.fromtimestamp(timestamp).isoformat() + 'Z',
                'source_ip': source_ip,
                'threat_type': threat_type,
                'severity': severity,
                'url': f"/target-{threat_id}",
                'method': method or 'GET',
                'status': 'detected'
            })
            last_id = max(last_id, threat_id)
        
        result = {
            'status': 'ok',
            'feed': feed,
            'lastId': last_id
        }
        
        print(json.dumps(result))
        conn.close()
        return True
        
    except Exception as e:
        print(f'{{"status": "error", "message": "Failed to get threat feed: {e}"}}')
        return False

def get_threat_timeline(period='24h'):
    """Get threat timeline data for charts"""
    try:
        conn = init_database()
        if not conn:
            return False
        
        # Calculate time range based on period
        current_time = int(time.time())
        
        if period == '1h':
            start_time = current_time - 3600
            interval = 300  # 5 minutes
            intervals = 12
        elif period == '6h':
            start_time = current_time - (6 * 3600)
            interval = 1800  # 30 minutes
            intervals = 12
        elif period == '24h':
            start_time = current_time - (24 * 3600)
            interval = 7200  # 2 hours
            intervals = 12
        elif period == '7d':
            start_time = current_time - (7 * 24 * 3600)
            interval = 86400  # 1 day
            intervals = 7
        else:
            start_time = current_time - (24 * 3600)
            interval = 7200
            intervals = 12
        
        # Get threat counts for each interval
        labels = []
        threats = []
        requests = []  # Mock data for requests
        
        for i in range(intervals):
            interval_start = start_time + (i * interval)
            interval_end = interval_start + interval
            
            # Format label based on period
            if period in ['1h', '6h', '24h']:
                label = datetime.fromtimestamp(interval_start).strftime('%H:%M')
            else:
                label = datetime.fromtimestamp(interval_start).strftime('%m/%d')
            
            # Count threats in this interval
            cursor = conn.execute('''
                SELECT COUNT(*) FROM threats 
                WHERE timestamp >= ? AND timestamp < ? AND false_positive = 0
            ''', (interval_start, interval_end))
            
            threat_count = cursor.fetchone()[0]
            
            labels.append(label)
            threats.append(threat_count)
            requests.append(threat_count * 20 + 50)  # Mock request data
        
        result = {
            'status': 'ok',
            'timeline': {
                'labels': labels,
                'threats': threats,
                'requests': requests
            },
            'period': period
        }
        
        print(json.dumps(result))
        conn.close()
        return True
        
    except Exception as e:
        print(f'{{"status": "error", "message": "Failed to get timeline: {e}"}}')
        return False
    
def main():
    if len(sys.argv) < 2:
        print("Usage: manage_threats.py <command> [args...]")
        print("Commands:")
        print("  false_positive <threat_id> [reason]")
        print("  whitelist_ip <threat_id> [description] [permanent]")
        print("  block_ip <threat_id> [duration] [reason]")
        print("  create_rule <threat_id> <rule_name> [rule_type] [enabled]")
        print("  clear_old <days> [severity]")
        print("  add_samples")
        print("  get_threats [page]")
        print("  get_recent [limit]")
        print("  get_feed <since_id> [limit]")
        print("  get_timeline [period]")
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == 'false_positive':
        if len(sys.argv) < 3:
            print("ERROR: Threat ID required")
            sys.exit(1)
        
        threat_id = int(sys.argv[2])
        reason = sys.argv[3] if len(sys.argv) > 3 else ''
        
        mark_false_positive(threat_id, reason)
        
    elif command == 'whitelist_ip':
        if len(sys.argv) < 3:
            print("ERROR: Threat ID required")
            sys.exit(1)
        
        threat_id = int(sys.argv[2])
        description = sys.argv[3] if len(sys.argv) > 3 else 'Added from threat'
        permanent = sys.argv[4] if len(sys.argv) > 4 else '1'
        
        whitelist_ip_from_threat(threat_id, description, permanent)
        
    elif command == 'block_ip':
        if len(sys.argv) < 3:
            print("ERROR: Threat ID required")
            sys.exit(1)
        
        threat_id = int(sys.argv[2])
        duration = sys.argv[3] if len(sys.argv) > 3 else '3600'
        reason = sys.argv[4] if len(sys.argv) > 4 else 'Blocked from threat'
        
        block_ip_from_threat(threat_id, duration, reason)
        
    elif command == 'create_rule':
        if len(sys.argv) < 4:
            print("ERROR: Threat ID and rule name required")
            sys.exit(1)
        
        threat_id = int(sys.argv[2])
        rule_name = sys.argv[3]
        rule_type = sys.argv[4] if len(sys.argv) > 4 else 'custom'
        enabled = sys.argv[5] if len(sys.argv) > 5 else '1'
        
        create_rule_from_threat(threat_id, rule_name, rule_type, enabled)
        
    elif command == 'clear_old':
        if len(sys.argv) < 3:
            print("ERROR: Days required")
            sys.exit(1)
        
        days = sys.argv[2]
        severity = sys.argv[3] if len(sys.argv) > 3 else 'low'
        
        clear_old_threats(days, severity)
        
    elif command == 'add_samples':
        add_sample_threats()
        
    elif command == 'get_threats':
        page = sys.argv[2] if len(sys.argv) > 2 else '1'
        get_threats(page)
        
    elif command == 'get_recent':
        limit = sys.argv[2] if len(sys.argv) > 2 else '10'
        get_recent_threats(int(limit))
        
    elif command == 'get_feed':
        if len(sys.argv) < 3:
            print("ERROR: Since ID required")
            sys.exit(1)
        since_id = sys.argv[2]
        limit = sys.argv[3] if len(sys.argv) > 3 else '50'
        get_threat_feed(int(since_id), int(limit))
        
    elif command == 'get_timeline':
        period = sys.argv[2] if len(sys.argv) > 2 else '24h'
        get_threat_timeline(period)
        
    else:
        print(f"ERROR: Unknown command: {command}")
        sys.exit(1)

if __name__ == '__main__':
    main()