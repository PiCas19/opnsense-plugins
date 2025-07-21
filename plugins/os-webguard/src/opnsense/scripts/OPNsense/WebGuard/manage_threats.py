# ==============================================================================
# manage_threats.py - Threat management operations
# ==============================================================================

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

def mark_false_positive(threat_id, reason=''):
    """Mark a threat as false positive"""
    if not os.path.exists(DB_FILE):
        print("ERROR: Database not found")
        return False
    
    try:
        conn = sqlite3.connect(DB_FILE)
        
        # Check if threat exists
        cursor = conn.execute('SELECT COUNT(*) FROM threats WHERE id = ?', (threat_id,))
        if cursor.fetchone()[0] == 0:
            print(f"ERROR: Threat {threat_id} not found")
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

def whitelist_ip_from_threat(threat_id, description='Added from threat', permanent=True):
    """Add IP to whitelist from threat"""
    if not os.path.exists(DB_FILE):
        print("ERROR: Database not found")
        return False
    
    try:
        conn = sqlite3.connect(DB_FILE)
        
        # Get threat IP
        cursor = conn.execute('SELECT source_ip FROM threats WHERE id = ?', (threat_id,))
        row = cursor.fetchone()
        if not row:
            print(f"ERROR: Threat {threat_id} not found")
            return False
        
        ip_address = row[0]
        current_time = int(time.time())
        
        # Add to whitelist
        conn.execute('''
            INSERT OR REPLACE INTO whitelist 
            (ip_address, description, added_at, expires_at, permanent)
            VALUES (?, ?, ?, ?, ?)
        ''', (ip_address, description, current_time, None, 1 if permanent else 0))
        
        conn.commit()
        conn.close()
        
        print(f"OK: {ip_address} added to whitelist from threat {threat_id}")
        return True
        
    except Exception as e:
        print(f"ERROR: Failed to whitelist IP: {e}")
        return False

def block_ip_from_threat(threat_id, duration=3600, reason='Blocked from threat'):
    """Block IP from threat"""
    if not os.path.exists(DB_FILE):
        print("ERROR: Database not found")
        return False
    
    try:
        conn = sqlite3.connect(DB_FILE)
        
        # Get threat IP
        cursor = conn.execute('SELECT source_ip FROM threats WHERE id = ?', (threat_id,))
        row = cursor.fetchone()
        if not row:
            print(f"ERROR: Threat {threat_id} not found")
            return False
        
        ip_address = row[0]
        current_time = int(time.time())
        expires_at = current_time + duration if duration > 0 else None
        
        # Add to blocked IPs
        conn.execute('''
            INSERT OR REPLACE INTO blocked_ips 
            (ip_address, block_type, blocked_since, expires_at, reason, violations, last_violation)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (ip_address, 'manual', current_time, expires_at, reason, 1, current_time))
        
        conn.commit()
        conn.close()
        
        print(f"OK: {ip_address} blocked from threat {threat_id}")
        return True
        
    except Exception as e:
        print(f"ERROR: Failed to block IP: {e}")
        return False

def create_rule_from_threat(threat_id, rule_name, rule_type='custom', enabled=True):
    """Create custom WAF rule from threat"""
    if not os.path.exists(DB_FILE):
        print("ERROR: Database not found")
        return False
    
    try:
        conn = sqlite3.connect(DB_FILE)
        
        # Get threat details
        cursor = conn.execute('''
            SELECT source_ip, payload, type, method FROM threats WHERE id = ?
        ''', (threat_id,))
        row = cursor.fetchone()
        if not row:
            print(f"ERROR: Threat {threat_id} not found")
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
            'enabled': enabled,
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
    if not os.path.exists(DB_FILE):
        print("ERROR: Database not found")
        return False
    
    try:
        conn = sqlite3.connect(DB_FILE)
        
        cutoff_time = int(time.time() - (days * 86400))
        
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

def main():
    if len(sys.argv) < 2:
        print("Usage: manage_threats.py <command> [args...]")
        print("Commands:")
        print("  false_positive <threat_id> [reason]")
        print("  whitelist_ip <threat_id> [description] [permanent]")
        print("  block_ip <threat_id> [duration] [reason]")
        print("  create_rule <threat_id> <rule_name> [rule_type] [enabled]")
        print("  clear_old <days> [severity]")
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
        permanent = sys.argv[4].lower() in ['true', '1', 'yes'] if len(sys.argv) > 4 else True
        
        whitelist_ip_from_threat(threat_id, description, permanent)
        
    elif command == 'block_ip':
        if len(sys.argv) < 3:
            print("ERROR: Threat ID required")
            sys.exit(1)
        
        threat_id = int(sys.argv[2])
        duration = int(sys.argv[3]) if len(sys.argv) > 3 else 3600
        reason = sys.argv[4] if len(sys.argv) > 4 else 'Blocked from threat'
        
        block_ip_from_threat(threat_id, duration, reason)
        
    elif command == 'create_rule':
        if len(sys.argv) < 4:
            print("ERROR: Threat ID and rule name required")
            sys.exit(1)
        
        threat_id = int(sys.argv[2])
        rule_name = sys.argv[3]
        rule_type = sys.argv[4] if len(sys.argv) > 4 else 'custom'
        enabled = sys.argv[5].lower() in ['true', '1', 'yes'] if len(sys.argv) > 5 else True
        
        create_rule_from_threat(threat_id, rule_name, rule_type, enabled)
        
    elif command == 'clear_old':
        if len(sys.argv) < 3:
            print("ERROR: Days required")
            sys.exit(1)
        
        days = int(sys.argv[2])
        severity = sys.argv[3] if len(sys.argv) > 3 else 'low'
        
        clear_old_threats(days, severity)
        
    else:
        print(f"ERROR: Unknown command: {command}")
        sys.exit(1)

if __name__ == '__main__':
    main()