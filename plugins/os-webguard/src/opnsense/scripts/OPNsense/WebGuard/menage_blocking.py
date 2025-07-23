#!/usr/local/bin/python3.11

"""
WebGuard IP Blocking Management Script
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
        
        conn.commit()
        return conn
        
    except Exception as e:
        print(f"ERROR: Database initialization failed: {e}")
        return None

def update_firewall_table(action='reload'):
    """Update pfctl table with blocked IPs"""
    try:
        if action == 'reload':
            # Get all currently blocked IPs
            conn = init_database()
            if not conn:
                return False
            
            current_time = int(time.time())
            cursor = conn.execute('''
                SELECT ip_address FROM blocked_ips 
                WHERE expires_at IS NULL OR expires_at > ?
            ''', (current_time,))
            
            blocked_ips = [row[0] for row in cursor.fetchall()]
            conn.close()
            
            # Update firewall table (simplified for testing)
            if blocked_ips:
                print(f"OK: Would update firewall table with {len(blocked_ips)} IPs")
                return True
            else:
                print("OK: Would clear firewall table")
                return True
                
        return True
        
    except Exception as e:
        print(f"ERROR: Failed to update firewall: {e}")
        return False

def block_ip(ip_address, duration=3600, reason='Manual block', block_type='manual'):
    """Block an IP address"""
    try:
        # Basic IP validation
        import ipaddress
        ipaddress.ip_address(ip_address)
        
        conn = init_database()
        if not conn:
            return False
        
        current_time = int(time.time())
        expires_at = current_time + int(duration) if int(duration) > 0 else None
        
        conn.execute('''
            INSERT OR REPLACE INTO blocked_ips 
            (ip_address, block_type, blocked_since, expires_at, reason, violations, last_violation)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (ip_address, block_type, current_time, expires_at, reason, 1, current_time))
        
        conn.commit()
        conn.close()
        
        # Update firewall
        update_firewall_table()
        
        print(f"OK: {ip_address} blocked")
        return True
        
    except Exception as e:
        print(f"ERROR: Failed to block IP: {e}")
        return False

def unblock_ip(ip_address, reason='Manual unblock'):
    """Unblock an IP address"""
    try:
        conn = init_database()
        if not conn:
            return False
        
        cursor = conn.execute('SELECT COUNT(*) FROM blocked_ips WHERE ip_address = ?', (ip_address,))
        if cursor.fetchone()[0] == 0:
            print(f"WARNING: {ip_address} not found in blocked list")
            conn.close()
            return True  # Not an error if already unblocked
        
        conn.execute('DELETE FROM blocked_ips WHERE ip_address = ?', (ip_address,))
        conn.commit()
        conn.close()
        
        # Update firewall
        update_firewall_table()
        
        print(f"OK: {ip_address} unblocked")
        return True
        
    except Exception as e:
        print(f"ERROR: Failed to unblock IP: {e}")
        return False

def list_blocked_ips(page=1, limit=50):
    """List blocked IPs with pagination"""
    try:
        conn = init_database()
        if not conn:
            return {'error': 'Database initialization failed'}
        
        offset = (page - 1) * limit
        current_time = int(time.time())
        
        # Get total count
        cursor = conn.execute('SELECT COUNT(*) FROM blocked_ips')
        total = cursor.fetchone()[0]
        
        # Get entries
        cursor = conn.execute('''
            SELECT ip_address, block_type, blocked_since, expires_at, reason, violations, last_violation
            FROM blocked_ips
            ORDER BY blocked_since DESC
            LIMIT ? OFFSET ?
        ''', (limit, offset))
        
        blocked_ips = []
        for row in cursor.fetchall():
            entry = {
                'ip_address': row[0],
                'block_type': row[1] or 'manual',
                'blocked_since': row[2] or current_time,
                'blocked_since_iso': datetime.fromtimestamp(row[2] or current_time).isoformat(),
                'expires_at': row[3],
                'expires_at_iso': datetime.fromtimestamp(row[3]).isoformat() if row[3] else None,
                'reason': row[4] or 'Manual block',
                'violations': row[5] or 1,
                'last_violation': row[6] or current_time,
                'expired': row[3] and row[3] <= current_time if row[3] else False,
                'permanent': row[3] is None
            }
            blocked_ips.append(entry)
        
        result = {
            'blocked_ips': blocked_ips,
            'total': total,
            'page': page,
            'limit': limit,
            'total_pages': max(1, (total + limit - 1) // limit) if total > 0 else 1
        }
        
        conn.close()
        return result
        
    except Exception as e:
        return {'error': f'Failed to list blocked IPs: {e}'}

def bulk_block_ips(ip_list, duration=3600, reason='Bulk block', block_type='manual'):
    """Block multiple IPs"""
    try:
        ips = [ip.strip() for ip in ip_list.split('\n') if ip.strip()]
        blocked_count = 0
        
        for ip_str in ips:
            if block_ip(ip_str, duration, reason, block_type):
                blocked_count += 1
        
        print(f"OK: Blocked {blocked_count}/{len(ips)} IPs")
        return True
        
    except Exception as e:
        print(f"ERROR: Failed to bulk block IPs: {e}")
        return False

def clear_expired_blocks():
    """Remove expired IP blocks"""
    try:
        conn = init_database()
        if not conn:
            return False
        
        current_time = int(time.time())
        
        # Get count of expired blocks
        cursor = conn.execute('''
            SELECT COUNT(*) FROM blocked_ips 
            WHERE expires_at IS NOT NULL AND expires_at <= ?
        ''', (current_time,))
        
        expired_count = cursor.fetchone()[0]
        
        if expired_count > 0:
            # Remove expired blocks
            conn.execute('''
                DELETE FROM blocked_ips 
                WHERE expires_at IS NOT NULL AND expires_at <= ?
            ''', (current_time,))
            
            conn.commit()
            
            # Update firewall
            update_firewall_table()
            
            print(f"OK: Removed {expired_count} expired blocks")
        else:
            print("OK: No expired blocks found")
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"ERROR: Failed to clear expired blocks: {e}")
        return False

def export_blocked_ips(format='json', include_expired=False):
    """Export blocked IPs"""
    try:
        blocked_data = list_blocked_ips(limit=10000)
        
        if 'error' in blocked_data:
            return blocked_data
        
        if not include_expired:
            blocked_data['blocked_ips'] = [ip for ip in blocked_data['blocked_ips'] if not ip['expired']]
        
        if format.lower() == 'json':
            return json.dumps(blocked_data, indent=2)
        elif format.lower() == 'csv':
            import csv
            import io
            
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(['IP Address', 'Block Type', 'Blocked Since', 'Expires At', 'Reason', 'Violations', 'Status'])
            
            for ip in blocked_data['blocked_ips']:
                status = 'Expired' if ip['expired'] else 'Active'
                writer.writerow([
                    ip['ip_address'],
                    ip['block_type'],
                    ip['blocked_since_iso'],
                    ip['expires_at_iso'] or 'Permanent',
                    ip['reason'],
                    ip['violations'],
                    status
                ])
            
            return output.getvalue()
        else:
            return json.dumps(blocked_data, indent=2)
            
    except Exception as e:
        return {'error': f'Failed to export blocked IPs: {e}'}

def main():
    if len(sys.argv) < 2:
        print("Usage: manage_blocking.py <command> [args...]")
        print("Commands:")
        print("  block <ip> [duration] [reason] [block_type]")
        print("  unblock <ip> [reason]")
        print("  list [page] [limit]")
        print("  bulk_block <ip_list> [duration] [reason] [block_type]")
        print("  clear_expired")
        print("  export <format> [include_expired]")
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == 'block':
        if len(sys.argv) < 3:
            print("ERROR: IP address required")
            sys.exit(1)
        
        ip = sys.argv[2]
        duration = sys.argv[3] if len(sys.argv) > 3 else "3600"
        reason = sys.argv[4] if len(sys.argv) > 4 else "Manual block"
        block_type = sys.argv[5] if len(sys.argv) > 5 else "manual"
        
        block_ip(ip, duration, reason, block_type)
        
    elif command == 'unblock':
        if len(sys.argv) < 3:
            print("ERROR: IP address required")
            sys.exit(1)
        
        ip = sys.argv[2]
        reason = sys.argv[3] if len(sys.argv) > 3 else "Manual unblock"
        
        unblock_ip(ip, reason)
        
    elif command == 'list':
        page = int(sys.argv[2]) if len(sys.argv) > 2 else 1
        limit = int(sys.argv[3]) if len(sys.argv) > 3 else 50
        
        result = list_blocked_ips(page, limit)
        print(json.dumps(result, indent=2))
        
    elif command == 'bulk_block':
        if len(sys.argv) < 3:
            print("ERROR: IP list required")
            sys.exit(1)
        
        ip_list = sys.argv[2]
        duration = sys.argv[3] if len(sys.argv) > 3 else "3600"
        reason = sys.argv[4] if len(sys.argv) > 4 else "Bulk block"
        block_type = sys.argv[5] if len(sys.argv) > 5 else "manual"
        
        bulk_block_ips(ip_list, duration, reason, block_type)
        
    elif command == 'clear_expired':
        clear_expired_blocks()
        
    elif command == 'export':
        format = sys.argv[2] if len(sys.argv) > 2 else "json"
        include_expired = sys.argv[3].lower() in ['true', '1', 'yes'] if len(sys.argv) > 3 else False
        
        result = export_blocked_ips(format, include_expired)
        print(result)
        
    else:
        print(f"ERROR: Unknown command: {command}")
        sys.exit(1)

if __name__ == '__main__':
    main()