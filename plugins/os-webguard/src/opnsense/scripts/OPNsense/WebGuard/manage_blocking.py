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
        
        # Create table if it doesn't exist
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
        
        conn.commit()
        return conn
        
    except Exception as e:
        print(f"ERROR: Database initialization failed: {e}")
        return None

def block_ip(ip_address, duration=3600, reason='Manual block', block_type='manual'):
    """Block an IP address"""
    try:
        conn = init_database()
        if not conn:
            return False
        
        current_time = int(time.time())
        expires_at = current_time + int(duration) if int(duration) > 0 else None
        
        # Insert or update blocked IP
        conn.execute('''
            INSERT OR REPLACE INTO blocked_ips 
            (ip_address, block_type, blocked_since, expires_at, reason, violations, last_violation)
            VALUES (?, ?, ?, ?, ?, 1, ?)
        ''', (ip_address, block_type, current_time, expires_at, reason, current_time))
        
        conn.commit()
        conn.close()
        
        print(f"OK: {ip_address} blocked successfully")
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
        
        # Check if IP is blocked
        cursor = conn.execute('SELECT COUNT(*) FROM blocked_ips WHERE ip_address = ?', (ip_address,))
        if cursor.fetchone()[0] == 0:
            print(f"ERROR: IP {ip_address} is not blocked")
            conn.close()
            return False
        
        # Remove from blocked IPs
        conn.execute('DELETE FROM blocked_ips WHERE ip_address = ?', (ip_address,))
        
        conn.commit()
        conn.close()
        
        print(f"OK: {ip_address} unblocked successfully")
        return True
        
    except Exception as e:
        print(f"ERROR: Failed to unblock IP: {e}")
        return False

def list_blocked_ips(page=1, limit=50):
    """List blocked IP addresses with pagination"""
    try:
        conn = init_database()
        if not conn:
            return False
        
        offset = (int(page) - 1) * int(limit)
        
        # Get total count
        cursor = conn.execute('SELECT COUNT(*) FROM blocked_ips')
        total = cursor.fetchone()[0]
        
        # Get blocked IPs with pagination
        cursor = conn.execute('''
            SELECT ip_address, block_type, blocked_since, expires_at, reason, violations, last_violation
            FROM blocked_ips 
            ORDER BY blocked_since DESC
            LIMIT ? OFFSET ?
        ''', (int(limit), offset))
        
        blocked_ips = []
        current_time = int(time.time())
        
        for row in cursor.fetchall():
            ip_address, block_type, blocked_since, expires_at, reason, violations, last_violation = row
            
            # Check if expired
            expired = expires_at is not None and expires_at < current_time
            
            blocked_ips.append({
                'ip_address': ip_address,
                'block_type': block_type,
                'blocked_since': blocked_since,
                'blocked_since_iso': datetime.fromtimestamp(blocked_since).isoformat(),
                'expires_at': expires_at,
                'expires_at_iso': datetime.fromtimestamp(expires_at).isoformat() if expires_at else None,
                'reason': reason,
                'violations': violations,
                'last_violation': last_violation,
                'expired': expired
            })
        
        result = {
            'blocked_ips': blocked_ips,
            'total': total,
            'page': int(page),
            'limit': int(limit),
            'pages': (total + int(limit) - 1) // int(limit)
        }
        
        print(json.dumps(result, indent=2))
        conn.close()
        return True
        
    except Exception as e:
        print(f"ERROR: Failed to list blocked IPs: {e}")
        return False

def bulk_block_ips(ip_list, duration=3600, reason='Bulk block', block_type='manual'):
    """Block multiple IP addresses"""
    try:
        if isinstance(ip_list, str):
            ips = [ip.strip() for ip in ip_list.split('\n') if ip.strip()]
        else:
            ips = ip_list
        
        blocked_count = 0
        failed_count = 0
        
        for ip in ips:
            if block_ip(ip, duration, reason, block_type):
                blocked_count += 1
            else:
                failed_count += 1
        
        print(f"OK: Bulk block completed - {blocked_count} blocked, {failed_count} failed")
        return True
        
    except Exception as e:
        print(f"ERROR: Failed to bulk block IPs: {e}")
        return False

def clear_expired():
    """Clear expired blocked IPs"""
    try:
        conn = init_database()
        if not conn:
            return False
        
        current_time = int(time.time())
        
        # Get count before deletion
        cursor = conn.execute('''
            SELECT COUNT(*) FROM blocked_ips 
            WHERE expires_at IS NOT NULL AND expires_at < ?
        ''', (current_time,))
        
        expired_count = cursor.fetchone()[0]
        
        if expired_count > 0:
            # Delete expired blocks
            conn.execute('''
                DELETE FROM blocked_ips 
                WHERE expires_at IS NOT NULL AND expires_at < ?
            ''', (current_time,))
            
            conn.commit()
            print(f"OK: Removed {expired_count} expired blocks")
        else:
            print("OK: No expired blocks found")
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"ERROR: Failed to clear expired blocks: {e}")
        return False

def export_blocked_ips(format_type='json'):
    """Export blocked IPs in different formats"""
    try:
        conn = init_database()
        if not conn:
            return False
        
        cursor = conn.execute('''
            SELECT ip_address, block_type, blocked_since, expires_at, reason, violations
            FROM blocked_ips 
            ORDER BY blocked_since DESC
        ''')
        
        rows = cursor.fetchall()
        
        if format_type == 'json':
            blocked_ips = []
            for row in rows:
                ip_address, block_type, blocked_since, expires_at, reason, violations = row
                blocked_ips.append({
                    'ip_address': ip_address,
                    'block_type': block_type,
                    'blocked_since': datetime.fromtimestamp(blocked_since).isoformat(),
                    'expires_at': datetime.fromtimestamp(expires_at).isoformat() if expires_at else None,
                    'reason': reason,
                    'violations': violations
                })
            
            print(json.dumps({'blocked_ips': blocked_ips}, indent=2))
            
        elif format_type == 'csv':
            print("IP Address,Block Type,Blocked Since,Expires At,Reason,Violations")
            for row in rows:
                ip_address, block_type, blocked_since, expires_at, reason, violations = row
                blocked_since_str = datetime.fromtimestamp(blocked_since).strftime('%Y-%m-%d %H:%M:%S')
                expires_at_str = datetime.fromtimestamp(expires_at).strftime('%Y-%m-%d %H:%M:%S') if expires_at else 'Never'
                print(f'"{ip_address}","{block_type}","{blocked_since_str}","{expires_at_str}","{reason}",{violations}')
                
        elif format_type == 'txt':
            print("WebGuard Blocked IPs Report")
            print("=" * 50)
            print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"Total blocked IPs: {len(rows)}")
            print()
            
            for row in rows:
                ip_address, block_type, blocked_since, expires_at, reason, violations = row
                blocked_since_str = datetime.fromtimestamp(blocked_since).strftime('%Y-%m-%d %H:%M:%S')
                expires_at_str = datetime.fromtimestamp(expires_at).strftime('%Y-%m-%d %H:%M:%S') if expires_at else 'Never'
                
                print(f"IP: {ip_address}")
                print(f"  Type: {block_type}")
                print(f"  Blocked: {blocked_since_str}")
                print(f"  Expires: {expires_at_str}")
                print(f"  Reason: {reason}")
                print(f"  Violations: {violations}")
                print()
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"ERROR: Failed to export blocked IPs: {e}")
        return False

def get_ip_history(ip_address):
    """Get history for a specific IP address"""
    try:
        conn = init_database()
        if not conn:
            return False
        
        cursor = conn.execute('''
            SELECT ip_address, block_type, blocked_since, expires_at, reason, violations, last_violation
            FROM blocked_ips 
            WHERE ip_address = ?
        ''', (ip_address,))
        
        row = cursor.fetchone()
        
        if row:
            ip_address, block_type, blocked_since, expires_at, reason, violations, last_violation = row
            
            history = {
                'ip_address': ip_address,
                'block_type': block_type,
                'blocked_since': datetime.fromtimestamp(blocked_since).isoformat(),
                'expires_at': datetime.fromtimestamp(expires_at).isoformat() if expires_at else None,
                'reason': reason,
                'violations': violations,
                'last_violation': datetime.fromtimestamp(last_violation).isoformat(),
                'currently_blocked': True
            }
        else:
            history = {
                'ip_address': ip_address,
                'currently_blocked': False,
                'message': 'IP not found in blocked list'
            }
        
        print(json.dumps(history, indent=2))
        conn.close()
        return True
        
    except Exception as e:
        print(f"ERROR: Failed to get IP history: {e}")
        return False

def main():
    if len(sys.argv) < 2:
        print("Usage: manage_blocking.py <command> [args...]")
        print("Commands:")
        print("  block <ip> [duration] [reason] [block_type]")
        print("  unblock <ip> [reason]")
        print("  list [page] [limit]")
        print("  bulk_block <ip_list> [duration] [reason] [block_type]")
        print("  clear_expired")
        print("  export [format]")
        print("  history <ip>")
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == 'block':
        if len(sys.argv) < 3:
            print("ERROR: IP address required")
            sys.exit(1)
        
        ip_address = sys.argv[2]
        duration = sys.argv[3] if len(sys.argv) > 3 else '3600'
        reason = sys.argv[4] if len(sys.argv) > 4 else 'Manual block'
        block_type = sys.argv[5] if len(sys.argv) > 5 else 'manual'
        
        if not block_ip(ip_address, duration, reason, block_type):
            sys.exit(1)
        
    elif command == 'unblock':
        if len(sys.argv) < 3:
            print("ERROR: IP address required")
            sys.exit(1)
        
        ip_address = sys.argv[2]
        reason = sys.argv[3] if len(sys.argv) > 3 else 'Manual unblock'
        
        if not unblock_ip(ip_address, reason):
            sys.exit(1)
        
    elif command == 'list':
        page = sys.argv[2] if len(sys.argv) > 2 else '1'
        limit = sys.argv[3] if len(sys.argv) > 3 else '50'
        
        if not list_blocked_ips(page, limit):
            sys.exit(1)
        
    elif command == 'bulk_block':
        if len(sys.argv) < 3:
            print("ERROR: IP list required")
            sys.exit(1)
        
        ip_list = sys.argv[2]
        duration = sys.argv[3] if len(sys.argv) > 3 else '3600'
        reason = sys.argv[4] if len(sys.argv) > 4 else 'Bulk block'
        block_type = sys.argv[5] if len(sys.argv) > 5 else 'manual'
        
        if not bulk_block_ips(ip_list, duration, reason, block_type):
            sys.exit(1)
        
    elif command == 'clear_expired':
        if not clear_expired():
            sys.exit(1)
        
    elif command == 'export':
        format_type = sys.argv[2] if len(sys.argv) > 2 else 'json'
        
        if not export_blocked_ips(format_type):
            sys.exit(1)
        
    elif command == 'history':
        if len(sys.argv) < 3:
            print("ERROR: IP address required")
            sys.exit(1)
        
        ip_address = sys.argv[2]
        
        if not get_ip_history(ip_address):
            sys.exit(1)
        
    else:
        print(f"ERROR: Unknown command: {command}")
        sys.exit(1)

if __name__ == '__main__':
    main()