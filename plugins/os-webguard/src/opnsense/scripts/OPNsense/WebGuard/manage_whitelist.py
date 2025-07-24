#!/usr/local/bin/python3.11

"""
WebGuard Whitelist Management Script
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

def add_to_whitelist(ip_address, description='Manual whitelist', permanent='1', expiry=''):
    """Add IP to whitelist"""
    try:
        conn = init_database()
        if not conn:
            return False
        
        current_time = int(time.time())
        expires_at = None
        
        if permanent == '0' and expiry:
            # Calculate expiry time if not permanent
            try:
                expires_at = current_time + int(expiry)
            except ValueError:
                expires_at = None
        
        # Insert or update whitelist entry
        conn.execute('''
            INSERT OR REPLACE INTO whitelist 
            (ip_address, description, added_at, expires_at, permanent)
            VALUES (?, ?, ?, ?, ?)
        ''', (ip_address, description, current_time, expires_at, 1 if permanent == '1' else 0))
        
        conn.commit()
        conn.close()
        
        print(f"OK: {ip_address} added to whitelist")
        return True
        
    except Exception as e:
        print(f"ERROR: Failed to add IP to whitelist: {e}")
        return False

def remove_from_whitelist(ip_address, reason='Manual removal'):
    """Remove IP from whitelist"""
    try:
        conn = init_database()
        if not conn:
            return False
        
        # Check if IP is in whitelist
        cursor = conn.execute('SELECT COUNT(*) FROM whitelist WHERE ip_address = ?', (ip_address,))
        if cursor.fetchone()[0] == 0:
            print(f"ERROR: IP {ip_address} is not in whitelist")
            conn.close()
            return False
        
        # Remove from whitelist
        conn.execute('DELETE FROM whitelist WHERE ip_address = ?', (ip_address,))
        
        conn.commit()
        conn.close()
        
        print(f"OK: {ip_address} removed from whitelist")
        return True
        
    except Exception as e:
        print(f"ERROR: Failed to remove IP from whitelist: {e}")
        return False

def list_whitelist(page=1, limit=100):
    """List whitelist entries with pagination"""
    try:
        conn = init_database()
        if not conn:
            return False
        
        offset = (int(page) - 1) * int(limit)
        
        # Get total count
        cursor = conn.execute('SELECT COUNT(*) FROM whitelist')
        total = cursor.fetchone()[0]
        
        # Get whitelist entries with pagination
        cursor = conn.execute('''
            SELECT ip_address, description, added_at, expires_at, permanent
            FROM whitelist 
            ORDER BY added_at DESC
            LIMIT ? OFFSET ?
        ''', (int(limit), offset))
        
        whitelist = []
        current_time = int(time.time())
        
        for row in cursor.fetchall():
            ip_address, description, added_at, expires_at, permanent = row
            
            # Check if expired (for non-permanent entries)
            expired = not permanent and expires_at is not None and expires_at < current_time
            
            whitelist.append({
                'ip_address': ip_address,
                'description': description,
                'added_at': added_at,
                'added_at_iso': datetime.fromtimestamp(added_at).isoformat(),
                'expires_at': expires_at,
                'expires_at_iso': datetime.fromtimestamp(expires_at).isoformat() if expires_at else None,
                'permanent': bool(permanent),
                'expired': expired
            })
        
        result = {
            'whitelist': whitelist,
            'total': total,
            'page': int(page),
            'limit': int(limit),
            'pages': (total + int(limit) - 1) // int(limit)
        }
        
        print(json.dumps(result, indent=2))
        conn.close()
        return True
        
    except Exception as e:
        print(f"ERROR: Failed to list whitelist: {e}")
        return False

def check_whitelist(ip_address):
    """Check if IP is in whitelist"""
    try:
        conn = init_database()
        if not conn:
            return False
        
        current_time = int(time.time())
        
        cursor = conn.execute('''
            SELECT ip_address, description, expires_at, permanent
            FROM whitelist 
            WHERE ip_address = ?
        ''', (ip_address,))
        
        row = cursor.fetchone()
        
        if row:
            ip_address, description, expires_at, permanent = row
            
            # Check if expired (for non-permanent entries)
            if not permanent and expires_at is not None and expires_at < current_time:
                print("NO: IP is in whitelist but expired")
                result = False
            else:
                print("YES: IP is whitelisted")
                result = True
        else:
            print("NO: IP is not in whitelist")
            result = False
        
        conn.close()
        return result
        
    except Exception as e:
        print(f"ERROR: Failed to check whitelist: {e}")
        return False

def cleanup_expired():
    """Clean up expired whitelist entries"""
    try:
        conn = init_database()
        if not conn:
            return False
        
        current_time = int(time.time())
        
        # Get count before deletion
        cursor = conn.execute('''
            SELECT COUNT(*) FROM whitelist 
            WHERE permanent = 0 AND expires_at IS NOT NULL AND expires_at < ?
        ''', (current_time,))
        
        expired_count = cursor.fetchone()[0]
        
        if expired_count > 0:
            # Delete expired entries
            conn.execute('''
                DELETE FROM whitelist 
                WHERE permanent = 0 AND expires_at IS NOT NULL AND expires_at < ?
            ''', (current_time,))
            
            conn.commit()
            print(f"OK: Removed {expired_count} expired whitelist entries")
        else:
            print("OK: No expired whitelist entries found")
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"ERROR: Failed to cleanup expired entries: {e}")
        return False

def export_whitelist(format_type='json'):
    """Export whitelist in different formats"""
    try:
        conn = init_database()
        if not conn:
            return False
        
        cursor = conn.execute('''
            SELECT ip_address, description, added_at, expires_at, permanent
            FROM whitelist 
            ORDER BY added_at DESC
        ''')
        
        rows = cursor.fetchall()
        
        if format_type == 'json':
            whitelist = []
            for row in rows:
                ip_address, description, added_at, expires_at, permanent = row
                whitelist.append({
                    'ip_address': ip_address,
                    'description': description,
                    'added_at': datetime.fromtimestamp(added_at).isoformat(),
                    'expires_at': datetime.fromtimestamp(expires_at).isoformat() if expires_at else None,
                    'permanent': bool(permanent)
                })
            
            print(json.dumps({'whitelist': whitelist}, indent=2))
            
        elif format_type == 'csv':
            print("IP Address,Description,Added At,Expires At,Permanent")
            for row in rows:
                ip_address, description, added_at, expires_at, permanent = row
                added_at_str = datetime.fromtimestamp(added_at).strftime('%Y-%m-%d %H:%M:%S')
                expires_at_str = datetime.fromtimestamp(expires_at).strftime('%Y-%m-%d %H:%M:%S') if expires_at else 'Never'
                permanent_str = 'Yes' if permanent else 'No'
                print(f'"{ip_address}","{description}","{added_at_str}","{expires_at_str}","{permanent_str}"')
                
        elif format_type == 'txt':
            print("WebGuard Whitelist Report")
            print("=" * 50)
            print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"Total whitelist entries: {len(rows)}")
            print()
            
            for row in rows:
                ip_address, description, added_at, expires_at, permanent = row
                added_at_str = datetime.fromtimestamp(added_at).strftime('%Y-%m-%d %H:%M:%S')
                expires_at_str = datetime.fromtimestamp(expires_at).strftime('%Y-%m-%d %H:%M:%S') if expires_at else 'Never'
                permanent_str = 'Yes' if permanent else 'No'
                
                print(f"IP: {ip_address}")
                print(f"  Description: {description}")
                print(f"  Added: {added_at_str}")
                print(f"  Expires: {expires_at_str}")
                print(f"  Permanent: {permanent_str}")
                print()
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"ERROR: Failed to export whitelist: {e}")
        return False

def main():
    if len(sys.argv) < 2:
        print("Usage: manage_whitelist.py <command> [args...]")
        print("Commands:")
        print("  add <ip> [description] [permanent] [expiry]")
        print("  remove <ip> [reason]")
        print("  list [page] [limit]")
        print("  check <ip>")
        print("  cleanup")
        print("  export [format]")
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == 'add':
        if len(sys.argv) < 3:
            print("ERROR: IP address required")
            sys.exit(1)
        
        ip_address = sys.argv[2]
        description = sys.argv[3] if len(sys.argv) > 3 else 'Manual whitelist'
        permanent = sys.argv[4] if len(sys.argv) > 4 else '1'
        expiry = sys.argv[5] if len(sys.argv) > 5 else ''
        
        if not add_to_whitelist(ip_address, description, permanent, expiry):
            sys.exit(1)
        
    elif command == 'remove':
        if len(sys.argv) < 3:
            print("ERROR: IP address required")
            sys.exit(1)
        
        ip_address = sys.argv[2]
        reason = sys.argv[3] if len(sys.argv) > 3 else 'Manual removal'
        
        if not remove_from_whitelist(ip_address, reason):
            sys.exit(1)
        
    elif command == 'list':
        page = sys.argv[2] if len(sys.argv) > 2 else '1'
        limit = sys.argv[3] if len(sys.argv) > 3 else '100'
        
        if not list_whitelist(page, limit):
            sys.exit(1)
        
    elif command == 'check':
        if len(sys.argv) < 3:
            print("ERROR: IP address required")
            sys.exit(1)
        
        ip_address = sys.argv[2]
        
        if not check_whitelist(ip_address):
            sys.exit(1)
        
    elif command == 'cleanup':
        if not cleanup_expired():
            sys.exit(1)
        
    elif command == 'export':
        format_type = sys.argv[2] if len(sys.argv) > 2 else 'json'
        
        if not export_whitelist(format_type):
            sys.exit(1)
        
    else:
        print(f"ERROR: Unknown command: {command}")
        sys.exit(1)

if __name__ == '__main__':
    main()