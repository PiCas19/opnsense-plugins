#!/usr/local/bin/python3

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
from ipaddress import ip_address, ip_network
from datetime import datetime

DB_FILE = '/var/db/webguard/webguard.db'

def init_database():
    """Initialize database connection"""
    if not os.path.exists(DB_FILE):
        print("ERROR: Database not found")
        return None
    
    return sqlite3.connect(DB_FILE)

def add_to_whitelist(ip_address_str, description='', permanent=True, expiry=None):
    """Add IP address to whitelist"""
    try:
        # Validate IP address
        ip_address(ip_address_str)
        
        conn = init_database()
        if not conn:
            return False
        
        current_time = int(time.time())
        expires_at = None
        
        if not permanent and expiry:
            try:
                expires_at = int(datetime.fromisoformat(expiry).timestamp())
            except:
                print("ERROR: Invalid expiry date format")
                return False
        
        conn.execute('''
            INSERT OR REPLACE INTO whitelist 
            (ip_address, description, added_at, expires_at, permanent)
            VALUES (?, ?, ?, ?, ?)
        ''', (ip_address_str, description, current_time, expires_at, 1 if permanent else 0))
        
        conn.commit()
        conn.close()
        
        print(f"OK: {ip_address_str} added to whitelist")
        return True
        
    except Exception as e:
        print(f"ERROR: Failed to add to whitelist: {e}")
        return False

def remove_from_whitelist(ip_address_str, reason=''):
    """Remove IP address from whitelist"""
    try:
        conn = init_database()
        if not conn:
            return False
        
        cursor = conn.execute('SELECT COUNT(*) FROM whitelist WHERE ip_address = ?', (ip_address_str,))
        if cursor.fetchone()[0] == 0:
            print(f"ERROR: {ip_address_str} not found in whitelist")
            return False
        
        conn.execute('DELETE FROM whitelist WHERE ip_address = ?', (ip_address_str,))
        conn.commit()
        conn.close()
        
        print(f"OK: {ip_address_str} removed from whitelist")
        return True
        
    except Exception as e:
        print(f"ERROR: Failed to remove from whitelist: {e}")
        return False

def list_whitelist(page=1, limit=50):
    """List whitelist entries with pagination"""
    try:
        conn = init_database()
        if not conn:
            return {'error': 'Database not found'}
        
        offset = (page - 1) * limit
        current_time = int(time.time())
        
        # Get total count
        cursor = conn.execute('SELECT COUNT(*) FROM whitelist')
        total = cursor.fetchone()[0]
        
        # Get entries
        cursor = conn.execute('''
            SELECT ip_address, description, added_at, expires_at, permanent
            FROM whitelist
            ORDER BY added_at DESC
            LIMIT ? OFFSET ?
        ''', (limit, offset))
        
        entries = []
        for row in cursor.fetchall():
            entry = {
                'ip_address': row[0],
                'description': row[1] or '',
                'added_at': row[2],
                'expires_at': row[3],
                'permanent': bool(row[4]),
                'expired': row[3] and row[3] <= current_time if row[3] else False
            }
            entries.append(entry)
        
        result = {
            'whitelist': entries,
            'total': total,
            'page': page,
            'limit': limit,
            'total_pages': (total + limit - 1) // limit
        }
        
        conn.close()
        return result
        
    except Exception as e:
        return {'error': f'Failed to list whitelist: {e}'}

def check_whitelist(ip_address_str):
    """Check if IP address is whitelisted"""
    try:
        conn = init_database()
        if not conn:
            return False
        
        current_time = int(time.time())
        
        # Check exact match
        cursor = conn.execute('''
            SELECT COUNT(*) FROM whitelist 
            WHERE ip_address = ? AND (expires_at IS NULL OR expires_at > ?)
        ''', (ip_address_str, current_time))
        
        if cursor.fetchone()[0] > 0:
            conn.close()
            return True
        
        # Check network ranges (simplified - in practice would need more sophisticated matching)
        cursor = conn.execute('''
            SELECT ip_address FROM whitelist 
            WHERE expires_at IS NULL OR expires_at > ?
        ''', (current_time,))
        
        for row in cursor.fetchall():
            whitelist_entry = row[0]
            try:
                # Check if it's a network range
                if '/' in whitelist_entry:
                    if ip_address(ip_address_str) in ip_network(whitelist_entry, strict=False):
                        conn.close()
                        return True
            except:
                continue
        
        conn.close()
        return False
        
    except Exception as e:
        print(f"ERROR: Failed to check whitelist: {e}")
        return False

def cleanup_expired():
    """Remove expired whitelist entries"""
    try:
        conn = init_database()
        if not conn:
            return False
        
        current_time = int(time.time())
        
        # Get count of expired entries
        cursor = conn.execute('''
            SELECT COUNT(*) FROM whitelist 
            WHERE expires_at IS NOT NULL AND expires_at <= ?
        ''', (current_time,))
        
        expired_count = cursor.fetchone()[0]
        
        if expired_count > 0:
            # Remove expired entries
            conn.execute('''
                DELETE FROM whitelist 
                WHERE expires_at IS NOT NULL AND expires_at <= ?
            ''', (current_time,))
            
            conn.commit()
            print(f"OK: Removed {expired_count} expired whitelist entries")
        else:
            print("OK: No expired entries found")
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"ERROR: Failed to cleanup expired entries: {e}")
        return False

def bulk_add(ip_list, description='Bulk import', permanent=True):
    """Add multiple IPs to whitelist"""
    try:
        conn = init_database()
        if not conn:
            return False
        
        ips = [ip.strip() for ip in ip_list.split('\n') if ip.strip()]
        added_count = 0
        current_time = int(time.time())
        
        for ip_str in ips:
            try:
                # Validate IP
                ip_address(ip_str)
                
                conn.execute('''
                    INSERT OR REPLACE INTO whitelist 
                    (ip_address, description, added_at, expires_at, permanent)
                    VALUES (?, ?, ?, ?, ?)
                ''', (ip_str, description, current_time, None, 1 if permanent else 0))
                
                added_count += 1
                
            except Exception as e:
                print(f"WARNING: Skipped invalid IP {ip_str}: {e}")
                continue
        
        conn.commit()
        conn.close()
        
        print(f"OK: Added {added_count} IPs to whitelist")
        return True
        
    except Exception as e:
        print(f"ERROR: Failed to bulk add to whitelist: {e}")
        return False

def export_whitelist(format='json'):
    """Export whitelist in specified format"""
    try:
        conn = init_database()
        if not conn:
            return None
        
        cursor = conn.execute('''
            SELECT ip_address, description, added_at, expires_at, permanent
            FROM whitelist
            ORDER BY added_at DESC
        ''')
        
        entries = []
        for row in cursor.fetchall():
            entry = {
                'ip_address': row[0],
                'description': row[1] or '',
                'added_at': row[2],
                'expires_at': row[3],
                'permanent': bool(row[4])
            }
            entries.append(entry)
        
        conn.close()
        
        if format.lower() == 'json':
            return json.dumps(entries, indent=2)
        elif format.lower() == 'csv':
            import csv
            import io
            
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(['IP Address', 'Description', 'Added At', 'Expires At', 'Permanent'])
            
            for entry in entries:
                writer.writerow([
                    entry['ip_address'],
                    entry['description'],
                    datetime.fromtimestamp(entry['added_at']).isoformat() if entry['added_at'] else '',
                    datetime.fromtimestamp(entry['expires_at']).isoformat() if entry['expires_at'] else '',
                    'Yes' if entry['permanent'] else 'No'
                ])
            
            return output.getvalue()
        else:
            return json.dumps(entries, indent=2)
        
    except Exception as e:
        print(f"ERROR: Failed to export whitelist: {e}")
        return None

def main():
    if len(sys.argv) < 2:
        print("Usage: manage_whitelist.py <command> [args...]")
        print("Commands:")
        print("  add <ip> [description] [permanent] [expiry]")
        print("  remove <ip> [reason]")
        print("  list [page] [limit]")
        print("  check <ip>")
        print("  cleanup")
        print("  bulk_add <ip_list> [description] [permanent]")
        print("  export [format]")
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == 'add':
        if len(sys.argv) < 3:
            print("ERROR: IP address required")
            sys.exit(1)
        
        ip = sys.argv[2]
        description = sys.argv[3] if len(sys.argv) > 3 else ''
        permanent = sys.argv[4].lower() in ['true', '1', 'yes'] if len(sys.argv) > 4 else True
        expiry = sys.argv[5] if len(sys.argv) > 5 else None
        
        add_to_whitelist(ip, description, permanent, expiry)
        
    elif command == 'remove':
        if len(sys.argv) < 3:
            print("ERROR: IP address required")
            sys.exit(1)
        
        ip = sys.argv[2]
        reason = sys.argv[3] if len(sys.argv) > 3 else ''
        
        remove_from_whitelist(ip, reason)
        
    elif command == 'list':
        page = int(sys.argv[2]) if len(sys.argv) > 2 else 1
        limit = int(sys.argv[3]) if len(sys.argv) > 3 else 50
        
        result = list_whitelist(page, limit)
        print(json.dumps(result))
        
    elif command == 'check':
        if len(sys.argv) < 3:
            print("ERROR: IP address required")
            sys.exit(1)
        
        ip = sys.argv[2]
        is_whitelisted = check_whitelist(ip)
        print(json.dumps({'ip': ip, 'whitelisted': is_whitelisted}))
        
    elif command == 'cleanup':
        cleanup_expired()
        
    elif command == 'bulk_add':
        if len(sys.argv) < 3:
            print("ERROR: IP list required")
            sys.exit(1)
        
        ip_list = sys.argv[2]
        description = sys.argv[3] if len(sys.argv) > 3 else 'Bulk import'
        permanent = sys.argv[4].lower() in ['true', '1', 'yes'] if len(sys.argv) > 4 else True
        
        bulk_add(ip_list, description, permanent)
        
    elif command == 'export':
        format = sys.argv[2] if len(sys.argv) > 2 else 'json'
        
        result = export_whitelist(format)
        if result:
            filename = f"whitelist_export_{int(time.time())}.{format}"
            print(json.dumps({
                'data': result,
                'filename': filename,
                'format': format
            }))
        
    else:
        print(f"ERROR: Unknown command: {command}")
        sys.exit(1)

if __name__ == '__main__':
    main()