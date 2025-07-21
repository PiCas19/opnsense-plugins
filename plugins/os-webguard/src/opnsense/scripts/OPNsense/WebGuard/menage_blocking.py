# ==============================================================================
# manage_blocking.py - IP blocking management
# ==============================================================================

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
import subprocess
from datetime import datetime

DB_FILE = '/var/db/webguard/webguard.db'

def init_database():
    """Initialize database connection"""
    if not os.path.exists(DB_FILE):
        print("ERROR: Database not found")
        return None
    
    return sqlite3.connect(DB_FILE)

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
            
            # Update firewall table
            if blocked_ips:
                # Create temporary file with IPs
                temp_file = '/tmp/webguard_blocked_ips.txt'
                with open(temp_file, 'w') as f:
                    for ip in blocked_ips:
                        f.write(f"{ip}\n")
                
                # Load into pfctl table
                result = subprocess.run(['pfctl', '-t', 'webguard_blocked', '-T', 'replace', '-f', temp_file], 
                                      capture_output=True, text=True)
                
                os.remove(temp_file)
                
                if result.returncode == 0:
                    print(f"OK: Updated firewall table with {len(blocked_ips)} IPs")
                    return True
                else:
                    print(f"ERROR: Failed to update firewall table: {result.stderr}")
                    return False
            else:
                # Clear table
                subprocess.run(['pfctl', '-t', 'webguard_blocked', '-T', 'flush'], 
                             capture_output=True, text=True)
                print("OK: Cleared firewall table")
                return True
                
        return True
        
    except Exception as e:
        print(f"ERROR: Failed to update firewall: {e}")
        return False

def block_ip(ip_address, duration=3600, reason='Manual block', block_type='manual'):
    """Block an IP address"""
    try:
        from ipaddress import ip_address as validate_ip
        validate_ip(ip_address)
        
        conn = init_database()
        if not conn:
            return False
        
        current_time = int(time.time())
        expires_at = current_time + duration if duration > 0 else None
        
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
            print(f"ERROR: {ip_address} not found in blocked list")
            return False
        
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
            return {'error': 'Database not found'}
        
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
                'block_type': row[1],
                'blocked_since': row[2],
                'blocked_since_iso': datetime.fromtimestamp(row[2]).isoformat(),
                'expires_at': row[3],
                'expires_at_iso': datetime.fromtimestamp(row[3]).isoformat() if row[3] else None,
                'reason': row[4],
                'violations': row[5],
                'last_violation': row[6],
                'expired': row[3] and row[3] <= current_time if row[3] else False,
                'permanent': row[3] is None
            }
            blocked_ips.append(entry)
        
        result = {
            'blocked_ips': blocked_ips,
            'total': total,
            'page': page,
            'limit': limit,
            'total_pages': (total + limit - 1) // limit
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

def bulk_unblock_ips(ip_list, reason='Bulk unblock'):
    """Unblock multiple IPs"""
    try:
        ips = [ip.strip() for ip in ip_list.split('\n') if ip.strip()]
        unblocked_count = 0
        
        for ip_str in ips:
            if unblock_ip(ip_str, reason):
                unblocked_count += 1
        
        print(f"OK: Unblocked {unblocked_count}/{len(ips)} IPs")
        return True
        
    except Exception as e:
        print(f"ERROR: Failed to bulk unblock IPs: {e}")
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

def get_ip_history(ip_address):
    """Get blocking history for an IP"""
    try:
        conn = init_database()
        if not conn:
            return {'error': 'Database not found'}
        
        # Get blocking history
        cursor = conn.execute('''
            SELECT block_type, blocked_since, expires_at, reason, violations
            FROM blocked_ips 
            WHERE ip_address = ?
            ORDER BY blocked_since DESC
        ''', (ip_address,))
        
        blocks = []
        for row in cursor.fetchall():
            block = {
                'block_type': row[0],
                'blocked_since': row[1],
                'blocked_since_iso': datetime.fromtimestamp(row[1]).isoformat(),
                'expires_at': row[2],
                'expires_at_iso': datetime.fromtimestamp(row[2]).isoformat() if row[2] else None,
                'reason': row[3],
                'violations': row[4]
            }
            blocks.append(block)
        
        # Get threat history
        cursor = conn.execute('''
            SELECT timestamp, type, severity, description
            FROM threats 
            WHERE source_ip = ?
            ORDER BY timestamp DESC
            LIMIT 20
        ''', (ip_address,))
        
        threats = []
        for row in cursor.fetchall():
            threat = {
                'timestamp': row[0],
                'timestamp_iso': datetime.fromtimestamp(row[0]).isoformat(),
                'type': row[1],
                'severity': row[2],
                'description': row[3]
            }
            threats.append(threat)
        
        result = {
            'ip_address': ip_address,
            'blocking_history': blocks,
            'threat_history': threats,
            'total_blocks': len(blocks),
            'total_threats': len(threats)
        }
        
        conn.close()
        return result
        
    except Exception as e:
        return {'error': f'Failed to get IP history: {e}'}

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

def import_blocked_ips(ip_list, duration=3600, reason='Imported', block_type='imported'):
    """Import blocked IPs from list"""
    try:
        import_data = json.loads(ip_list) if ip_list.startswith('{') else ip_list.split('\n')
        
        if isinstance(import_data, dict) and 'blocked_ips' in import_data:
            # Import from exported JSON
            imported_count = 0
            for ip_data in import_data['blocked_ips']:
                ip_address = ip_data['ip_address']
                ip_reason = ip_data.get('reason', reason)
                ip_duration = duration
                
                if block_ip(ip_address, ip_duration, ip_reason, block_type):
                    imported_count += 1
        else:
            # Import from simple list
            imported_count = 0
            ips = [ip.strip() for ip in import_data if ip.strip()]
            
            for ip_address in ips:
                if block_ip(ip_address, duration, reason, block_type):
                    imported_count += 1
        
        print(f"OK: Imported {imported_count} blocked IPs")
        return True
        
    except Exception as e:
        print(f"ERROR: Failed to import blocked IPs: {e}")
        return False

def main():
    if len(sys.argv) < 2:
        print("Usage: manage_blocking.py <command> [args...]")
        print("Commands:")
        print("  block <ip> [duration] [reason] [block_type]")
        print("  unblock <ip> [reason]")
        print("  list [page] [limit]")
        print("  bulk_block <ip_list> [duration] [reason] [block_type]")
        print("  bulk_unblock <ip_list> [reason]")
        print("  clear_expired")
        print("  history <ip>")
        print("  export <format> [include_expired]")
        print("  import <ip_list> [duration] [reason] [block_type]")
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == 'block':
        if len(sys.argv) < 3:
            print("ERROR: IP address required")
            sys.exit(1)
        
        ip = sys.argv[2]
        duration = int(sys.argv[3]) if len(sys.argv) > 3 else 3600
        reason = sys.argv[4] if len(sys.argv) > 4 else 'Manual block'
        block_type = sys.argv[5] if len(sys.argv) > 5 else 'manual'
        
        block_ip(ip, duration, reason, block_type)
        
    elif command == 'unblock':
        if len(sys.argv) < 3:
            print("ERROR: IP address required")
            sys.exit(1)
        
        ip = sys.argv[2]
        reason = sys.argv[3] if len(sys.argv) > 3 else 'Manual unblock'
        
        unblock_ip(ip, reason)
        
    elif command == 'list':
        page = int(sys.argv[2]) if len(sys.argv) > 2 else 1
        limit = int(sys.argv[3]) if len(sys.argv) > 3 else 50
        
        result = list_blocked_ips(page, limit)
        print(json.dumps(result))
        
    elif command == 'bulk_block':
        if len(sys.argv) < 3:
            print("ERROR: IP list required")
            sys.exit(1)
        
        ip_list = sys.argv[2]
        duration = int(sys.argv[3]) if len(sys.argv) > 3 else 3600
        reason = sys.argv[4] if len(sys.argv) > 4 else 'Bulk block'
        block_type = sys.argv[5] if len(sys.argv) > 5 else 'manual'
        
        bulk_block_ips(ip_list, duration, reason, block_type)
        
    elif command == 'bulk_unblock':
        if len(sys.argv) < 3:
            print("ERROR: IP list required")
            sys.exit(1)
        
        ip_list = sys.argv[2]
        reason = sys.argv[3] if len(sys.argv) > 3 else 'Bulk unblock'
        
        bulk_unblock_ips(ip_list, reason)
        
    elif command == 'clear_expired':
        clear_expired_blocks()
        
    elif command == 'history':
        if len(sys.argv) < 3:
            print("ERROR: IP address required")
            sys.exit(1)
        
        ip = sys.argv[2]
        result = get_ip_history(ip)
        print(json.dumps(result))
        
    elif command == 'export':
        if len(sys.argv) < 3:
            print("ERROR: Format required")
            sys.exit(1)
        
        format = sys.argv[2]
        include_expired = sys.argv[3].lower() in ['true', '1', 'yes'] if len(sys.argv) > 3 else False
        
        result = export_blocked_ips(format, include_expired)
        print(result)
        
    elif command == 'import':
        if len(sys.argv) < 3:
            print("ERROR: IP list required")
            sys.exit(1)
        
        ip_list = sys.argv[2]
        duration = int(sys.argv[3]) if len(sys.argv) > 3 else 3600
        reason = sys.argv[4] if len(sys.argv) > 4 else 'Imported'
        block_type = sys.argv[5] if len(sys.argv) > 5 else 'imported'
        
        import_blocked_ips(ip_list, duration, reason, block_type)
        
    else:
        print(f"ERROR: Unknown command: {command}")
        sys.exit(1)

if __name__ == '__main__':
    main()

