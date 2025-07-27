#!/usr/local/bin/python3.11

"""
WebGuard Geographic Blocking Management Script
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
            CREATE TABLE IF NOT EXISTS blocked_countries (
                country TEXT PRIMARY KEY,
                blocked_since INTEGER,
                expires_at INTEGER,
                reason TEXT,
                threat_count INTEGER DEFAULT 0
            )
        ''')
        
        conn.commit()
        return conn
        
    except Exception as e:
        print(f"ERROR: Database initialization failed: {e}")
        return None

def block_country(country, duration=3600, reason='Geographic blocking'):
    """Block a country"""
    try:
        conn = init_database()
        if not conn:
            return False
        
        current_time = int(time.time())
        expires_at = current_time + int(duration) if int(duration) > 0 else None
        
        # Insert or update blocked country
        conn.execute('''
            INSERT OR REPLACE INTO blocked_countries 
            (country, blocked_since, expires_at, reason)
            VALUES (?, ?, ?, ?)
        ''', (country, current_time, expires_at, reason))
        
        conn.commit()
        conn.close()
        
        print(json.dumps({
            'status': 'ok',
            'message': f'{country} blocked successfully',
            'country': country,
            'expires_at': expires_at
        }))
        return True
        
    except Exception as e:
        print(json.dumps({
            'status': 'error',
            'message': f'Failed to block country: {e}'
        }))
        return False

def unblock_country(country, reason='Manual unblock'):
    """Unblock a country"""
    try:
        conn = init_database()
        if not conn:
            return False
        
        # Check if country is blocked
        cursor = conn.execute('SELECT COUNT(*) FROM blocked_countries WHERE country = ?', (country,))
        if cursor.fetchone()[0] == 0:
            print(json.dumps({
                'status': 'error',
                'message': f'Country {country} is not blocked'
            }))
            conn.close()
            return False
        
        # Remove from blocked countries
        conn.execute('DELETE FROM blocked_countries WHERE country = ?', (country,))
        
        conn.commit()
        conn.close()
        
        print(json.dumps({
            'status': 'ok',
            'message': f'{country} unblocked successfully'
        }))
        return True
        
    except Exception as e:
        print(json.dumps({
            'status': 'error',
            'message': f'Failed to unblock country: {e}'
        }))
        return False

def list_blocked_countries():
    """List blocked countries"""
    try:
        conn = init_database()
        if not conn:
            return False
        
        # Get blocked countries
        cursor = conn.execute('''
            SELECT country, blocked_since, expires_at, reason, threat_count
            FROM blocked_countries 
            ORDER BY blocked_since DESC
        ''')
        
        blocked_countries = []
        current_time = int(time.time())
        
        for row in cursor.fetchall():
            country, blocked_since, expires_at, reason, threat_count = row
            
            # Check if expired
            expired = expires_at is not None and expires_at < current_time
            
            blocked_countries.append({
                'country': country,
                'blocked_since': blocked_since,
                'blocked_since_iso': datetime.fromtimestamp(blocked_since).isoformat(),
                'expires_at': expires_at,
                'expires_at_iso': datetime.fromtimestamp(expires_at).isoformat() if expires_at else None,
                'reason': reason,
                'threat_count': threat_count,
                'expired': expired
            })
        
        result = {
            'status': 'ok',
            'blocked_countries': blocked_countries,
            'count': len(blocked_countries)
        }
        
        print(json.dumps(result, indent=2))
        conn.close()
        return True
        
    except Exception as e:
        print(json.dumps({
            'status': 'error',
            'message': f'Failed to list blocked countries: {e}',
            'blocked_countries': []
        }))
        return False

def main():
    if len(sys.argv) < 2:
        print("Usage: manage_geo_blocking.py <command> [args...]")
        print("Commands:")
        print("  block <country> [duration] [reason]")
        print("  unblock <country> [reason]")
        print("  list")
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == 'block':
        if len(sys.argv) < 3:
            print("ERROR: Country name required")
            sys.exit(1)
        
        country = sys.argv[2]
        duration = sys.argv[3] if len(sys.argv) > 3 else '3600'
        reason = sys.argv[4] if len(sys.argv) > 4 else 'Geographic blocking'
        
        if not block_country(country, duration, reason):
            sys.exit(1)
        
    elif command == 'unblock':
        if len(sys.argv) < 3:
            print("ERROR: Country name required")
            sys.exit(1)
        
        country = sys.argv[2]
        reason = sys.argv[3] if len(sys.argv) > 3 else 'Manual unblock'
        
        if not unblock_country(country, reason):
            sys.exit(1)
        
    elif command == 'list':
        if not list_blocked_countries():
            sys.exit(1)
        
    else:
        print(f"ERROR: Unknown command: {command}")
        sys.exit(1)

if __name__ == '__main__':
    main()