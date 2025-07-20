#!/usr/local/bin/python3.11

"""
WebGuard WAF Statistics Script
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

def get_waf_stats(period='24h'):
    """Get WAF-specific statistics"""
    if not os.path.exists(DB_FILE):
        return {'error': 'Database not found'}
    
    try:
        conn = sqlite3.connect(DB_FILE)
        
        # Calculate time range
        if period == '1h':
            start_time = int(time.time() - 3600)
        elif period == '24h':
            start_time = int(time.time() - 86400)
        elif period == '7d':
            start_time = int(time.time() - 604800)
        elif period == '30d':
            start_time = int(time.time() - 2592000)
        else:
            start_time = int(time.time() - 86400)  # Default to 24h
        
        stats = {}
        
        # SQL injection attempts
        cursor = conn.execute('''
            SELECT COUNT(*) FROM threats 
            WHERE type = 'sql_injection' AND timestamp >= ?
        ''', (start_time,))
        stats['sql_injection_attempts'] = cursor.fetchone()[0]
        
        # XSS attempts
        cursor = conn.execute('''
            SELECT COUNT(*) FROM threats 
            WHERE type = 'xss' AND timestamp >= ?
        ''', (start_time,))
        stats['xss_attempts'] = cursor.fetchone()[0]
        
        # CSRF attempts
        cursor = conn.execute('''
            SELECT COUNT(*) FROM threats 
            WHERE type = 'csrf' AND timestamp >= ?
        ''', (start_time,))
        stats['csrf_attempts'] = cursor.fetchone()[0]
        
        # LFI attempts
        cursor = conn.execute('''
            SELECT COUNT(*) FROM threats 
            WHERE type = 'lfi' AND timestamp >= ?
        ''', (start_time,))
        stats['lfi_attempts'] = cursor.fetchone()[0]
        
        # RFI attempts
        cursor = conn.execute('''
            SELECT COUNT(*) FROM threats 
            WHERE type = 'rfi' AND timestamp >= ?
        ''', (start_time,))
        stats['rfi_attempts'] = cursor.fetchone()[0]
        
        # Command injection attempts
        cursor = conn.execute('''
            SELECT COUNT(*) FROM threats 
            WHERE type = 'command_injection' AND timestamp >= ?
        ''', (start_time,))
        stats['command_injection_attempts'] = cursor.fetchone()[0]
        
        # Total blocked requests
        cursor = conn.execute('''
            SELECT COUNT(*) FROM threats 
            WHERE type IN ('sql_injection', 'xss', 'csrf', 'lfi', 'rfi', 'command_injection') 
            AND timestamp >= ?
        ''', (start_time,))
        stats['blocked_requests'] = cursor.fetchone()[0]
        
        # WAF rules triggered
        cursor = conn.execute('''
            SELECT rule_matched, COUNT(*) as count FROM threats 
            WHERE rule_matched IS NOT NULL AND rule_matched != '' 
            AND timestamp >= ?
            GROUP BY rule_matched 
            ORDER BY count DESC 
            LIMIT 10
        ''', (start_time,))
        stats['top_triggered_rules'] = [{'rule': row[0], 'count': row[1]} for row in cursor.fetchall()]
        
        # Attack severity distribution
        cursor = conn.execute('''
            SELECT severity, COUNT(*) FROM threats 
            WHERE type IN ('sql_injection', 'xss', 'csrf', 'lfi', 'rfi', 'command_injection') 
            AND timestamp >= ?
            GROUP BY severity
        ''', (start_time,))
        stats['attack_severity'] = dict(cursor.fetchall())
        
        # Hourly attack distribution
        hourly_stats = []
        for i in range(24):
            hour_start = start_time + (i * 3600)
            hour_end = hour_start + 3600
            
            cursor = conn.execute('''
                SELECT COUNT(*) FROM threats 
                WHERE type IN ('sql_injection', 'xss', 'csrf', 'lfi', 'rfi', 'command_injection')
                AND timestamp >= ? AND timestamp < ?
            ''', (hour_start, hour_end))
            
            count = cursor.fetchone()[0]
            hourly_stats.append({
                'timestamp': hour_start,
                'count': count,
                'hour': datetime.fromtimestamp(hour_start).strftime('%H:00')
            })
        
        stats['hourly_distribution'] = hourly_stats
        
        # Top attacking IPs for WAF
        cursor = conn.execute('''
            SELECT source_ip, COUNT(*) as count FROM threats 
            WHERE type IN ('sql_injection', 'xss', 'csrf', 'lfi', 'rfi', 'command_injection')
            AND timestamp >= ? 
            GROUP BY source_ip 
            ORDER BY count DESC 
            LIMIT 10
        ''', (start_time,))
        stats['top_attacking_ips'] = [{'ip': row[0], 'count': row[1]} for row in cursor.fetchall()]
        
        # Average threat score
        cursor = conn.execute('''
            SELECT AVG(score) FROM threats 
            WHERE type IN ('sql_injection', 'xss', 'csrf', 'lfi', 'rfi', 'command_injection')
            AND timestamp >= ? AND score > 0
        ''', (start_time,))
        result = cursor.fetchone()[0]
        stats['average_threat_score'] = round(result, 2) if result else 0
        
        conn.close()
        return stats
        
    except Exception as e:
        return {'error': f'Failed to get WAF stats: {e}'}

def main():
    period = sys.argv[1] if len(sys.argv) > 1 else '24h'
    stats = get_waf_stats(period)
    print(json.dumps(stats))

if __name__ == '__main__':
    main()