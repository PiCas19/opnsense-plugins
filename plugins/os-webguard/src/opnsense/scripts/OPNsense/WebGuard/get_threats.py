#!/usr/local/bin/python3.11
# get_threats.py - Retrieve threat data from WebGuard database
"""
WebGuard Threat Data Retrieval Script
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

def get_threats(period='24h', limit=100, offset=0):
    """Get threats with pagination"""
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
            start_time = int(time.time() - 86400)
        
        # Get total count
        cursor = conn.execute('SELECT COUNT(*) FROM threats WHERE timestamp >= ?', (start_time,))
        total = cursor.fetchone()[0]
        
        # Get threats
        cursor = conn.execute('''
            SELECT id, timestamp, source_ip, target, method, type, severity, status, 
                   score, payload, request_headers, rule_matched, description, false_positive
            FROM threats 
            WHERE timestamp >= ? 
            ORDER BY timestamp DESC 
            LIMIT ? OFFSET ?
        ''', (start_time, limit, offset))
        
        threats = []
        for row in cursor.fetchall():
            threat = {
                'id': row[0],
                'timestamp': row[1],
                'timestamp_iso': datetime.fromtimestamp(row[1]).isoformat(),
                'source_ip': row[2],
                'target': row[3],
                'method': row[4],
                'type': row[5],
                'severity': row[6],
                'status': row[7],
                'score': row[8],
                'payload': row[9],
                'request_headers': row[10],
                'rule_matched': row[11],
                'description': row[12],
                'false_positive': bool(row[13])
            }
            threats.append(threat)
        
        result = {
            'threats': threats,
            'total': total,
            'limit': limit,
            'offset': offset,
            'period': period
        }
        
        conn.close()
        return result
        
    except Exception as e:
        return {'error': f'Failed to get threats: {e}'}

def get_threat_detail(threat_id):
    """Get detailed information about a specific threat"""
    if not os.path.exists(DB_FILE):
        return {'error': 'Database not found'}
    
    try:
        conn = sqlite3.connect(DB_FILE)
        
        cursor = conn.execute('''
            SELECT id, timestamp, source_ip, method, type, severity, description,
                   false_positive, payload
            FROM threats 
            WHERE id = ?
        ''', (threat_id,))
        
        row = cursor.fetchone()
        if not row:
            conn.close()
            return {'error': 'Threat not found'}
        
        threat = {
            'id': row[0],
            'timestamp': row[1],
            'timestamp_iso': datetime.fromtimestamp(row[1]).isoformat(),
            'source_ip': row[2],
            'method': row[3],
            'type': row[4],
            'severity': row[5],
            'description': row[6],
            'false_positive': bool(row[7]),
            'payload': row[8],
        }
        
        # Get related threats from same IP in last 24h
        cursor = conn.execute('''
            SELECT COUNT(*) FROM threats 
            WHERE source_ip = ? AND timestamp >= ?
        ''', (row[2], int(time.time() - 86400)))
        
        threat['related_count'] = cursor.fetchone()[0]
        
        conn.close()
        return threat
        
    except Exception as e:
        return {'error': f'Failed to get threat detail: {e}'}


def get_threat_feed(feed_type='recent', limit=50):
    """Get threat feed data"""
    if not os.path.exists(DB_FILE):
        return {'error': 'Database not found'}
    
    try:
        conn = sqlite3.connect(DB_FILE)
        
        if feed_type == 'recent':
            cursor = conn.execute('''
                SELECT id, timestamp, source_ip, type, severity, description
                FROM threats 
                ORDER BY timestamp DESC 
                LIMIT ?
            ''', (limit,))
        elif feed_type == 'critical':
            cursor = conn.execute('''
                SELECT id, timestamp, source_ip, type, severity, description
                FROM threats 
                WHERE severity = 'critical'
                ORDER BY timestamp DESC 
                LIMIT ?
            ''', (limit,))
        elif feed_type == 'high':
            cursor = conn.execute('''
                SELECT id, timestamp, source_ip, type, severity, description
                FROM threats 
                WHERE severity IN ('critical', 'high')
                ORDER BY timestamp DESC 
                LIMIT ?
            ''', (limit,))
        else:
            cursor = conn.execute('''
                SELECT id, timestamp, source_ip, type, severity, description
                FROM threats 
                ORDER BY timestamp DESC 
                LIMIT ?
            ''', (limit,))
        
        feed = []
        for row in cursor.fetchall():
            item = {
                'id': row[0],
                'timestamp': row[1],
                'timestamp_iso': datetime.fromtimestamp(row[1]).isoformat(),
                'source_ip': row[2],
                'type': row[3],
                'severity': row[4],
                'description': row[5]
            }
            feed.append(item)
        
        conn.close()
        return {'feed': feed, 'type': feed_type, 'count': len(feed)}
        
    except Exception as e:
        return {'error': f'Failed to get threat feed: {e}'}

def get_attack_patterns(period='24h', pattern_type='all'):
    """Get attack patterns analysis"""
    if not os.path.exists(DB_FILE):
        return {'error': 'Database not found'}
    
    try:
        conn = sqlite3.connect(DB_FILE)
        
        # Calculate time range
        if period == '24h':
            start_time = int(time.time() - 86400)
        elif period == '7d':
            start_time = int(time.time() - 604800)
        else:
            start_time = int(time.time() - 86400)
        
        patterns = {}
        
        # Pattern by type
        cursor = conn.execute('''
            SELECT type, COUNT(*) as count, AVG(score) as avg_score
            FROM threats 
            WHERE timestamp >= ?
            GROUP BY type
            ORDER BY count DESC
        ''', (start_time,))
        
        patterns['by_type'] = []
        for row in cursor.fetchall():
            patterns['by_type'].append({
                'type': row[0],
                'count': row[1],
                'avg_score': round(row[2], 2) if row[2] else 0
            })
        
        # Pattern by hour
        cursor = conn.execute('''
            SELECT strftime('%H', datetime(timestamp, 'unixepoch')) as hour, 
                   COUNT(*) as count
            FROM threats 
            WHERE timestamp >= ?
            GROUP BY hour
            ORDER BY hour
        ''', (start_time,))
        
        patterns['by_hour'] = []
        for row in cursor.fetchall():
            patterns['by_hour'].append({
                'hour': int(row[0]),
                'count': row[1]
            })
        
        # Pattern by severity
        cursor = conn.execute('''
            SELECT severity, COUNT(*) as count
            FROM threats 
            WHERE timestamp >= ?
            GROUP BY severity
            ORDER BY count DESC
        ''', (start_time,))
        
        patterns['by_severity'] = []
        for row in cursor.fetchall():
            patterns['by_severity'].append({
                'severity': row[0],
                'count': row[1]
            })
        
        conn.close()
        return patterns
        
    except Exception as e:
        return {'error': f'Failed to get attack patterns: {e}'}

def export_threats(format='json', period='24h'):
    """Export threat data"""
    threats_data = get_threats(period, limit=10000)
    
    if 'error' in threats_data:
        return threats_data
    
    if format.lower() == 'json':
        return json.dumps(threats_data, indent=2)
    elif format.lower() == 'csv':
        import csv
        import io
        
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['ID', 'Timestamp', 'Source IP', 'Target', 'Method', 'Type', 'Severity', 'Status', 'Score', 'Description'])
        
        for threat in threats_data['threats']:
            writer.writerow([
                threat['id'],
                threat['timestamp_iso'],
                threat['source_ip'],
                threat['target'],
                threat['method'],
                threat['type'],
                threat['severity'],
                threat['status'],
                threat['score'],
                threat['description']
            ])
        
        return output.getvalue()
    else:
        return json.dumps(threats_data, indent=2)

def main():
    if len(sys.argv) < 2:
        print("Usage: get_threats.py <command> [args...]")
        print("Commands:")
        print("  list [period] [limit] [offset]")
        print("  detail <threat_id>")
        print("  feed <feed_type> [limit]")
        print("  patterns <period> [pattern_type]")
        print("  export <format> [period]")
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == 'list':
        period = sys.argv[2] if len(sys.argv) > 2 else '24h'
        limit = int(sys.argv[3]) if len(sys.argv) > 3 else 100
        offset = int(sys.argv[4]) if len(sys.argv) > 4 else 0
        
        result = get_threats(period, limit, offset)
        print(json.dumps(result))
        
    elif command == 'detail':
        if len(sys.argv) < 3:
            print("ERROR: Threat ID required")
            sys.exit(1)
        
        threat_id = int(sys.argv[2])
        result = get_threat_detail(threat_id)
        print(json.dumps(result))
        
    elif command == 'feed':
        if len(sys.argv) < 3:
            print("ERROR: Feed type required")
            sys.exit(1)
        
        feed_type = sys.argv[2]
        limit = int(sys.argv[3]) if len(sys.argv) > 3 else 50
        
        result = get_threat_feed(feed_type, limit)
        print(json.dumps(result))
        
    elif command == 'patterns':
        period = sys.argv[2] if len(sys.argv) > 2 else '24h'
        pattern_type = sys.argv[3] if len(sys.argv) > 3 else 'all'
        
        result = get_attack_patterns(period, pattern_type)
        print(json.dumps(result))
        
    elif command == 'export':
        if len(sys.argv) < 3:
            print("ERROR: Format required")
            sys.exit(1)
        
        format = sys.argv[2]
        period = sys.argv[3] if len(sys.argv) > 3 else '24h'
        
        result = export_threats(format, period)
        print(result)
        
    else:
        print(f"ERROR: Unknown command: {command}")
        sys.exit(1)

if __name__ == '__main__':
    main()
