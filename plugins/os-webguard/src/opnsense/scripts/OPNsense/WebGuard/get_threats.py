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
import logging
from datetime import datetime
from collections import defaultdict

DB_FILE = '/var/db/webguard/webguard.db'

# Configure logging
logging.basicConfig(level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def get_threats(period='24h', limit=100, offset=0):
    """Get threats with pagination"""
    if not os.path.exists(DB_FILE):
        return {'error': 'Database not found'}
    
    try:
        with sqlite3.connect(DB_FILE) as conn:
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
            
            return result
            
    except Exception as e:
        logger.error(f'Failed to get threats: {e}')
        return {'error': f'Failed to get threats: {e}'}

def get_threat_detail(threat_id):
    """Get detailed information about a specific threat"""
    if not os.path.exists(DB_FILE):
        return {'error': 'Database not found'}
    
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.execute('''
                SELECT id, timestamp, source_ip, target, method, type, severity, description,
                       false_positive, payload
                FROM threats 
                WHERE id = ?
            ''', (threat_id,))
            
            row = cursor.fetchone()
            if not row:
                return {'error': 'Threat not found'}
            
            threat = {
                'id': row[0],
                'timestamp': row[1],
                'timestamp_iso': datetime.fromtimestamp(row[1]).isoformat(),
                'source_ip': row[2],
                'target': row[3],
                'method': row[4],
                'type': row[5],
                'severity': row[6],
                'description': row[7],
                'false_positive': bool(row[8]),
                'payload': row[9]
            }
            
            # Get related threats from same IP in last 24h
            cursor = conn.execute('''
                SELECT COUNT(*) FROM threats 
                WHERE source_ip = ? AND timestamp >= ?
            ''', (row[2], int(time.time() - 86400)))
            
            threat['related_count'] = cursor.fetchone()[0]
            
            return threat
            
    except Exception as e:
        logger.error(f'Failed to get threat detail: {e}')
        return {'error': f'Failed to get threat detail: {e}'}

def get_threat_feed(feed_type='recent', limit=50):
    """Get threat feed data"""
    if not os.path.exists(DB_FILE):
        return {'error': 'Database not found'}
    
    try:
        with sqlite3.connect(DB_FILE) as conn:
            if feed_type == 'recent':
                cursor = conn.execute('''
                    SELECT id, timestamp, source_ip, target, type, severity, description
                    FROM threats 
                    ORDER BY timestamp DESC 
                    LIMIT ?
                ''', (limit,))
            elif feed_type == 'critical':
                cursor = conn.execute('''
                    SELECT id, timestamp, source_ip, target, type, severity, description
                    FROM threats 
                    WHERE severity = 'critical'
                    ORDER BY timestamp DESC 
                    LIMIT ?
                ''', (limit,))
            elif feed_type == 'high':
                cursor = conn.execute('''
                    SELECT id, timestamp, source_ip, target, type, severity, description
                    FROM threats 
                    WHERE severity IN ('critical', 'high')
                    ORDER BY timestamp DESC 
                    LIMIT ?
                ''', (limit,))
            else:
                cursor = conn.execute('''
                    SELECT id, timestamp, source_ip, target, type, severity, description
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
                    'target': row[3],
                    'type': row[4],
                    'severity': row[5],
                    'description': row[6]
                }
                feed.append(item)
            
            return {'feed': feed, 'type': feed_type, 'count': len(feed)}
            
    except Exception as e:
        logger.error(f'Failed to get threat feed: {e}')
        return {'error': f'Failed to get threat feed: {e}'}

def get_attack_patterns(period='24h', pattern_type='all'):
    """Get attack patterns analysis - REQUIRED for API getPatterns"""
    if not os.path.exists(DB_FILE):
        return {'patterns': [], 'trending_attacks': [], 'attack_sequences': []}
    
    try:
        with sqlite3.connect(DB_FILE) as conn:
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
            
            # Get pattern data
            cursor = conn.execute('''
                SELECT type, COUNT(*) as count, AVG(score) as avg_score,
                       severity, source_ip, payload, rule_matched
                FROM threats 
                WHERE timestamp >= ?
                GROUP BY type, severity, rule_matched
                ORDER BY count DESC
            ''', (start_time,))
            
            patterns = []
            trending_attacks = []
            pattern_types = defaultdict(int)
            
            for row in cursor.fetchall():
                pattern_obj = {
                    'pattern': row[6] or f"rule_{row[0].lower().replace(' ', '_')}",
                    'signature': row[0],
                    'type': row[0],
                    'count': row[1],
                    'occurrences': row[1],
                    'avg_score': round(row[2], 2) if row[2] else 0,
                    'severity': row[3],
                    'blocked': int(row[1] * 0.95),  # Assume 95% blocked
                    'success_rate': round((row[1] * 0.05 / row[1] * 100), 2) if row[1] > 0 else 0,
                    'first_seen': datetime.fromtimestamp(start_time).isoformat(),
                    'trend': 'up' if row[1] > 10 else 'stable'
                }
                patterns.append(pattern_obj)
                pattern_types[row[0]] += row[1]
            
            # Create trending attacks
            for pattern_type, count in pattern_types.items():
                if count > 5:  # Only patterns with significant activity
                    trending_attacks.append({
                        'type': pattern_type,
                        'count': count,
                        'trend': 'increasing' if count > 10 else 'stable',
                        'severity': 'high' if count > 20 else 'medium'
                    })
            
            # Get attack sequences (same IP multiple attacks)
            cursor = conn.execute('''
                SELECT source_ip, GROUP_CONCAT(type, ',') as sequence, COUNT(*) as count
                FROM threats 
                WHERE timestamp >= ?
                GROUP BY source_ip
                HAVING COUNT(*) > 1
                ORDER BY count DESC
                LIMIT 10
            ''', (start_time,))
            
            attack_sequences = []
            for row in cursor.fetchall():
                attack_sequences.append({
                    'source_ip': row[0],
                    'sequence': row[1].split(','),
                    'count': row[2],
                    'risk_level': 'high' if row[2] > 5 else 'medium'
                })
            
            return {
                'patterns': patterns,
                'trending_attacks': trending_attacks,
                'attack_sequences': attack_sequences
            }
            
    except Exception as e:
        logger.error(f'Failed to get attack patterns: {e}')
        return {'patterns': [], 'trending_attacks': [], 'attack_sequences': []}

def get_threat_stats(period='24h'):
    """Get threat statistics - REQUIRED for API getStats"""
    if not os.path.exists(DB_FILE):
        return {
            'total_threats': 0,
            'threats_24h': 0,
            'blocked_today': 0,
            'threats_by_type': {},
            'threats_by_severity': {},
            'top_source_ips': {},
            'patterns': {}
        }
    
    try:
        with sqlite3.connect(DB_FILE) as conn:
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
            
            # Total threats count
            cursor = conn.execute('SELECT COUNT(*) FROM threats')
            total_threats = cursor.fetchone()[0]
            
            # Threats in period
            cursor = conn.execute('SELECT COUNT(*) FROM threats WHERE timestamp >= ?', (start_time,))
            threats_period = cursor.fetchone()[0]
            
            # Blocked threats in period
            cursor = conn.execute('''
                SELECT COUNT(*) FROM threats 
                WHERE timestamp >= ? AND status = 'blocked'
            ''', (start_time,))
            blocked_today = cursor.fetchone()[0]
            
            # Threats by type
            cursor = conn.execute('''
                SELECT type, COUNT(*) as count
                FROM threats 
                WHERE timestamp >= ?
                GROUP BY type
                ORDER BY count DESC
            ''', (start_time,))
            
            threats_by_type = {}
            for row in cursor.fetchall():
                threat_type = row[0]
                count = row[1]
                
                # Get patterns for this type
                cursor2 = conn.execute('''
                    SELECT rule_matched, COUNT(*) as pattern_count
                    FROM threats 
                    WHERE timestamp >= ? AND type = ?
                    GROUP BY rule_matched
                ''', (start_time, threat_type))
                
                patterns = {}
                for pattern_row in cursor2.fetchall():
                    pattern_name = pattern_row[0] or f"pattern_{threat_type.lower().replace(' ', '_')}"
                    patterns[pattern_name] = pattern_row[1]
                
                threats_by_type[threat_type] = {
                    'count': count,
                    'patterns': patterns
                }
            
            # Threats by severity
            cursor = conn.execute('''
                SELECT severity, COUNT(*) as count
                FROM threats 
                WHERE timestamp >= ?
                GROUP BY severity
                ORDER BY count DESC
            ''', (start_time,))
            
            threats_by_severity = {}
            for row in cursor.fetchall():
                threats_by_severity[row[0]] = row[1]
            
            # Top source IPs
            cursor = conn.execute('''
                SELECT source_ip, COUNT(*) as count
                FROM threats 
                WHERE timestamp >= ?
                GROUP BY source_ip
                ORDER BY count DESC
                LIMIT 10
            ''', (start_time,))
            
            top_source_ips = {}
            for row in cursor.fetchall():
                top_source_ips[row[0]] = row[1]
            
            return {
                'total_threats': total_threats,
                'threats_24h': threats_period if period == '24h' else threats_period,
                'blocked_today': blocked_today,
                'threats_by_type': threats_by_type,
                'threats_by_severity': threats_by_severity,
                'top_source_ips': top_source_ips,
                'patterns': {}  # Additional patterns data
            }
            
    except Exception as e:
        logger.error(f'Failed to get threat stats: {e}')
        return {
            'total_threats': 0,
            'threats_24h': 0,
            'blocked_today': 0,
            'threats_by_type': {},
            'threats_by_severity': {},
            'top_source_ips': {},
            'patterns': {}
        }

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
        print("  stats <period>")
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
        
    elif command == 'stats':
        period = sys.argv[2] if len(sys.argv) > 2 else '24h'
        
        result = get_threat_stats(period)
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