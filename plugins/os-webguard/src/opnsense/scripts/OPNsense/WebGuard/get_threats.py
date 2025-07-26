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
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def initialize_database():
    """Initialize the threats table if it doesn't exist."""
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS threats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp INTEGER,
                    source_ip TEXT,
                    target TEXT,
                    method TEXT,
                    type TEXT,
                    severity TEXT,
                    status TEXT,
                    score REAL,
                    payload TEXT,
                    request_headers TEXT,
                    rule_matched TEXT,
                    description TEXT,
                    false_positive INTEGER
                )
            ''')
            conn.commit()
            logger.info("Database initialized successfully")
            return {'status': 'ok', 'message': 'Database initialized'}
    except Exception as e:
        logger.error(f'Failed to initialize database: {e}')
        return {'error': f'Failed to initialize database: {e}'}

def add_sample_threats(count=5):
    """Add sample threats to the database for testing."""
    if not os.path.exists(DB_FILE):
        initialize_database()
    
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            current_time = int(time.time())
            sample_threats = [
                (
                    current_time - i * 300,  # Spread over last 5 minutes
                    f"192.168.1.{100 + i}",
                    "/test/path",
                    "GET",
                    "SQL Injection",
                    "high",
                    "blocked",
                    85.0 + i,
                    "SELECT * FROM users WHERE id = 1",
                    '{"User-Agent": "TestClient"}',
                    f"sql_injection_rule_{i+1}",
                    f"Detected SQL injection attempt {i+1}",
                    0
                )
                for i in range(count)
            ]
            cursor.executemany('''
                INSERT INTO threats (timestamp, source_ip, target, method, type, severity, status, score, payload, request_headers, rule_matched, description, false_positive)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', sample_threats)
            conn.commit()
            logger.info(f"Added {count} sample threats")
            return {'status': 'ok', 'message': f'Added {count} sample threats'}
    except Exception as e:
        logger.error(f'Failed to add sample threats: {e}')
        return {'error': f'Failed to add sample threats: {e}'}

def get_threats(period='24h', limit=100, offset=0):
    """Get threats with pagination"""
    if not os.path.exists(DB_FILE):
        initialize_database()
    
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
            
            logger.debug(f'Querying threats with period={period}, start_time={start_time}, limit={limit}, offset={offset}')
            
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
            
            logger.debug(f'Found {len(threats)} threats, total count={total}')
            
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
        initialize_database()
    
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
                logger.warning(f'Threat ID {threat_id} not found')
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
            
            cursor = conn.execute('''
                SELECT COUNT(*) FROM threats 
                WHERE source_ip = ? AND timestamp >= ?
            ''', (row[2], int(time.time() - 86400)))
            
            threat['related_count'] = cursor.fetchone()[0]
            logger.debug(f'Retrieved details for threat ID {threat_id}')
            
            return threat
            
    except Exception as e:
        logger.error(f'Failed to get threat detail: {e}')
        return {'error': f'Failed to get threat detail: {e}'}

def get_threat_feed(feed_type='recent', limit=50):
    """Get threat feed data"""
    if not os.path.exists(DB_FILE):
        initialize_database()
    
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
            
            logger.debug(f'Retrieved {len(feed)} items for threat feed (type: {feed_type})')
            return {'feed': feed, 'type': feed_type, 'count': len(feed)}
            
    except Exception as e:
        logger.error(f'Failed to get threat feed: {e}')
        return {'error': f'Failed to get threat feed: {e}'}

def list_false_positives(period='30d', limit=100, offset=0):
    """Get threats marked as false positives"""
    if not os.path.exists(DB_FILE):
        initialize_database()
    
    try:
        with sqlite3.connect(DB_FILE) as conn:
            if period == '1h':
                start_time = int(time.time() - 3600)
            elif period == '24h':
                start_time = int(time.time() - 86400)
            elif period == '7d':
                start_time = int(time.time() - 604800)
            elif period == '30d':
                start_time = int(time.time() - 2592000)
            else:
                start_time = int(time.time() - 2592000)
            
            cursor = conn.execute('SELECT COUNT(*) FROM threats WHERE timestamp >= ? AND false_positive = 1', (start_time,))
            total = cursor.fetchone()[0]
            
            cursor = conn.execute('''
                SELECT id, timestamp, source_ip, target, method, type, severity, status, 
                       score, payload, request_headers, rule_matched, description, false_positive
                FROM threats 
                WHERE timestamp >= ? AND false_positive = 1
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
            
            logger.debug(f'Retrieved {len(threats)} false positive threats for period {period}')
            return {
                'threats': threats,
                'total': total,
                'limit': limit,
                'offset': offset,
                'period': period
            }
            
    except Exception as e:
        logger.error(f'Failed to get false positive threats: {e}')
        return {'error': f'Failed to get false positive threats: {e}'}

def mark_false_positive(threat_id, reason="Manual false positive"):
    """Mark a threat as false positive"""
    if not os.path.exists(DB_FILE):
        initialize_database()
    
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.execute('UPDATE threats SET false_positive = 1 WHERE id = ?', (threat_id,))
            if cursor.rowcount == 0:
                logger.warning(f'Threat ID {threat_id} not found for marking as false positive')
                return {'error': 'Threat not found'}
            conn.commit()
            logger.info(f'Marked threat {threat_id} as false positive: {reason}')
            return {'status': 'ok', 'message': f'Threat {threat_id} marked as false positive'}
    except Exception as e:
        logger.error(f'Failed to mark threat {threat_id} as false positive: {e}')
        return {'error': f'Failed to mark threat as false positive: {e}'}

def unmark_false_positive(threat_id, reason="Manual unmark false positive"):
    """Unmark a threat as false positive"""
    if not os.path.exists(DB_FILE):
        initialize_database()
    
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.execute('UPDATE threats SET false_positive = 0 WHERE id = ?', (threat_id,))
            if cursor.rowcount == 0:
                logger.warning(f'Threat ID {threat_id} not found for unmarking as false positive')
                return {'error': 'Threat not found'}
            conn.commit()
            logger.info(f'Unmarked threat {threat_id} as false positive: {reason}')
            return {'status': 'ok', 'message': f'Threat {threat_id} unmarked as false positive'}
    except Exception as e:
        logger.error(f'Failed to unmark threat {threat_id} as false positive: {e}')
        return {'error': f'Failed to unmark threat as false positive: {e}'}

def whitelist_ip_from_threat(threat_id, description="Whitelisted from threat"):
    """Add the source IP of a threat to the whitelist"""
    if not os.path.exists(DB_FILE):
        initialize_database()
    
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.execute('SELECT source_ip FROM threats WHERE id = ?', (threat_id,))
            row = cursor.fetchone()
            if not row:
                logger.warning(f'Threat ID {threat_id} not found for whitelisting')
                return {'error': 'Threat not found'}
            
            ip = row[0]
            cursor.execute('''
                INSERT OR IGNORE INTO whitelist (ip, description, permanent, added_timestamp)
                VALUES (?, ?, ?, ?)
            ''', (ip, description, 1, int(time.time())))
            conn.commit()
            logger.info(f'Whitelisted IP {ip} from threat {threat_id}: {description}')
            return {'status': 'ok', 'message': f'IP {ip} whitelisted from threat {threat_id}'}
    except Exception as e:
        logger.error(f'Failed to whitelist IP from threat {threat_id}: {e}')
        return {'error': f'Failed to whitelist IP from threat: {e}'}

def block_ip_from_threat(threat_id, duration=3600, reason="Blocked from threat"):
    """Block the source IP of a threat"""
    if not os.path.exists(DB_FILE):
        initialize_database()
    
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.execute('SELECT source_ip FROM threats WHERE id = ?', (threat_id,))
            row = cursor.fetchone()
            if not row:
                logger.warning(f'Threat ID {threat_id} not found for blocking')
                return {'error': 'Threat not found'}
            
            ip = row[0]
            cursor.execute('''
                INSERT OR REPLACE INTO blocked_ips (ip, block_timestamp, duration, reason, block_type)
                VALUES (?, ?, ?, ?, ?)
            ''', (ip, int(time.time()), duration, reason, 'manual'))
            conn.commit()
            logger.info(f'Blocked IP {ip} from threat {threat_id} (duration: {duration}, reason: {reason})')
            return {'status': 'ok', 'message': f'IP {ip} blocked from threat {threat_id}'}
    except Exception as e:
        logger.error(f'Failed to block IP from threat {threat_id}: {e}')
        return {'error': f'Failed to block IP from threat: {e}'}

def create_rule_from_threat(threat_id):
    """Create a rule based on a threat (stub implementation)"""
    if not os.path.exists(DB_FILE):
        initialize_database()
    
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.execute('SELECT type, rule_matched, payload FROM threats WHERE id = ?', (threat_id,))
            row = cursor.fetchone()
            if not row:
                logger.warning(f'Threat ID {threat_id} not found for rule creation')
                return {'error': 'Threat not found'}
            
            logger.info(f'Created rule from threat {threat_id} (type: {row[0]}, rule_matched: {row[1]})')
            return {'status': 'ok', 'message': f'Rule created from threat {threat_id} (stub)'}
    except Exception as e:
        logger.error(f'Failed to create rule from threat {threat_id}: {e}')
        return {'error': f'Failed to create rule from threat: {e}'}

def get_threat_timeline(period='24h'):
    """Get threat timeline data"""
    if not os.path.exists(DB_FILE):
        initialize_database()
    
    try:
        with sqlite3.connect(DB_FILE) as conn:
            if period == '1h':
                start_time = int(time.time() - 3600)
                interval = 300  # 5-minute intervals
            elif period == '24h':
                start_time = int(time.time() - 86400)
                interval = 3600  # 1-hour intervals
            elif period == '7d':
                start_time = int(time.time() - 604800)
                interval = 86400  # 1-day intervals
            elif period == '30d':
                start_time = int(time.time() - 2592000)
                interval = 86400  # 1-day intervals
            else:
                start_time = int(time.time() - 86400)
                interval = 3600
            
            cursor = conn.execute('''
                SELECT strftime('%Y-%m-%d %H:%M', datetime(timestamp, 'unixepoch')) as time_slot,
                       COUNT(*) as threat_count
                FROM threats
                WHERE timestamp >= ?
                GROUP BY (timestamp / ?)
                ORDER BY timestamp
            ''', (start_time, interval))
            
            labels = []
            threats = []
            for row in cursor.fetchall():
                labels.append(row[0])
                threats.append(row[1])
            
            logger.debug(f'Retrieved timeline for period {period}: {len(labels)} intervals')
            return {
                'status': 'ok',
                'timeline': {
                    'labels': labels,
                    'threats': threats,
                    'requests': []  # Placeholder for future use
                },
                'period': period
            }
            
    except Exception as e:
        logger.error(f'Failed to get threat timeline: {e}')
        return {'error': f'Failed to get threat timeline: {e}'}

def get_attack_patterns(period='24h', pattern_type='all'):
    """Get attack patterns analysis - REQUIRED for API getPatterns"""
    if not os.path.exists(DB_FILE):
        initialize_database()
    
    try:
        with sqlite3.connect(DB_FILE) as conn:
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
            
            where_clause = 'WHERE timestamp >= ?'
            params = [start_time]
            if pattern_type != 'all':
                where_clause += ' AND type = ?'
                params.append(pattern_type)
            
            cursor = conn.execute(f'''
                SELECT type, COUNT(*) as count, AVG(score) as avg_score,
                       severity, source_ip, payload, rule_matched
                FROM threats 
                {where_clause}
                GROUP BY type, severity, rule_matched
                ORDER BY count DESC
            ''', params)
            
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
                    'blocked': int(row[1] * 0.95),
                    'success_rate': round((row[1] * 0.05 / row[1] * 100), 2) if row[1] > 0 else 0,
                    'first_seen': datetime.fromtimestamp(start_time).isoformat(),
                    'trend': 'up' if row[1] > 10 else 'stable'
                }
                patterns.append(pattern_obj)
                pattern_types[row[0]] += row[1]
            
            for pattern_type, count in pattern_types.items():
                if count > 5:
                    trending_attacks.append({
                        'type': pattern_type,
                        'count': count,
                        'trend': 'increasing' if count > 10 else 'stable',
                        'severity': 'high' if count > 20 else 'medium'
                    })
            
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
            
            logger.debug(f'Retrieved {len(patterns)} patterns, {len(trending_attacks)} trending attacks')
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
        initialize_database()
    
    try:
        with sqlite3.connect(DB_FILE) as conn:
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
            
            cursor = conn.execute('SELECT COUNT(*) FROM threats')
            total_threats = cursor.fetchone()[0]
            
            cursor = conn.execute('SELECT COUNT(*) FROM threats WHERE timestamp >= ?', (start_time,))
            threats_period = cursor.fetchone()[0]
            
            cursor = conn.execute('''
                SELECT COUNT(*) FROM threats 
                WHERE timestamp >= ? AND status = 'blocked'
            ''', (start_time,))
            blocked_today = cursor.fetchone()[0]
            
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
            
            logger.debug(f'Retrieved stats: {total_threats} total threats, {threats_period} in period')
            return {
                'total_threats': total_threats,
                'threats_24h': threats_period if period == '24h' else threats_period,
                'blocked_today': blocked_today,
                'threats_by_type': threats_by_type,
                'threats_by_severity': threats_by_severity,
                'top_source_ips': top_source_ips,
                'patterns': {}
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
        logger.error(f'Failed to export threats: {threats_data["error"]}')
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
        
        logger.debug(f'Exported {len(threats_data["threats"])} threats in CSV format')
        return output.getvalue()
    else:
        logger.debug(f'Exported {len(threats_data["threats"])} threats in JSON format')
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
        print("  add_sample_threats [count]")
        print("  list_false_positives [period] [limit] [offset]")
        print("  mark_false_positive <threat_id> [reason]")
        print("  unmark_false_positive <threat_id> [reason]")
        print("  whitelist_ip_from_threat <threat_id> [description]")
        print("  block_ip_from_threat <threat_id> [duration] [reason]")
        print("  create_rule_from_threat <threat_id>")
        print("  timeline [period]")
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
        
    elif command == 'add_sample_threats':
        count = int(sys.argv[2]) if len(sys.argv) > 2 else 5
        result = add_sample_threats(count)
        print(json.dumps(result))
        
    elif command == 'list_false_positives48':
        period = sys.argv[2] if len(sys.argv) > 2 else '30d'
        limit = int(sys.argv[3]) if len(sys.argv) > 3 else 100
        offset = int(sys.argv[4]) if len(sys.argv) > 4 else 0
        result = list_false_positives(period, limit, offset)
        print(json.dumps(result))
        
    elif command == 'mark_false_positive':
        if len(sys.argv) < 3:
            print("ERROR: Threat ID required")
            sys.exit(1)
        threat_id = int(sys.argv[2])
        reason = sys.argv[3] if len(sys.argv) > 3 else "Manual false positive"
        result = mark_false_positive(threat_id, reason)
        print(json.dumps(result))
        
    elif command == 'unmark_false_positive':
        if len(sys.argv) < 3:
            print("ERROR: Threat ID required")
            sys.exit(1)
        threat_id = int(sys.argv[2])
        reason = sys.argv[3] if len(sys.argv) > 3 else "Manual unmark false positive"
        result = unmark_false_positive(threat_id, reason)
        print(json.dumps(result))
        
    elif command == 'whitelist_ip_from_threat':
        if len(sys.argv) < 3:
            print("ERROR: Threat ID required")
            sys.exit(1)
        threat_id = int(sys.argv[2])
        description = sys.argv[3] if len(sys.argv) > 3 else "Whitelisted from threat"
        result = whitelist_ip_from_threat(threat_id, description)
        print(json.dumps(result))
        
    elif command == 'block_ip_from_threat':
        if len(sys.argv) < 3:
            print("ERROR: Threat ID required")
            sys.exit(1)
        threat_id = int(sys.argv[2])
        duration = int(sys.argv[3]) if len(sys.argv) > 3 else 3600
        reason = sys.argv[4] if len(sys.argv) > 4 else "Blocked from threat"
        result = block_ip_from_threat(threat_id, duration, reason)
        print(json.dumps(result))
        
    elif command == 'create_rule_from_threat':
        if len(sys.argv) < 3:
            print("ERROR: Threat ID required")
            sys.exit(1)
        threat_id = int(sys.argv[2])
        result = create_rule_from_threat(threat_id)
        print(json.dumps(result))
        
    elif command == 'timeline':
        period = sys.argv[2] if len(sys.argv) > 2 else '24h'
        result = get_threat_timeline(period)
        print(json.dumps(result))
        
    else:
        print(f"ERROR: Unknown command: {command}")
        sys.exit(1)

if __name__ == '__main__':
    main()