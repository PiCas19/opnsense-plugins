#!/usr/local/bin/python3.11

"""
WebGuard Threat Metrics Script
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

def get_threat_metrics(period='24h'):
    """Get comprehensive threat metrics"""
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
        
        metrics = {}
        
        # Total threats
        cursor = conn.execute('SELECT COUNT(*) FROM threats WHERE timestamp >= ?', (start_time,))
        metrics['total_threats'] = cursor.fetchone()[0]
        
        # Threat detection rate (threats per hour)
        time_span_hours = (time.time() - start_time) / 3600
        metrics['detection_rate'] = round(metrics['total_threats'] / time_span_hours, 2) if time_span_hours > 0 else 0
        
        # Threat types distribution
        cursor = conn.execute('''
            SELECT type, COUNT(*) FROM threats 
            WHERE timestamp >= ? 
            GROUP BY type 
            ORDER BY COUNT(*) DESC
        ''', (start_time,))
        metrics['threat_types'] = dict(cursor.fetchall())
        
        # Severity distribution
        cursor = conn.execute('''
            SELECT severity, COUNT(*) FROM threats 
            WHERE timestamp >= ? 
            GROUP BY severity
        ''', (start_time,))
        metrics['severity_distribution'] = dict(cursor.fetchall())
        
        # Critical threats
        cursor = conn.execute('''
            SELECT COUNT(*) FROM threats 
            WHERE severity = 'critical' AND timestamp >= ?
        ''', (start_time,))
        metrics['critical_threats'] = cursor.fetchone()[0]
        
        # High priority threats
        cursor = conn.execute('''
            SELECT COUNT(*) FROM threats 
            WHERE severity IN ('critical', 'high') AND timestamp >= ?
        ''', (start_time,))
        metrics['high_priority_threats'] = cursor.fetchone()[0]
        
        # False positive rate (simplified calculation)
        cursor = conn.execute('''
            SELECT COUNT(*) FROM threats 
            WHERE false_positive = 1 AND timestamp >= ?
        ''', (start_time,))
        false_positives = cursor.fetchone()[0]
        metrics['false_positive_rate'] = round((false_positives / metrics['total_threats']) * 100, 2) if metrics['total_threats'] > 0 else 0
        
        # Top threat sources
        cursor = conn.execute('''
            SELECT source_ip, COUNT(*) as count FROM threats 
            WHERE timestamp >= ? 
            GROUP BY source_ip 
            ORDER BY count DESC 
            LIMIT 15
        ''', (start_time,))
        metrics['top_threat_sources'] = [{'ip': row[0], 'count': row[1]} for row in cursor.fetchall()]
        
        # Recent high-severity threats
        cursor = conn.execute('''
            SELECT timestamp, source_ip, type, severity, description 
            FROM threats 
            WHERE severity IN ('critical', 'high') AND timestamp >= ?
            ORDER BY timestamp DESC 
            LIMIT 20
        ''', (start_time,))
        
        recent_threats = []
        for row in cursor.fetchall():
            recent_threats.append({
                'timestamp': datetime.fromtimestamp(row[0]).isoformat(),
                'source_ip': row[1],
                'type': row[2],
                'severity': row[3],
                'description': row[4]
            })
        metrics['recent_high_severity'] = recent_threats
        
        # Threat trend (last 24 hours in hourly buckets)
        trend = []
        current_time = int(time.time())
        for i in range(24):
            hour_end = current_time - (i * 3600)
            hour_start = hour_end - 3600
            
            cursor = conn.execute('''
                SELECT COUNT(*) FROM threats 
                WHERE timestamp >= ? AND timestamp < ?
            ''', (hour_start, hour_end))
            
            count = cursor.fetchone()[0]
            trend.insert(0, {  # Insert at beginning to maintain chronological order
                'timestamp': hour_start,
                'count': count,
                'hour_ago': i
            })
        
        metrics['hourly_trend'] = trend
        
        # Blocked vs detected ratio
        cursor = conn.execute('''
            SELECT 
                SUM(CASE WHEN status = 'blocked' THEN 1 ELSE 0 END) as blocked,
                SUM(CASE WHEN status = 'detected' THEN 1 ELSE 0 END) as detected
            FROM threats 
            WHERE timestamp >= ?
        ''', (start_time,))
        
        result = cursor.fetchone()
        blocked = result[0] or 0
        detected = result[1] or 0
        total_actions = blocked + detected
        
        metrics['action_distribution'] = {
            'blocked': blocked,
            'detected': detected,
            'block_rate': round((blocked / total_actions) * 100, 2) if total_actions > 0 else 0
        }
        
        # Average threat score by type
        cursor = conn.execute('''
            SELECT type, AVG(score) as avg_score FROM threats 
            WHERE timestamp >= ? AND score > 0
            GROUP BY type 
            ORDER BY avg_score DESC
        ''', (start_time,))
        
        metrics['avg_scores_by_type'] = {}
        for row in cursor.fetchall():
            metrics['avg_scores_by_type'][row[0]] = round(row[1], 2)
        
        # Protocol distribution
        cursor = conn.execute('''
            SELECT method, COUNT(*) FROM threats 
            WHERE timestamp >= ? 
            GROUP BY method
        ''', (start_time,))
        metrics['protocol_distribution'] = dict(cursor.fetchall())
        
        # Daily comparison (if period allows)
        if period in ['7d', '30d']:
            # Compare with previous period
            prev_start = start_time - (start_time - int(time.time() - (7 * 86400 if period == '7d' else 30 * 86400)))
            
            cursor = conn.execute('''
                SELECT COUNT(*) FROM threats 
                WHERE timestamp >= ? AND timestamp < ?
            ''', (prev_start, start_time))
            prev_threats = cursor.fetchone()[0]
            
            change = metrics['total_threats'] - prev_threats
            change_percent = round((change / prev_threats) * 100, 2) if prev_threats > 0 else 0
            
            metrics['period_comparison'] = {
                'current_period': metrics['total_threats'],
                'previous_period': prev_threats,
                'change': change,
                'change_percent': change_percent,
                'trend': 'increasing' if change > 0 else 'decreasing' if change < 0 else 'stable'
            }
        
        conn.close()
        return metrics
        
    except Exception as e:
        return {'error': f'Failed to get threat metrics: {e}'}

def main():
    period = sys.argv[1] if len(sys.argv) > 1 else '24h'
    metrics = get_threat_metrics(period)
    print(json.dumps(metrics))

if __name__ == '__main__':
    main()