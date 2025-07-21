#!/usr/local/bin/python3.11

"""
WebGuard Statistics Retrieval Script
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
CONFIG_FILE = '/usr/local/etc/webguard/config.json'

def get_engine_stats():
    """Get real-time engine statistics"""
    stats = {
        'requests_analyzed': 0,
        'threats_blocked': 0,
        'ips_blocked': 0,
        'uptime': 0,
        'cpu_usage': 0,
        'memory_usage': 0,
        'threats_today': 0,
        'status': 'unknown'
    }
    
    try:
        # Check if engine is running
        import psutil
        engine_running = False
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                if 'web_guard_engine.py' in ' '.join(proc.info['cmdline'] or []):
                    engine_running = True
                    stats['cpu_usage'] = proc.cpu_percent()
                    stats['memory_usage'] = proc.memory_percent()
                    stats['uptime'] = int(time.time() - proc.create_time())
                    break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        stats['status'] = 'running' if engine_running else 'stopped'
        
        # Get database statistics
        if os.path.exists(DB_FILE):
            conn = sqlite3.connect(DB_FILE)
            
            # Total threats
            cursor = conn.execute('SELECT COUNT(*) FROM threats')
            stats['threats_blocked'] = cursor.fetchone()[0]
            
            # Threats today
            today_start = int(datetime.now().replace(hour=0, minute=0, second=0, microsecond=0).timestamp())
            cursor = conn.execute('SELECT COUNT(*) FROM threats WHERE timestamp >= ?', (today_start,))
            stats['threats_today'] = cursor.fetchone()[0]
            
            # Active blocked IPs
            current_time = int(time.time())
            cursor = conn.execute('''
                SELECT COUNT(*) FROM blocked_ips 
                WHERE expires_at IS NULL OR expires_at > ?
            ''', (current_time,))
            stats['ips_blocked'] = cursor.fetchone()[0]
            
            conn.close()
        
        # Estimate requests analyzed (simplified)
        if stats['uptime'] > 0:
            stats['requests_analyzed'] = stats['uptime'] * 10  # Rough estimate
        
    except Exception as e:
        print(f"ERROR: Failed to get stats: {e}", file=sys.stderr)
    
    return stats

def get_threat_stats(period='24h'):
    """Get threat statistics for specified period"""
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
        
        # Total threats in period
        cursor = conn.execute('SELECT COUNT(*) FROM threats WHERE timestamp >= ?', (start_time,))
        stats['total_threats'] = cursor.fetchone()[0]
        
        # Threats by type
        cursor = conn.execute('''
            SELECT type, COUNT(*) FROM threats 
            WHERE timestamp >= ? 
            GROUP BY type
        ''', (start_time,))
        stats['threats_by_type'] = dict(cursor.fetchall())
        
        # Threats by severity
        cursor = conn.execute('''
            SELECT severity, COUNT(*) FROM threats 
            WHERE timestamp >= ? 
            GROUP BY severity
        ''', (start_time,))
        stats['threats_by_severity'] = dict(cursor.fetchall())
        
        # Top source IPs
        cursor = conn.execute('''
            SELECT source_ip, COUNT(*) as count FROM threats 
            WHERE timestamp >= ? 
            GROUP BY source_ip 
            ORDER BY count DESC 
            LIMIT 10
        ''', (start_time,))
        stats['top_source_ips'] = [{'ip': row[0], 'count': row[1]} for row in cursor.fetchall()]
        
        # Threat timeline (hourly buckets)
        timeline = []
        for i in range(24):
            hour_start = start_time + (i * 3600)
            hour_end = hour_start + 3600
            
            cursor = conn.execute('''
                SELECT COUNT(*) FROM threats 
                WHERE timestamp >= ? AND timestamp < ?
            ''', (hour_start, hour_end))
            
            count = cursor.fetchone()[0]
            timeline.append({
                'timestamp': hour_start,
                'count': count,
                'hour': datetime.fromtimestamp(hour_start).strftime('%H:00')
            })
        
        stats['threat_timeline'] = timeline
        
        conn.close()
        return stats
        
    except Exception as e:
        return {'error': f'Failed to get threat stats: {e}'}

def get_blocking_stats(period='24h'):
    """Get blocking statistics for specified period"""
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
        
        stats = {}
        current_time = int(time.time())
        
        # Active blocks
        cursor = conn.execute('''
            SELECT COUNT(*) FROM blocked_ips 
            WHERE expires_at IS NULL OR expires_at > ?
        ''', (current_time,))
        stats['active_blocks'] = cursor.fetchone()[0]
        
        # Blocks by type
        cursor = conn.execute('''
            SELECT block_type, COUNT(*) FROM blocked_ips 
            WHERE blocked_since >= ?
            GROUP BY block_type
        ''', (start_time,))
        stats['blocks_by_type'] = dict(cursor.fetchall())
        
        # Auto vs manual blocks
        cursor = conn.execute('''
            SELECT 
                SUM(CASE WHEN block_type = 'automatic' THEN 1 ELSE 0 END) as auto_blocks,
                SUM(CASE WHEN block_type != 'automatic' THEN 1 ELSE 0 END) as manual_blocks
            FROM blocked_ips 
            WHERE blocked_since >= ?
        ''', (start_time,))
        
        result = cursor.fetchone()
        stats['auto_blocks'] = result[0] or 0
        stats['manual_blocks'] = result[1] or 0
        
        # Whitelist entries
        cursor = conn.execute('SELECT COUNT(*) FROM whitelist')
        stats['whitelist_entries'] = cursor.fetchone()[0]
        
        # Block timeline
        timeline = []
        for i in range(24):
            hour_start = start_time + (i * 3600)
            hour_end = hour_start + 3600
            
            cursor = conn.execute('''
                SELECT COUNT(*) FROM blocked_ips 
                WHERE blocked_since >= ? AND blocked_since < ?
            ''', (hour_start, hour_end))
            
            count = cursor.fetchone()[0]
            timeline.append({
                'timestamp': hour_start,
                'count': count,
                'hour': datetime.fromtimestamp(hour_start).strftime('%H:00')
            })
        
        stats['block_timeline'] = timeline
        
        conn.close()
        return stats
        
    except Exception as e:
        return {'error': f'Failed to get blocking stats: {e}'}

def get_geo_stats(period='24h'):
    """Get geographic statistics for threats"""
    if not os.path.exists(DB_FILE):
        return {'error': 'Database not found'}
    
    try:
        import geoip2.database
        
        # Load GeoIP database
        try:
            geoip_reader = geoip2.database.Reader('/usr/local/share/GeoIP/GeoLite2-Country.mmdb')
        except:
            return {'error': 'GeoIP database not available'}
        
        conn = sqlite3.connect(DB_FILE)
        
        # Calculate time range
        if period == '24h':
            start_time = int(time.time() - 86400)
        elif period == '7d':
            start_time = int(time.time() - 604800)
        else:
            start_time = int(time.time() - 86400)
        
        # Get unique source IPs from threats
        cursor = conn.execute('''
            SELECT DISTINCT source_ip FROM threats 
            WHERE timestamp >= ?
        ''', (start_time,))
        
        ips = [row[0] for row in cursor.fetchall()]
        
        # Resolve countries
        countries = {}
        for ip in ips:
            try:
                response = geoip_reader.country(ip)
                country_code = response.country.iso_code
                country_name = response.country.name
                
                if country_code not in countries:
                    countries[country_code] = {
                        'name': country_name,
                        'code': country_code,
                        'count': 0
                    }
                countries[country_code]['count'] += 1
                
            except:
                # Unknown/private IP
                if 'unknown' not in countries:
                    countries['unknown'] = {
                        'name': 'Unknown',
                        'code': 'unknown',
                        'count': 0
                    }
                countries['unknown']['count'] += 1
        
        # Sort by count
        top_countries = sorted(countries.values(), key=lambda x: x['count'], reverse=True)[:10]
        
        stats = {
            'countries': list(countries.values()),
            'total_countries': len(countries),
            'top_countries': top_countries
        }
        
        conn.close()
        geoip_reader.close()
        return stats
        
    except Exception as e:
        return {'error': f'Failed to get geo stats: {e}'}

def main():
    if len(sys.argv) > 1:
        stat_type = sys.argv[1]
        period = sys.argv[2] if len(sys.argv) > 2 else '24h'
        
        if stat_type == 'engine':
            stats = get_engine_stats()
        elif stat_type == 'threats':
            stats = get_threat_stats(period)
        elif stat_type == 'blocking':
            stats = get_blocking_stats(period)
        elif stat_type == 'geo':
            stats = get_geo_stats(period)
        else:
            stats = get_engine_stats()
    else:
        stats = get_engine_stats()
    
    print(json.dumps(stats))

if __name__ == '__main__':
    main()