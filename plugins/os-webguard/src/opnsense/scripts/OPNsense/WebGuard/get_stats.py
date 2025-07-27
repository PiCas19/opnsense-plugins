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
    """DEBUG VERSION - Get geographic statistics with detailed IP analysis"""
    if not os.path.exists(DB_FILE):
        return {'error': 'Database not found'}

    try:
        import geoip2.database
        import ipaddress
    except ImportError:
        return {'error': 'geoip2 module not installed. Run: pip install geoip2'}

    # Load databases
    databases = {
        'ip2location': '/usr/local/share/GeoIP/IP2LOCATION-LITE-DB1.MMDB',
        'geolite2': '/usr/local/share/GeoIP/GeoLite2-Country.mmdb'
    }
    
    readers = {}
    
    # Load IP2Location
    if os.path.exists(databases['ip2location']):
        try:
            readers['ip2location'] = geoip2.database.Reader(databases['ip2location'])
            print(f"✓ Loaded IP2Location", file=sys.stderr)
        except Exception as e:
            print(f"✗ Failed IP2Location: {e}", file=sys.stderr)
    
    # Load GeoLite2
    if os.path.exists(databases['geolite2']):
        try:
            readers['geolite2'] = geoip2.database.Reader(databases['geolite2'])
            print(f"✓ Loaded GeoLite2", file=sys.stderr)
        except Exception as e:
            print(f"✗ Failed GeoLite2: {e}", file=sys.stderr)

    def debug_ip_classification(ip):
        """Debug function to understand IP classification"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            print(f"DEBUG IP {ip}:", file=sys.stderr)
            print(f"  - is_private: {ip_obj.is_private}", file=sys.stderr)
            print(f"  - is_loopback: {ip_obj.is_loopback}", file=sys.stderr)
            print(f"  - is_link_local: {ip_obj.is_link_local}", file=sys.stderr)
            print(f"  - is_multicast: {ip_obj.is_multicast}", file=sys.stderr)
            print(f"  - is_reserved: {ip_obj.is_reserved}", file=sys.stderr)
            print(f"  - is_global: {ip_obj.is_global}", file=sys.stderr)
            
            # Check if it's actually a public IP
            if ip_obj.is_global and not ip_obj.is_private:
                print(f"  - Classification: PUBLIC IP", file=sys.stderr)
                return True
            else:
                print(f"  - Classification: PRIVATE/LOCAL IP", file=sys.stderr)
                return False
                
        except Exception as e:
            print(f"  - Error classifying {ip}: {e}", file=sys.stderr)
            return False

    def get_country_from_ip(ip):
        """Get country with detailed debugging"""
        print(f"\n=== Processing IP: {ip} ===", file=sys.stderr)
        
        # First check if it's a valid public IP
        if not debug_ip_classification(ip):
            return None, None, 'private'
        
        # Now try the databases
        country_name = None
        country_code = None
        
        # Try IP2Location
        if 'ip2location' in readers:
            try:
                print(f"Trying IP2Location for {ip}...", file=sys.stderr)
                response = readers['ip2location'].country(ip)
                
                print(f"IP2Location raw response: {response}", file=sys.stderr)
                print(f"Response country: {response.country}", file=sys.stderr)
                print(f"Country name: {getattr(response.country, 'name', 'NO NAME')}", file=sys.stderr)
                print(f"Country code: {getattr(response.country, 'iso_code', 'NO CODE')}", file=sys.stderr)
                
                country_name = getattr(response.country, 'name', None)
                country_code = getattr(response.country, 'iso_code', None)
                
                if country_name and country_name != '-':
                    print(f"✓ IP2Location SUCCESS: {ip} -> {country_name} ({country_code})", file=sys.stderr)
                    return country_name.strip(), country_code.strip() if country_code else 'XX', 'IP2Location'
                else:
                    print(f"IP2Location returned empty/dash for {ip}", file=sys.stderr)
                    
            except Exception as e:
                print(f"IP2Location error for {ip}: {e}", file=sys.stderr)
        
        # Try GeoLite2
        if 'geolite2' in readers:
            try:
                print(f"Trying GeoLite2 for {ip}...", file=sys.stderr)
                response = readers['geolite2'].country(ip)
                
                print(f"GeoLite2 raw response: {response}", file=sys.stderr)
                country_name = response.country.name
                country_code = response.country.iso_code
                
                if country_name:
                    print(f"✓ GeoLite2 SUCCESS: {ip} -> {country_name} ({country_code})", file=sys.stderr)
                    return country_name.strip(), country_code.strip() if country_code else 'XX', 'GeoLite2'
                else:
                    print(f"GeoLite2 returned empty for {ip}", file=sys.stderr)
                    
            except Exception as e:
                print(f"GeoLite2 error for {ip}: {e}", file=sys.stderr)
        
        print(f"✗ FAILED: No database could resolve {ip}", file=sys.stderr)
        return 'Other', 'XX', 'not_found'

    try:
        conn = sqlite3.connect(DB_FILE)

        if period == '24h':
            start_time = int(time.time() - 86400)
        else:
            start_time = int(time.time() - 86400)

        # Get SAMPLE of IPs for debugging (first 10)
        cursor = conn.execute('''
            SELECT source_ip, COUNT(*) as threat_count FROM threats 
            WHERE timestamp >= ? AND source_ip IS NOT NULL AND source_ip != ''
            GROUP BY source_ip
            LIMIT 10
        ''', (start_time,))
        
        ip_counts = cursor.fetchall()
        conn.close()

        print(f"\n=== DEBUGGING {len(ip_counts)} SAMPLE IPs ===", file=sys.stderr)
        
        countries = {}
        total_threats = 0
        stats_counter = {'processed': 0, 'IP2Location': 0, 'GeoLite2': 0, 'not_found': 0, 'private': 0}
        
        for ip, threat_count in ip_counts:
            print(f"\n--- Processing IP {ip} (threats: {threat_count}) ---", file=sys.stderr)
            
            country_name, country_code, source = get_country_from_ip(ip)
            
            stats_counter['processed'] += 1
            if source in stats_counter:
                stats_counter[source] += 1
            
            if country_name is None:
                print(f"SKIPPED: {ip} (private)", file=sys.stderr)
                continue
            
            if country_name not in countries:
                countries[country_name] = {'name': country_name, 'code': country_code, 'count': 0, 'unique_ips': 0}
            
            countries[country_name]['count'] += threat_count
            countries[country_name]['unique_ips'] += 1
            total_threats += threat_count
            
            print(f"ADDED: {ip} -> {country_name} ({source})", file=sys.stderr)

        print(f"\n=== FINAL DEBUG RESULTS ===", file=sys.stderr)
        print(f"Countries found: {list(countries.keys())}", file=sys.stderr)
        print(f"Stats: {stats_counter}", file=sys.stderr)

        # Calculate percentages
        for country in countries.values():
            if total_threats > 0:
                country['percentage'] = round((country['count'] / total_threats) * 100, 1)
            else:
                country['percentage'] = 0

        result = {
            'countries': list(countries.values()),
            'total_countries': len(countries),
            'total_threats': total_threats,
            'top_countries': list(countries.values()),
            'sources': ['IP2Location-LITE-DB1', 'GeoLite2-Country'],
            'debug_stats': stats_counter,
            'sample_size': len(ip_counts)
        }
        
        # Close readers
        for reader in readers.values():
            reader.close()
            
        return result

    except Exception as e:
        for reader in readers.values():
            try:
                reader.close()
            except:
                pass
        return {'error': f'Debug failed: {e}'}

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