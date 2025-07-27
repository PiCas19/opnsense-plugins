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
    """Get geographic statistics using BOTH IP2Location AND GeoLite2 for maximum coverage"""
    if not os.path.exists(DB_FILE):
        return {'error': 'Database not found'}

    try:
        import geoip2.database
        import ipaddress
    except ImportError:
        return {'error': 'geoip2 module not installed. Run: pip install geoip2'}

    # Define both database paths
    databases = {
        'ip2location': '/usr/local/share/GeoIP/IP2LOCATION-LITE-DB1.MMDB',
        'geolite2': '/usr/local/share/GeoIP/GeoLite2-Country.mmdb'
    }
    
    readers = {}
    sources_loaded = []
    
    # Load IP2Location
    if os.path.exists(databases['ip2location']):
        try:
            readers['ip2location'] = geoip2.database.Reader(databases['ip2location'])
            sources_loaded.append('IP2Location-LITE-DB1')
            print(f"✓ Loaded IP2Location: {databases['ip2location']}", file=sys.stderr)
        except Exception as e:
            print(f"✗ Failed to load IP2Location: {e}", file=sys.stderr)
    
    # Load GeoLite2
    if os.path.exists(databases['geolite2']):
        try:
            readers['geolite2'] = geoip2.database.Reader(databases['geolite2'])
            sources_loaded.append('GeoLite2-Country')
            print(f"✓ Loaded GeoLite2: {databases['geolite2']}", file=sys.stderr)
        except Exception as e:
            print(f"✗ Failed to load GeoLite2: {e}", file=sys.stderr)
    
    if not readers:
        return {'error': 'Neither IP2Location nor GeoLite2 databases could be loaded'}

    print(f"Using databases: {', '.join(sources_loaded)}", file=sys.stderr)

    def get_country_from_ip(ip):
        """Get country using both databases - IP2Location first, then GeoLite2 fallback"""
        try:
            # Validate IP
            ip_obj = ipaddress.ip_address(ip)
            
            # Skip private/local IPs
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast:
                return None, None, 'private'
            
            country_name = None
            country_code = None
            source_used = None
            
            # Strategy 1: Try IP2Location first (often more accurate for Asian countries)
            if 'ip2location' in readers:
                try:
                    response = readers['ip2location'].country(ip)
                    
                    # IP2Location field access
                    country_name = getattr(response.country, 'name', None)
                    country_code = getattr(response.country, 'iso_code', None)
                    
                    # Clean IP2Location data
                    if country_name and country_name.strip() and country_name != '-':
                        country_name = country_name.strip()
                        country_code = country_code.strip().upper() if country_code else 'XX'
                        source_used = 'IP2Location'
                        return country_name, country_code, source_used
                    
                except geoip2.errors.AddressNotFoundError:
                    pass  # Try next database
                except Exception as e:
                    print(f"IP2Location error for {ip}: {e}", file=sys.stderr)
            
            # Strategy 2: Try GeoLite2 if IP2Location didn't find it
            if 'geolite2' in readers and not country_name:
                try:
                    response = readers['geolite2'].country(ip)
                    
                    # GeoLite2 field access
                    country_name = response.country.name
                    country_code = response.country.iso_code
                    
                    if country_name and country_name.strip():
                        country_name = country_name.strip()
                        country_code = country_code.strip().upper() if country_code else 'XX'
                        source_used = 'GeoLite2'
                        return country_name, country_code, source_used
                    
                except geoip2.errors.AddressNotFoundError:
                    pass  # Not found in either database
                except Exception as e:
                    print(f"GeoLite2 error for {ip}: {e}", file=sys.stderr)
            
            # If neither database found the IP
            return 'Other', 'XX', 'not_found'
            
        except ValueError:
            # Invalid IP address
            return None, None, 'invalid'
        except Exception as e:
            print(f"General error processing {ip}: {e}", file=sys.stderr)
            return 'Other', 'XX', 'error'

    try:
        conn = sqlite3.connect(DB_FILE)

        # Calculate time range
        if period == '24h':
            start_time = int(time.time() - 86400)
        elif period == '7d':
            start_time = int(time.time() - 604800)
        elif period == '30d':
            start_time = int(time.time() - 2592000)
        else:
            start_time = int(time.time() - 86400)

        # Get threats grouped by IP
        cursor = conn.execute('''
            SELECT source_ip, COUNT(*) as threat_count FROM threats 
            WHERE timestamp >= ? AND source_ip IS NOT NULL AND source_ip != ''
            GROUP BY source_ip
        ''', (start_time,))
        
        ip_counts = cursor.fetchall()
        conn.close()

        if not ip_counts:
            # Close readers before returning
            for reader in readers.values():
                reader.close()
            return {
                'countries': [],
                'total_countries': 0,
                'total_threats': 0,
                'top_countries': [],
                'sources': sources_loaded,
                'message': 'No threat data found'
            }

        countries = {}
        total_threats = 0
        
        # Statistics tracking
        stats_counter = {
            'processed': 0,
            'IP2Location': 0,
            'GeoLite2': 0,
            'not_found': 0,
            'private': 0,
            'invalid': 0,
            'error': 0
        }
        
        print(f"Processing {len(ip_counts)} unique IPs using dual database lookup...", file=sys.stderr)
        
        for ip, threat_count in ip_counts:
            stats_counter['processed'] += 1
            
            if stats_counter['processed'] % 500 == 0:
                print(f"Progress: {stats_counter['processed']}/{len(ip_counts)} IPs", file=sys.stderr)
            
            country_name, country_code, source = get_country_from_ip(ip)
            
            # Update statistics
            if source in stats_counter:
                stats_counter[source] += 1
            
            # Skip private/invalid IPs
            if country_name is None:
                continue
            
            # Aggregate country data
            if country_name not in countries:
                countries[country_name] = {
                    'name': country_name,
                    'code': country_code,
                    'count': 0,
                    'unique_ips': 0
                }
            
            countries[country_name]['count'] += threat_count
            countries[country_name]['unique_ips'] += 1
            total_threats += threat_count

        # Calculate percentages
        for country in countries.values():
            if total_threats > 0:
                country['percentage'] = round((country['count'] / total_threats) * 100, 1)
            else:
                country['percentage'] = 0

        # Sort by threat count
        sorted_countries = sorted(countries.values(), key=lambda x: x['count'], reverse=True)
        
        # Calculate success rates
        public_ips = stats_counter['processed'] - stats_counter['private'] - stats_counter['invalid']
        resolved_ips = stats_counter['IP2Location'] + stats_counter['GeoLite2']
        resolution_rate = round((resolved_ips / max(public_ips, 1)) * 100, 1)
        
        print(f"Resolution Summary:", file=sys.stderr)
        print(f"  Total IPs: {stats_counter['processed']}", file=sys.stderr)
        print(f"  IP2Location hits: {stats_counter['IP2Location']}", file=sys.stderr)
        print(f"  GeoLite2 hits: {stats_counter['GeoLite2']}", file=sys.stderr)
        print(f"  Not found: {stats_counter['not_found']}", file=sys.stderr)
        print(f"  Resolution rate: {resolution_rate}%", file=sys.stderr)

        result = {
            'countries': sorted_countries,
            'total_countries': len(countries),
            'total_threats': total_threats,
            'top_countries': sorted_countries[:10],
            'sources': sources_loaded,
            'database_type': 'Dual (IP2Location + GeoLite2)',
            'statistics': {
                'total_ips_processed': stats_counter['processed'],
                'ip2location_hits': stats_counter['IP2Location'],
                'geolite2_hits': stats_counter['GeoLite2'],
                'not_found': stats_counter['not_found'],
                'private_ips_skipped': stats_counter['private'],
                'resolution_rate_percent': resolution_rate
            },
            'coverage': {
                'primary_source': 'IP2Location',
                'fallback_source': 'GeoLite2',
                'combined_coverage': resolution_rate
            }
        }
        
        # Close all database readers
        for reader in readers.values():
            reader.close()
            
        return result

    except Exception as e:
        # Ensure all readers are closed on error
        for reader in readers.values():
            try:
                reader.close()
            except:
                pass
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