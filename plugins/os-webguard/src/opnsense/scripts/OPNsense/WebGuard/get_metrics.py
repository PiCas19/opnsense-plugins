#!/usr/local/bin/python3.11

"""
WebGuard System Metrics Script
Copyright (C) 2024 OPNsense WebGuard Plugin
All rights reserved.
"""

import sys
import json
import os
import time
from datetime import datetime

def get_metrics():
    """Get comprehensive system and WebGuard metrics"""
    try:
        metrics = {
            'system': {},
            'webguard': {},
            'network': {},
            'performance': {}
        }
        
        # System metrics
        try:
            import psutil
            
            # CPU usage
            metrics['system']['cpu_usage'] = psutil.cpu_percent(interval=1)
            
            # Memory usage
            memory = psutil.virtual_memory()
            metrics['system']['memory_usage'] = memory.percent
            metrics['system']['memory_total'] = memory.total
            metrics['system']['memory_available'] = memory.available
            
            # Disk usage
            disk = psutil.disk_usage('/')
            metrics['system']['disk_usage'] = round((disk.used / disk.total) * 100, 2)
            metrics['system']['disk_total'] = disk.total
            metrics['system']['disk_free'] = disk.free
            
            # Load average
            load_avg = os.getloadavg()
            metrics['system']['load_avg'] = {
                '1min': load_avg[0],
                '5min': load_avg[1],
                '15min': load_avg[2]
            }
            
            # System uptime
            boot_time = psutil.boot_time()
            metrics['system']['uptime'] = int(time.time() - boot_time)
            
        except ImportError:
            # Fallback without psutil
            try:
                # Get load average
                with open('/proc/loadavg', 'r') as f:
                    load_data = f.read().strip().split()
                    metrics['system']['load_avg'] = {
                        '1min': float(load_data[0]),
                        '5min': float(load_data[1]),
                        '15min': float(load_data[2])
                    }
            except:
                pass
            
            try:
                # Get memory info
                with open('/proc/meminfo', 'r') as f:
                    meminfo = {}
                    for line in f:
                        key, value = line.split(':', 1)
                        meminfo[key.strip()] = int(value.strip().split()[0]) * 1024  # Convert to bytes
                    
                    total = meminfo.get('MemTotal', 0)
                    free = meminfo.get('MemFree', 0) + meminfo.get('Buffers', 0) + meminfo.get('Cached', 0)
                    used = total - free
                    
                    metrics['system']['memory_total'] = total
                    metrics['system']['memory_available'] = free
                    metrics['system']['memory_usage'] = round((used / total) * 100, 2) if total > 0 else 0
            except:
                pass
        
        # WebGuard process metrics
        try:
            import psutil
            webguard_process = None
            
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'cpu_percent', 'memory_percent', 'create_time']):
                try:
                    if 'web_guard_engine.py' in ' '.join(proc.info['cmdline'] or []):
                        webguard_process = proc
                        break
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            if webguard_process:
                metrics['webguard']['status'] = 'running'
                metrics['webguard']['pid'] = webguard_process.pid
                metrics['webguard']['cpu_usage'] = webguard_process.cpu_percent()
                metrics['webguard']['memory_usage'] = webguard_process.memory_percent()
                metrics['webguard']['uptime'] = int(time.time() - webguard_process.create_time())
                
                # Memory details
                memory_info = webguard_process.memory_info()
                metrics['webguard']['memory_rss'] = memory_info.rss
                metrics['webguard']['memory_vms'] = memory_info.vms
                
                # Thread count
                metrics['webguard']['thread_count'] = webguard_process.num_threads()
                
                # File descriptors
                try:
                    metrics['webguard']['open_files'] = len(webguard_process.open_files())
                except:
                    metrics['webguard']['open_files'] = 0
                
            else:
                metrics['webguard']['status'] = 'stopped'
                
        except ImportError:
            # Check if process is running without psutil
            try:
                result = subprocess.run(['pgrep', '-f', 'web_guard_engine.py'], 
                                      capture_output=True, text=True)
                if result.returncode == 0:
                    metrics['webguard']['status'] = 'running'
                    metrics['webguard']['pid'] = int(result.stdout.strip().split('\n')[0])
                else:
                    metrics['webguard']['status'] = 'stopped'
            except:
                metrics['webguard']['status'] = 'unknown'
        
        # Network interface metrics
        try:
            import psutil
            
            net_io = psutil.net_io_counters(pernic=True)
            interface_stats = {}
            
            for interface, stats in net_io.items():
                # Skip loopback
                if interface.startswith('lo'):
                    continue
                    
                interface_stats[interface] = {
                    'bytes_sent': stats.bytes_sent,
                    'bytes_recv': stats.bytes_recv,
                    'packets_sent': stats.packets_sent,
                    'packets_recv': stats.packets_recv,
                    'errors_in': stats.errin,
                    'errors_out': stats.errout,
                    'drops_in': stats.dropin,
                    'drops_out': stats.dropout
                }
            
            metrics['network']['interfaces'] = interface_stats
            
            # Network connections
            connections = psutil.net_connections()
            metrics['network']['active_connections'] = len([c for c in connections if c.status == 'ESTABLISHED'])
            metrics['network']['listening_ports'] = len([c for c in connections if c.status == 'LISTEN'])
            
        except ImportError:
            # Fallback network stats
            try:
                result = subprocess.run(['netstat', '-i'], capture_output=True, text=True)
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\n')[1:]  # Skip header
                    interface_stats = {}
                    
                    for line in lines:
                        if line.strip():
                            parts = line.split()
                            if len(parts) >= 10:
                                interface = parts[0]
                                if not interface.startswith('lo'):
                                    interface_stats[interface] = {
                                        'packets_recv': int(parts[4]) if parts[4].isdigit() else 0,
                                        'packets_sent': int(parts[7]) if parts[7].isdigit() else 0
                                    }
                    
                    metrics['network']['interfaces'] = interface_stats
            except:
                pass
        
        # Performance metrics
        try:
            # Database file size
            db_file = '/var/db/webguard/webguard.db'
            if os.path.exists(db_file):
                metrics['performance']['database_size'] = os.path.getsize(db_file)
            
            # Log file sizes
            log_dir = '/var/log/webguard'
            if os.path.exists(log_dir):
                total_log_size = 0
                log_files = {}
                
                for filename in os.listdir(log_dir):
                    filepath = os.path.join(log_dir, filename)
                    if os.path.isfile(filepath):
                        size = os.path.getsize(filepath)
                        log_files[filename] = size
                        total_log_size += size
                
                metrics['performance']['log_files'] = log_files
                metrics['performance']['total_log_size'] = total_log_size
            
            # Configuration file timestamps
            config_files = {
                'main_config': '/usr/local/etc/webguard/config.json',
                'waf_rules': '/usr/local/etc/webguard/waf_rules.json',
                'attack_patterns': '/usr/local/etc/webguard/attack_patterns.json'
            }
            
            config_info = {}
            for name, path in config_files.items():
                if os.path.exists(path):
                    stat = os.stat(path)
                    config_info[name] = {
                        'size': stat.st_size,
                        'modified': int(stat.st_mtime),
                        'modified_iso': datetime.fromtimestamp(stat.st_mtime).isoformat()
                    }
            
            metrics['performance']['config_files'] = config_info
            
        except Exception as e:
            metrics['performance']['error'] = str(e)
        
        # Disk I/O stats
        try:
            import psutil
            
            disk_io = psutil.disk_io_counters()
            if disk_io:
                metrics['performance']['disk_io'] = {
                    'read_count': disk_io.read_count,
                    'write_count': disk_io.write_count,
                    'read_bytes': disk_io.read_bytes,
                    'write_bytes': disk_io.write_bytes,
                    'read_time': disk_io.read_time,
                    'write_time': disk_io.write_time
                }
                
        except:
            pass
        
        # System temperature (if available)
        try:
            import psutil
            
            temps = psutil.sensors_temperatures()
            if temps:
                temp_data = {}
                for name, entries in temps.items():
                    temp_data[name] = []
                    for entry in entries:
                        temp_data[name].append({
                            'label': entry.label or 'Unknown',
                            'current': entry.current,
                            'high': entry.high,
                            'critical': entry.critical
                        })
                metrics['system']['temperatures'] = temp_data
                
        except:
            pass
        
        # WebGuard specific performance
        try:
            # Check packet capture performance
            stats_file = '/var/log/webguard/stats.json'
            if os.path.exists(stats_file):
                with open(stats_file, 'r') as f:
                    webguard_stats = json.load(f)
                    
                    metrics['webguard']['requests_analyzed'] = webguard_stats.get('requests_analyzed', 0)
                    metrics['webguard']['threats_blocked'] = webguard_stats.get('threats_blocked', 0)
                    metrics['webguard']['ips_blocked'] = webguard_stats.get('ips_blocked', 0)
                    
                    # Calculate processing rate
                    uptime = webguard_stats.get('performance', {}).get('uptime', 0)
                    if uptime > 0:
                        requests = webguard_stats.get('requests_analyzed', 0)
                        metrics['webguard']['processing_rate'] = round(requests / uptime, 2)
                    else:
                        metrics['webguard']['processing_rate'] = 0
                        
        except Exception as e:
            metrics['webguard']['stats_error'] = str(e)
        
        # Network latency test
        try:
            # Ping test to localhost
            result = subprocess.run(['ping', '-c', '1', '127.0.0.1'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                # Extract latency from ping output
                for line in result.stdout.split('\n'):
                    if 'time=' in line:
                        import re
                        match = re.search(r'time=(\d+\.?\d*)', line)
                        if match:
                            metrics['network']['localhost_latency'] = float(match.group(1))
                            break
        except:
            pass
        
        # File system info
        try:
            import subprocess
            
            # Get filesystem info for webguard directories
            directories = ['/var/log/webguard', '/var/db/webguard', '/usr/local/etc/webguard']
            fs_info = {}
            
            for directory in directories:
                if os.path.exists(directory):
                    result = subprocess.run(['df', '-h', directory], 
                                          capture_output=True, text=True)
                    if result.returncode == 0:
                        lines = result.stdout.strip().split('\n')
                        if len(lines) > 1:
                            parts = lines[1].split()
                            if len(parts) >= 6:
                                fs_info[directory] = {
                                    'filesystem': parts[0],
                                    'size': parts[1],
                                    'used': parts[2],
                                    'available': parts[3],
                                    'use_percent': parts[4],
                                    'mount_point': parts[5]
                                }
            
            metrics['performance']['filesystem'] = fs_info
            
        except:
            pass
        
        # Add timestamp
        metrics['timestamp'] = datetime.now().isoformat()
        metrics['collection_time'] = int(time.time())
        
        return metrics
        
    except Exception as e:
        return {'error': f'Failed to collect metrics: {e}'}

def get_system_health():
    """Get system health status"""
    health = {
        'status': 'unknown',
        'issues': [],
        'warnings': []
    }
    
    try:
        metrics = get_metrics()
        
        # Check CPU usage
        cpu_usage = metrics.get('system', {}).get('cpu_usage', 0)
        if cpu_usage > 90:
            health['issues'].append(f'High CPU usage: {cpu_usage}%')
        elif cpu_usage > 75:
            health['warnings'].append(f'Elevated CPU usage: {cpu_usage}%')
        
        # Check memory usage
        memory_usage = metrics.get('system', {}).get('memory_usage', 0)
        if memory_usage > 95:
            health['issues'].append(f'Critical memory usage: {memory_usage}%')
        elif memory_usage > 80:
            health['warnings'].append(f'High memory usage: {memory_usage}%')
        
        # Check disk usage
        disk_usage = metrics.get('system', {}).get('disk_usage', 0)
        if disk_usage > 95:
            health['issues'].append(f'Critical disk usage: {disk_usage}%')
        elif disk_usage > 85:
            health['warnings'].append(f'High disk usage: {disk_usage}%')
        
        # Check WebGuard status
        webguard_status = metrics.get('webguard', {}).get('status', 'unknown')
        if webguard_status != 'running':
            health['issues'].append('WebGuard engine is not running')
        
        # Check load average
        load_avg = metrics.get('system', {}).get('load_avg', {})
        load_1min = load_avg.get('1min', 0)
        if load_1min > 4:
            health['issues'].append(f'High system load: {load_1min}')
        elif load_1min > 2:
            health['warnings'].append(f'Elevated system load: {load_1min}')
        
        # Determine overall status
        if health['issues']:
            health['status'] = 'critical'
        elif health['warnings']:
            health['status'] = 'warning'
        else:
            health['status'] = 'healthy'
        
        health['timestamp'] = datetime.now().isoformat()
        
    except Exception as e:
        health['status'] = 'error'
        health['error'] = str(e)
    
    return health

def main():
    if len(sys.argv) > 1:
        if sys.argv[1] == 'health':
            result = get_system_health()
        else:
            result = get_metrics()
    else:
        result = get_metrics()
    
    print(json.dumps(result, indent=2))

if __name__ == '__main__':
    main()