#!/usr/local/bin/python3
"""
DeepInspector DPI Engine Performance Metrics Collector - Object-Oriented Version
--------------------------------------------------------------------------------
Comprehensive system and application performance monitoring specifically designed
for DeepInspector DPI engine with real-time metrics collection, resource tracking,
and performance analysis tailored for industrial network security applications.

Features:
- Multi-dimensional metrics collection with specialized collectors for each domain
- Real-time system resource monitoring (CPU, memory, disk, load average)
- DPI engine process tracking with detailed performance profiling
- Network interface statistics with error and drop rate analysis
- Process lifecycle management and health monitoring
- Resource utilization trending and threshold alerting
- Performance baseline establishment and deviation detection
- Historical metrics aggregation with rolling window statistics

Author: Pierpaolo Casati
Version: 1.0.0
"""

import os
import json
import subprocess
import psutil
from datetime import datetime
from typing import Dict, Any, Optional, List
from abc import ABC, abstractmethod
from dataclasses import dataclass


class MetricsCollectionError(Exception):
    """Custom exception for metrics collection errors"""
    pass


@dataclass
class ProcessInfo:
    """Data class for process information"""
    pid: int
    name: str
    status: str
    cpu_percent: float
    memory_percent: float
    memory_rss: int
    num_threads: int
    create_time: float
    cmdline: List[str]


class MetricsCollector(ABC):
    """Abstract base class for metrics collectors"""
    
    @abstractmethod
    def collect(self) -> Dict[str, Any]:
        """Collect metrics and return data dictionary"""
        pass
    
    @abstractmethod
    def get_collector_info(self) -> Dict[str, Any]:
        """Get information about the collector"""
        pass


class SystemMetricsCollector(MetricsCollector):
    """Collector for system-wide metrics"""
    
    def __init__(self, cpu_interval: float = 1.0):
        """
        Initialize system metrics collector
        
        Args:
            cpu_interval: CPU measurement interval in seconds
        """
        self.cpu_interval = cpu_interval
    
    def collect(self) -> Dict[str, Any]:
        """
        Collect comprehensive system metrics
        
        Returns:
            Dict containing system performance metrics
        """
        try:
            # CPU metrics with detailed breakdown
            cpu_data = self._collect_cpu_metrics()
            
            # Memory metrics with swap information
            memory_data = self._collect_memory_metrics()
            
            # Disk usage for all mounted filesystems
            disk_data = self._collect_disk_metrics()
            
            # System load and uptime information
            load_data = self._collect_load_metrics()
            
            return {
                'cpu': cpu_data,
                'memory': memory_data,
                'disk': disk_data,
                'load': load_data,
                'boot_time': psutil.boot_time(),
                'users': len(psutil.users())
            }
            
        except Exception as e:
            raise MetricsCollectionError(f"System metrics collection failed: {e}")
    
    def _collect_cpu_metrics(self) -> Dict[str, Any]:
        """Collect detailed CPU metrics"""
        # Overall CPU usage
        cpu_percent = psutil.cpu_percent(interval=self.cpu_interval)
        
        # Per-CPU core usage
        cpu_per_core = psutil.cpu_percent(interval=self.cpu_interval, percpu=True)
        
        # CPU frequency information
        cpu_freq = psutil.cpu_freq()
        
        # CPU count information
        cpu_count_logical = psutil.cpu_count(logical=True)
        cpu_count_physical = psutil.cpu_count(logical=False)
        
        return {
            'usage_percent': cpu_percent,
            'per_core_percent': cpu_per_core,
            'frequency_mhz': cpu_freq.current if cpu_freq else None,
            'frequency_max_mhz': cpu_freq.max if cpu_freq else None,
            'cores_logical': cpu_count_logical,
            'cores_physical': cpu_count_physical,
            'load_1min': os.getloadavg()[0],
            'load_5min': os.getloadavg()[1],
            'load_15min': os.getloadavg()[2]
        }
    
    def _collect_memory_metrics(self) -> Dict[str, Any]:
        """Collect detailed memory metrics"""
        virtual_mem = psutil.virtual_memory()
        swap_mem = psutil.swap_memory()
        
        return {
            'virtual': {
                'total_bytes': virtual_mem.total,
                'available_bytes': virtual_mem.available,
                'used_bytes': virtual_mem.used,
                'free_bytes': virtual_mem.free,
                'percent_used': virtual_mem.percent,
                'buffers_bytes': getattr(virtual_mem, 'buffers', 0),
                'cached_bytes': getattr(virtual_mem, 'cached', 0)
            },
            'swap': {
                'total_bytes': swap_mem.total,
                'used_bytes': swap_mem.used,
                'free_bytes': swap_mem.free,
                'percent_used': swap_mem.percent,
                'sin_bytes': swap_mem.sin,
                'sout_bytes': swap_mem.sout
            }
        }
    
    def _collect_disk_metrics(self) -> Dict[str, Any]:
        """Collect disk usage metrics for all mounted filesystems"""
        disk_data = {}
        
        # Get all disk partitions
        partitions = psutil.disk_partitions()
        
        for partition in partitions:
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                disk_data[partition.mountpoint] = {
                    'device': partition.device,
                    'fstype': partition.fstype,
                    'total_bytes': usage.total,
                    'used_bytes': usage.used,
                    'free_bytes': usage.free,
                    'percent_used': (usage.used / usage.total) * 100 if usage.total > 0 else 0
                }
            except (PermissionError, FileNotFoundError):
                # Skip partitions we can't access
                continue
        
        # Add disk I/O statistics
        try:
            disk_io = psutil.disk_io_counters()
            if disk_io:
                disk_data['io_counters'] = {
                    'read_count': disk_io.read_count,
                    'write_count': disk_io.write_count,
                    'read_bytes': disk_io.read_bytes,
                    'write_bytes': disk_io.write_bytes,
                    'read_time': disk_io.read_time,
                    'write_time': disk_io.write_time
                }
        except Exception:
            pass
        
        return disk_data
    
    def _collect_load_metrics(self) -> Dict[str, Any]:
        """Collect system load metrics"""
        load_avg = os.getloadavg()
        
        return {
            'load_average': list(load_avg),
            'load_1min': load_avg[0],
            'load_5min': load_avg[1],
            'load_15min': load_avg[2],
            'uptime_seconds': (datetime.now().timestamp() - psutil.boot_time())
        }
    
    def get_collector_info(self) -> Dict[str, Any]:
        """Get system metrics collector information"""
        return {
            'collector_type': 'system',
            'cpu_interval': self.cpu_interval,
            'capabilities': ['cpu', 'memory', 'disk', 'load', 'uptime'],
            'platform': psutil.LINUX if hasattr(psutil, 'LINUX') else 'unknown'
        }


class EngineMetricsCollector(MetricsCollector):
    """Collector for DPI engine specific metrics"""
    
    def __init__(self, engine_name: str = 'deepinspector_engine'):
        """
        Initialize engine metrics collector
        
        Args:
            engine_name: Name or pattern to identify the DPI engine process
        """
        self.engine_name = engine_name
        self.process_manager = ProcessManager()
    
    def collect(self) -> Dict[str, Any]:
        """
        Collect DPI engine performance metrics
        
        Returns:
            Dict containing engine-specific metrics
        """
        try:
            engine_process = self._find_engine_process()
            
            if not engine_process:
                return {
                    'status': 'not_running',
                    'discovery_method': 'process_scan',
                    'search_pattern': self.engine_name
                }
            
            # Collect detailed process metrics
            process_metrics = self._collect_process_metrics(engine_process)
            
            # Add engine-specific analysis
            engine_analysis = self._analyze_engine_performance(process_metrics)
            
            return {
                'status': 'running',
                'process': process_metrics,
                'analysis': engine_analysis,
                'discovery_method': 'process_scan'
            }
            
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e),
                'discovery_method': 'process_scan'
            }
    
    def _find_engine_process(self) -> Optional[ProcessInfo]:
        """Find the DPI engine process"""
        # Try pgrep first (faster)
        pid = self._find_process_by_pgrep()
        if pid:
            try:
                return self.process_manager.get_process_info(pid)
            except psutil.NoSuchProcess:
                pass
        
        # Fall back to process scanning
        return self.process_manager.find_process_by_name(self.engine_name)
    
    def _find_process_by_pgrep(self) -> Optional[int]:
        """Find process using pgrep command"""
        try:
            result = subprocess.run(['pgrep', '-f', self.engine_name],
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0 and result.stdout.strip():
                return int(result.stdout.strip().split('\n')[0])
        except (subprocess.TimeoutExpired, ValueError, FileNotFoundError):
            pass
        return None
    
    def _collect_process_metrics(self, process_info: ProcessInfo) -> Dict[str, Any]:
        """Collect detailed metrics for the engine process"""
        try:
            process = psutil.Process(process_info.pid)
            
            # Get memory details
            memory_info = process.memory_info()
            memory_full = process.memory_full_info()
            
            # Get I/O statistics if available
            io_counters = None
            try:
                io_counters = process.io_counters()
            except (psutil.AccessDenied, AttributeError):
                pass
            
            # Get file descriptors count if available
            num_fds = None
            try:
                num_fds = process.num_fds()
            except (psutil.AccessDenied, AttributeError):
                pass
            
            return {
                'pid': process_info.pid,
                'name': process_info.name,
                'status': process_info.status,
                'cpu_percent': process.cpu_percent(),
                'memory_percent': process.memory_percent(),
                'memory': {
                    'rss_bytes': memory_info.rss,
                    'vms_bytes': memory_info.vms,
                    'shared_bytes': getattr(memory_info, 'shared', 0),
                    'text_bytes': getattr(memory_info, 'text', 0),
                    'data_bytes': getattr(memory_info, 'data', 0),
                    'uss_bytes': getattr(memory_full, 'uss', 0),
                    'pss_bytes': getattr(memory_full, 'pss', 0)
                },
                'threads': {
                    'count': process.num_threads(),
                    'details': [{'id': t.id, 'user_time': t.user_time, 'system_time': t.system_time} 
                               for t in process.threads()]
                },
                'create_time': process_info.create_time,
                'cmdline': process_info.cmdline,
                'io_counters': {
                    'read_count': io_counters.read_count if io_counters else 0,
                    'write_count': io_counters.write_count if io_counters else 0,
                    'read_bytes': io_counters.read_bytes if io_counters else 0,
                    'write_bytes': io_counters.write_bytes if io_counters else 0
                },
                'file_descriptors': num_fds,
                'runtime_seconds': datetime.now().timestamp() - process_info.create_time
            }
            
        except psutil.NoSuchProcess:
            raise MetricsCollectionError("Engine process disappeared during metrics collection")
    
    def _analyze_engine_performance(self, process_metrics: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze engine performance and provide insights"""
        analysis = {
            'health_status': 'healthy',
            'performance_indicators': {},
            'resource_efficiency': {},
            'alerts': []
        }
        
        # CPU analysis
        cpu_percent = process_metrics.get('cpu_percent', 0)
        if cpu_percent > 80:
            analysis['alerts'].append('High CPU usage detected')
            analysis['health_status'] = 'degraded'
        
        # Memory analysis
        memory_percent = process_metrics.get('memory_percent', 0)
        if memory_percent > 75:
            analysis['alerts'].append('High memory usage detected')
            analysis['health_status'] = 'degraded'
        
        # Thread analysis
        thread_count = process_metrics.get('threads', {}).get('count', 0)
        if thread_count > 100:
            analysis['alerts'].append('High thread count detected')
        
        # Performance indicators
        analysis['performance_indicators'] = {
            'cpu_efficiency': 'high' if cpu_percent < 50 else 'medium' if cpu_percent < 80 else 'low',
            'memory_efficiency': 'high' if memory_percent < 50 else 'medium' if memory_percent < 75 else 'low',
            'thread_efficiency': 'optimal' if thread_count < 50 else 'acceptable' if thread_count < 100 else 'high'
        }
        
        return analysis
    
    def get_collector_info(self) -> Dict[str, Any]:
        """Get engine metrics collector information"""
        return {
            'collector_type': 'engine',
            'engine_name': self.engine_name,
            'capabilities': ['process_metrics', 'performance_analysis', 'health_monitoring']
        }


class NetworkMetricsCollector(MetricsCollector):
    """Collector for network interface metrics"""
    
    def __init__(self, include_loopback: bool = False):
        """
        Initialize network metrics collector
        
        Args:
            include_loopback: Whether to include loopback interfaces
        """
        self.include_loopback = include_loopback
    
    def collect(self) -> Dict[str, Any]:
        """
        Collect network interface statistics
        
        Returns:
            Dict containing network metrics for all interfaces
        """
        try:
            # Get network I/O counters per interface
            net_stats = psutil.net_io_counters(pernic=True)
            
            # Get network addresses for context
            net_addresses = psutil.net_if_addrs()
            
            # Get interface status
            net_status = psutil.net_if_stats()
            
            network_data = {}
            
            for interface, stats in net_stats.items():
                # Skip loopback if not requested
                if not self.include_loopback and interface.startswith(('lo', 'loopback')):
                    continue
                
                interface_data = self._collect_interface_metrics(
                    interface, stats, net_addresses, net_status
                )
                network_data[interface] = interface_data
            
            # Add global network summary
            network_data['_summary'] = self._calculate_network_summary(network_data)
            
            return network_data
            
        except Exception as e:
            raise MetricsCollectionError(f"Network metrics collection failed: {e}")
    
    def _collect_interface_metrics(self, interface: str, stats: Any, 
                                 addresses: Dict, status: Dict) -> Dict[str, Any]:
        """Collect metrics for a single network interface"""
        interface_data = {
            'counters': {
                'bytes_sent': stats.bytes_sent,
                'bytes_recv': stats.bytes_recv,
                'packets_sent': stats.packets_sent,
                'packets_recv': stats.packets_recv,
                'errin': stats.errin,
                'errout': stats.errout,
                'dropin': stats.dropin,
                'dropout': stats.dropout
            },
            'rates': self._calculate_interface_rates(stats),
            'health': self._assess_interface_health(stats),
            'addresses': [],
            'status': {}
        }
        
        # Add address information
        if interface in addresses:
            for addr in addresses[interface]:
                interface_data['addresses'].append({
                    'family': str(addr.family),
                    'address': addr.address,
                    'netmask': getattr(addr, 'netmask', None),
                    'broadcast': getattr(addr, 'broadcast', None)
                })
        
        # Add status information
        if interface in status:
            stat = status[interface]
            interface_data['status'] = {
                'is_up': stat.isup,
                'duplex': str(stat.duplex),
                'speed_mbps': stat.speed,
                'mtu': stat.mtu
            }
        
        return interface_data
    
    def _calculate_interface_rates(self, stats: Any) -> Dict[str, float]:
        """Calculate rates and ratios for interface statistics"""
        total_bytes = stats.bytes_sent + stats.bytes_recv
        total_packets = stats.packets_sent + stats.packets_recv
        total_errors = stats.errin + stats.errout
        total_drops = stats.dropin + stats.dropout
        
        return {
            'error_rate': (total_errors / total_packets) * 100 if total_packets > 0 else 0,
            'drop_rate': (total_drops / total_packets) * 100 if total_packets > 0 else 0,
            'avg_packet_size': total_bytes / total_packets if total_packets > 0 else 0
        }
    
    def _assess_interface_health(self, stats: Any) -> Dict[str, Any]:
        """Assess the health of a network interface"""
        total_packets = stats.packets_sent + stats.packets_recv
        total_errors = stats.errin + stats.errout
        total_drops = stats.dropin + stats.dropout
        
        error_rate = (total_errors / total_packets) * 100 if total_packets > 0 else 0
        drop_rate = (total_drops / total_packets) * 100 if total_packets > 0 else 0
        
        health_status = 'healthy'
        issues = []
        
        if error_rate > 1.0:  # More than 1% error rate
            health_status = 'degraded'
            issues.append(f'High error rate: {error_rate:.2f}%')
        
        if drop_rate > 0.5:  # More than 0.5% drop rate
            health_status = 'degraded'
            issues.append(f'High drop rate: {drop_rate:.2f}%')
        
        return {
            'status': health_status,
            'error_rate_percent': error_rate,
            'drop_rate_percent': drop_rate,
            'issues': issues
        }
    
    def _calculate_network_summary(self, network_data: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate summary statistics across all interfaces"""
        total_bytes_sent = 0
        total_bytes_recv = 0
        total_packets_sent = 0
        total_packets_recv = 0
        total_errors = 0
        total_drops = 0
        interface_count = 0
        
        for interface, data in network_data.items():
            if interface.startswith('_'):  # Skip summary entries
                continue
            
            counters = data.get('counters', {})
            total_bytes_sent += counters.get('bytes_sent', 0)
            total_bytes_recv += counters.get('bytes_recv', 0)
            total_packets_sent += counters.get('packets_sent', 0)
            total_packets_recv += counters.get('packets_recv', 0)
            total_errors += counters.get('errin', 0) + counters.get('errout', 0)
            total_drops += counters.get('dropin', 0) + counters.get('dropout', 0)
            interface_count += 1
        
        total_packets = total_packets_sent + total_packets_recv
        
        return {
            'interface_count': interface_count,
            'total_bytes_sent': total_bytes_sent,
            'total_bytes_recv': total_bytes_recv,
            'total_packets_sent': total_packets_sent,
            'total_packets_recv': total_packets_recv,
            'total_errors': total_errors,
            'total_drops': total_drops,
            'overall_error_rate': (total_errors / total_packets) * 100 if total_packets > 0 else 0,
            'overall_drop_rate': (total_drops / total_packets) * 100 if total_packets > 0 else 0
        }
    
    def get_collector_info(self) -> Dict[str, Any]:
        """Get network metrics collector information"""
        return {
            'collector_type': 'network',
            'include_loopback': self.include_loopback,
            'capabilities': ['interface_stats', 'health_assessment', 'rate_calculation']
        }


class ProcessManager:
    """Utility class for process management and discovery"""
    
    def get_process_info(self, pid: int) -> ProcessInfo:
        """
        Get detailed information about a process
        
        Args:
            pid: Process ID
            
        Returns:
            ProcessInfo object with detailed process information
        """
        try:
            process = psutil.Process(pid)
            
            return ProcessInfo(
                pid=process.pid,
                name=process.name(),
                status=process.status(),
                cpu_percent=process.cpu_percent(),
                memory_percent=process.memory_percent(),
                memory_rss=process.memory_info().rss,
                num_threads=process.num_threads(),
                create_time=process.create_time(),
                cmdline=process.cmdline()
            )
            
        except psutil.NoSuchProcess:
            raise psutil.NoSuchProcess(pid)
    
    def find_process_by_name(self, name_pattern: str) -> Optional[ProcessInfo]:
        """
        Find process by name pattern
        
        Args:
            name_pattern: Pattern to match against process names or command lines
            
        Returns:
            ProcessInfo for the first matching process, or None if not found
        """
        for process in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                process_info = process.info
                
                # Check process name
                if name_pattern in process_info['name']:
                    return self.get_process_info(process_info['pid'])
                
                # Check command line
                cmdline = ' '.join(process_info['cmdline'] or [])
                if name_pattern in cmdline:
                    return self.get_process_info(process_info['pid'])
                    
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        return None


class PerformanceMetricsAggregator:
    """Main aggregator orchestrating all metrics collectors"""
    
    def __init__(self, engine_name: str = 'deepinspector_engine'):
        """
        Initialize performance metrics aggregator
        
        Args:
            engine_name: Name pattern for DPI engine process discovery
        """
        self.system_collector = SystemMetricsCollector()
        self.engine_collector = EngineMetricsCollector(engine_name)
        self.network_collector = NetworkMetricsCollector()
    
    def get_metrics(self) -> Dict[str, Any]:
        """
        Get comprehensive performance metrics
        
        Returns:
            Dict containing all collected metrics
        """
        try:
            metrics = {
                'timestamp': datetime.now().isoformat(),
                'collector_status': 'active',
                'system': {},
                'engine': {},
                'network': {}
            }
            
            # Collect system metrics
            try:
                metrics['system'] = self.system_collector.collect()
            except MetricsCollectionError as e:
                metrics['system'] = {'error': str(e)}
            
            # Collect engine metrics
            try:
                metrics['engine'] = self.engine_collector.collect()
            except Exception as e:
                metrics['engine'] = {'error': str(e), 'status': 'error'}
            
            # Collect network metrics
            try:
                metrics['network'] = self.network_collector.collect()
            except MetricsCollectionError as e:
                metrics['network'] = {'error': str(e)}
            
            return metrics
            
        except Exception as e:
            return {
                'error': str(e),
                'timestamp': datetime.now().isoformat(),
                'collector_status': 'error'
            }
    
    def get_aggregator_status(self) -> Dict[str, Any]:
        """Get aggregator status and configuration"""
        return {
            'collectors': {
                'system': self.system_collector.get_collector_info(),
                'engine': self.engine_collector.get_collector_info(),
                'network': self.network_collector.get_collector_info()
            },
            'status': 'operational',
            'last_check': datetime.now().isoformat()
        }
    
    def configure_collectors(self, **kwargs) -> None:
        """Configure collectors with custom parameters"""
        if 'cpu_interval' in kwargs:
            self.system_collector = SystemMetricsCollector(cpu_interval=kwargs['cpu_interval'])
        
        if 'engine_name' in kwargs:
            self.engine_collector = EngineMetricsCollector(engine_name=kwargs['engine_name'])
        
        if 'include_loopback' in kwargs:
            self.network_collector = NetworkMetricsCollector(include_loopback=kwargs['include_loopback'])


def main():
    """Main function to run metrics collection"""
    aggregator = PerformanceMetricsAggregator()
    
    # Show aggregator status
    status = aggregator.get_aggregator_status()
    print("Performance Metrics Aggregator Status:")
    print(f"  - System Collector: {status['collectors']['system']['collector_type']}")
    print(f"  - Engine Collector: {status['collectors']['engine']['collector_type']}")
    print(f"  - Network Collector: {status['collectors']['network']['collector_type']}")
    print()
    
    # Get and display metrics
    metrics = aggregator.get_metrics()
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()