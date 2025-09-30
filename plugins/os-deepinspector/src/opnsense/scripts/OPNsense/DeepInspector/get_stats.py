#!/usr/local/bin/python3
"""
DeepInspector DPI Engine Statistics Collector - Object-Oriented Version
-----------------------------------------------------------------------
Comprehensive statistics collection and analysis system for DeepInspector
DPI engine with real-time threat monitoring, trend analysis, and performance
metrics specifically designed for industrial network security environments.

Features:
- Multi-dimensional statistics collection with specialized analyzers
- Real-time threat detection monitoring with severity classification
- Industrial protocol statistics (Modbus, DNP3, OPC UA, SCADA)
- Performance metrics aggregation with trend analysis
- Threat intelligence correlation and pattern detection
- Alert classification and severity distribution analysis
- Historical data trending with configurable time windows
- Top threat identification and recent threat tracking

Author: Pierpaolo Casati
Version: 1.0.0
"""

import os
import json
from datetime import datetime, timedelta
from typing import Dict, Any, List, Tuple
from abc import ABC, abstractmethod
from collections import defaultdict, Counter
from dataclasses import dataclass


class StatisticsCollectionError(Exception):
    """Custom exception for statistics collection errors"""
    pass


@dataclass
class AlertEntry:
    """Data class for alert information"""
    timestamp: str
    threat_type: str
    severity: str
    source_ip: str
    destination_ip: str
    protocol: str
    description: str
    industrial_context: bool = False


@dataclass
class ThreatSummary:
    """Data class for threat summary information"""
    threat_type: str
    count: int
    severity_distribution: Dict[str, int]
    first_seen: str
    last_seen: str
    trending: str  # 'up', 'down', 'stable'


class StatisticsCollector(ABC):
    """Abstract base class for statistics collectors"""
    
    @abstractmethod
    def collect(self, data: Any) -> Dict[str, Any]:
        """Collect statistics from provided data"""
        pass
    
    @abstractmethod
    def get_collector_info(self) -> Dict[str, Any]:
        """Get collector information and capabilities"""
        pass


class PacketStatisticsCollector(StatisticsCollector):
    """Collector for packet and protocol statistics"""
    
    def __init__(self):
        """Initialize packet statistics collector"""
        self.supported_protocols = {
            'tcp', 'udp', 'icmp', 'http', 'https', 'ftp', 'smtp', 
            'dns', 'modbus', 'dnp3', 'opcua', 'iec61850'
        }
    
    def collect(self, stats_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Collect packet and protocol statistics
        
        Args:
            stats_data: Raw statistics data from stats file
            
        Returns:
            Dict containing packet analysis statistics
        """
        packet_stats = {
            'packets_analyzed': stats_data.get('packets_analyzed', 0),
            'total_bytes_processed': stats_data.get('total_bytes_processed', 0),
            'protocols': {},
            'protocol_distribution': {},
            'inspection_rates': {},
            'processing_efficiency': {}
        }
        
        # Extract protocol statistics
        protocols_data = stats_data.get('protocols_analyzed', {})
        total_packets = packet_stats['packets_analyzed']
        
        for protocol in self.supported_protocols:
            protocol_count = protocols_data.get(protocol, 0)
            packet_stats['protocols'][protocol] = protocol_count
            
            # Calculate protocol distribution percentage
            if total_packets > 0:
                packet_stats['protocol_distribution'][protocol] = (
                    protocol_count / total_packets
                ) * 100
        
        # Calculate inspection rates
        packet_stats['inspection_rates'] = self._calculate_inspection_rates(stats_data)
        
        # Calculate processing efficiency
        packet_stats['processing_efficiency'] = self._calculate_processing_efficiency(stats_data)
        
        return packet_stats
    
    def _calculate_inspection_rates(self, stats_data: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate inspection rates and throughput metrics"""
        return {
            'packets_per_second': stats_data.get('packet_rate', 0),
            'bytes_per_second': stats_data.get('byte_rate', 0),
            'inspection_depth_avg': stats_data.get('avg_inspection_depth', 0),
            'deep_inspection_ratio': stats_data.get('deep_inspection_ratio', 0)
        }
    
    def _calculate_processing_efficiency(self, stats_data: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate processing efficiency metrics"""
        processed = stats_data.get('packets_analyzed', 0)
        dropped = stats_data.get('packets_dropped', 0)
        total = processed + dropped
        
        return {
            'processing_success_rate': (processed / total) * 100 if total > 0 else 100,
            'packet_drop_rate': (dropped / total) * 100 if total > 0 else 0,
            'queue_utilization': stats_data.get('queue_utilization', 0),
            'buffer_efficiency': stats_data.get('buffer_efficiency', 0)
        }
    
    def get_collector_info(self) -> Dict[str, Any]:
        """Get packet statistics collector information"""
        return {
            'collector_type': 'packet',
            'supported_protocols': list(self.supported_protocols),
            'capabilities': ['protocol_analysis', 'throughput_calculation', 'efficiency_metrics']
        }


class ThreatStatisticsCollector(StatisticsCollector):
    """Collector for threat detection statistics"""
    
    def __init__(self):
        """Initialize threat statistics collector"""
        self.severity_levels = ['critical', 'high', 'medium', 'low']
        self.threat_categories = {
            'malware', 'intrusion', 'data_exfiltration', 'command_injection',
            'sql_injection', 'script_injection', 'crypto_mining', 'botnet',
            'phishing', 'scada_threat', 'industrial_anomaly'
        }
    
    def collect(self, stats_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Collect threat detection statistics
        
        Args:
            stats_data: Raw statistics data from stats file
            
        Returns:
            Dict containing threat analysis statistics
        """
        threat_stats = {
            'threats_detected': stats_data.get('threats_detected', 0),
            'false_positives': stats_data.get('false_positives', 0),
            'critical_alerts': stats_data.get('critical_alerts', 0),
            'threats_by_severity': self._initialize_severity_counters(),
            'threats_by_category': {},
            'detection_accuracy': {},
            'threat_trends': {}
        }
        
        # Update severity counters from stats
        severity_data = stats_data.get('threats_by_severity', {})
        for severity in self.severity_levels:
            threat_stats['threats_by_severity'][severity] = severity_data.get(severity, 0)
        
        # Calculate detection accuracy
        threat_stats['detection_accuracy'] = self._calculate_detection_accuracy(
            threat_stats['threats_detected'], 
            threat_stats['false_positives']
        )
        
        # Extract category statistics if available
        category_data = stats_data.get('threats_by_category', {})
        for category in self.threat_categories:
            threat_stats['threats_by_category'][category] = category_data.get(category, 0)
        
        return threat_stats
    
    def _initialize_severity_counters(self) -> Dict[str, int]:
        """Initialize severity counters"""
        return {severity: 0 for severity in self.severity_levels}
    
    def _calculate_detection_accuracy(self, detected: int, false_positives: int) -> Dict[str, Any]:
        """Calculate threat detection accuracy metrics"""
        total_alerts = detected + false_positives
        
        return {
            'true_positive_rate': (detected / total_alerts) * 100 if total_alerts > 0 else 0,
            'false_positive_rate': (false_positives / total_alerts) * 100 if total_alerts > 0 else 0,
            'precision': detected / total_alerts if total_alerts > 0 else 0,
            'alert_quality_score': (detected / total_alerts) * 100 if total_alerts > 0 else 100
        }
    
    def get_collector_info(self) -> Dict[str, Any]:
        """Get threat statistics collector information"""
        return {
            'collector_type': 'threat',
            'severity_levels': self.severity_levels,
            'threat_categories': list(self.threat_categories),
            'capabilities': ['severity_analysis', 'accuracy_calculation', 'trend_detection']
        }


class IndustrialStatisticsCollector(StatisticsCollector):
    """Collector for industrial protocol statistics"""
    
    def __init__(self):
        """Initialize industrial statistics collector"""
        self.industrial_protocols = {
            'modbus': 'modbus_packets',
            'dnp3': 'dnp3_packets',
            'opcua': 'opcua_packets',
            'iec61850': 'iec61850_packets',
            'ethernet_ip': 'ethernet_ip_packets'
        }
    
    def collect(self, stats_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Collect industrial protocol statistics
        
        Args:
            stats_data: Raw statistics data from stats file
            
        Returns:
            Dict containing industrial protocol statistics
        """
        industrial_data = stats_data.get('industrial_stats', {})
        
        industrial_stats = {
            'scada_alerts': industrial_data.get('scada_alerts', 0),
            'avg_latency': industrial_data.get('avg_latency', 0),
            'protocol_health': {},
            'industrial_threats': industrial_data.get('industrial_threats', 0),
            'control_system_events': industrial_data.get('control_system_events', 0),
            'safety_violations': industrial_data.get('safety_violations', 0)
        }
        
        # Collect protocol-specific statistics
        for protocol, stat_key in self.industrial_protocols.items():
            packet_count = industrial_data.get(stat_key, 0)
            industrial_stats[stat_key] = packet_count
            
            # Calculate protocol health metrics
            industrial_stats['protocol_health'][protocol] = self._assess_protocol_health(
                protocol, packet_count, industrial_data
            )
        
        # Calculate industrial performance metrics
        industrial_stats['performance_metrics'] = self._calculate_industrial_performance(
            industrial_data
        )
        
        return industrial_stats
    
    def _assess_protocol_health(self, protocol: str, packet_count: int, 
                               industrial_data: Dict[str, Any]) -> Dict[str, Any]:
        """Assess health of an industrial protocol"""
        error_key = f'{protocol}_errors'
        timeout_key = f'{protocol}_timeouts'
        
        errors = industrial_data.get(error_key, 0)
        timeouts = industrial_data.get(timeout_key, 0)
        
        total_events = packet_count + errors + timeouts
        error_rate = (errors / total_events) * 100 if total_events > 0 else 0
        timeout_rate = (timeouts / total_events) * 100 if total_events > 0 else 0
        
        # Determine health status
        if error_rate > 5 or timeout_rate > 10:
            status = 'critical'
        elif error_rate > 2 or timeout_rate > 5:
            status = 'degraded'
        elif packet_count > 0:
            status = 'healthy'
        else:
            status = 'inactive'
        
        return {
            'status': status,
            'packet_count': packet_count,
            'error_count': errors,
            'timeout_count': timeouts,
            'error_rate_percent': error_rate,
            'timeout_rate_percent': timeout_rate,
            'last_activity': industrial_data.get(f'{protocol}_last_seen', None)
        }
    
    def _calculate_industrial_performance(self, industrial_data: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate industrial network performance metrics"""
        return {
            'real_time_compliance': industrial_data.get('real_time_compliance', 0),
            'deterministic_performance': industrial_data.get('deterministic_performance', 0),
            'jitter_ms': industrial_data.get('jitter_ms', 0),
            'packet_loss_rate': industrial_data.get('packet_loss_rate', 0),
            'control_loop_efficiency': industrial_data.get('control_loop_efficiency', 0)
        }
    
    def get_collector_info(self) -> Dict[str, Any]:
        """Get industrial statistics collector information"""
        return {
            'collector_type': 'industrial',
            'supported_protocols': list(self.industrial_protocols.keys()),
            'capabilities': ['protocol_health', 'performance_analysis', 'safety_monitoring']
        }


class PerformanceStatisticsCollector(StatisticsCollector):
    """Collector for system and engine performance statistics"""
    
    def collect(self, stats_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Collect performance statistics
        
        Args:
            stats_data: Raw statistics data from stats file
            
        Returns:
            Dict containing performance statistics
        """
        performance_data = stats_data.get('performance', {})
        
        performance_stats = {
            'cpu_usage': performance_data.get('cpu_usage', 0),
            'memory_usage': performance_data.get('memory_usage', 0),
            'throughput_mbps': performance_data.get('throughput_mbps', 0),
            'latency_avg': performance_data.get('latency_avg', 0),
            'system_health': self._assess_system_health(performance_data),
            'resource_efficiency': self._calculate_resource_efficiency(performance_data),
            'bottleneck_analysis': self._identify_bottlenecks(performance_data)
        }
        
        return performance_stats
    
    def _assess_system_health(self, performance_data: Dict[str, Any]) -> Dict[str, Any]:
        """Assess overall system health"""
        cpu = performance_data.get('cpu_usage', 0)
        memory = performance_data.get('memory_usage', 0)
        latency = performance_data.get('latency_avg', 0)
        
        # Determine health status
        if cpu > 90 or memory > 90 or latency > 1000:
            status = 'critical'
        elif cpu > 70 or memory > 70 or latency > 500:
            status = 'degraded'
        else:
            status = 'healthy'
        
        return {
            'status': status,
            'cpu_health': 'good' if cpu < 70 else 'poor',
            'memory_health': 'good' if memory < 70 else 'poor',
            'latency_health': 'good' if latency < 100 else 'poor',
            'overall_score': max(0, 100 - max(cpu, memory, min(latency/10, 100)))
        }
    
    def _calculate_resource_efficiency(self, performance_data: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate resource utilization efficiency"""
        throughput = performance_data.get('throughput_mbps', 0)
        cpu = performance_data.get('cpu_usage', 0)
        memory = performance_data.get('memory_usage', 0)
        
        return {
            'throughput_per_cpu': throughput / max(cpu, 1),
            'throughput_per_memory': throughput / max(memory, 1),
            'resource_utilization_ratio': (cpu + memory) / 200,
            'efficiency_score': throughput / max((cpu + memory) / 100, 0.1)
        }
    
    def _identify_bottlenecks(self, performance_data: Dict[str, Any]) -> List[str]:
        """Identify system bottlenecks"""
        bottlenecks = []
        
        cpu = performance_data.get('cpu_usage', 0)
        memory = performance_data.get('memory_usage', 0)
        latency = performance_data.get('latency_avg', 0)
        throughput = performance_data.get('throughput_mbps', 0)
        
        if cpu > 80:
            bottlenecks.append('CPU utilization high')
        if memory > 80:
            bottlenecks.append('Memory utilization high')
        if latency > 500:
            bottlenecks.append('Network latency excessive')
        if throughput < 10:
            bottlenecks.append('Throughput below optimal')
        
        return bottlenecks
    
    def get_collector_info(self) -> Dict[str, Any]:
        """Get performance statistics collector information"""
        return {
            'collector_type': 'performance',
            'capabilities': ['health_assessment', 'efficiency_calculation', 'bottleneck_detection']
        }


class AlertAnalyzer:
    """Analyzer for processing alert logs and trends"""
    
    def __init__(self, time_window_hours: int = 24):
        """
        Initialize alert analyzer
        
        Args:
            time_window_hours: Time window for alert analysis
        """
        self.time_window_hours = time_window_hours
        self.cutoff_time = datetime.now() - timedelta(hours=time_window_hours)
    
    def analyze_alerts(self, alert_log_path: str) -> Dict[str, Any]:
        """
        Analyze alerts from log file
        
        Args:
            alert_log_path: Path to alert log file
            
        Returns:
            Dict containing alert analysis results
        """
        if not os.path.exists(alert_log_path):
            return self._get_empty_alert_analysis()
        
        try:
            alerts = self._load_alerts(alert_log_path)
            
            return {
                'recent_alerts_count': len(alerts),
                'top_threats': self._get_top_threats(alerts),
                'recent_threats': self._get_recent_threats(alerts),
                'severity_distribution': self._analyze_severity_distribution(alerts),
                'threat_trends': self._analyze_threat_trends(alerts),
                'temporal_analysis': self._analyze_temporal_patterns(alerts)
            }
            
        except Exception as e:
            return {'error': f'Alert analysis failed: {e}'}
    
    def _load_alerts(self, alert_log_path: str) -> List[AlertEntry]:
        """Load and parse alerts from log file"""
        alerts = []
        
        with open(alert_log_path, 'r') as f:
            for line in f:
                try:
                    alert_data = json.loads(line.strip())
                    alert_time = datetime.fromisoformat(alert_data.get('timestamp', ''))
                    
                    if alert_time > self.cutoff_time:
                        alert = AlertEntry(
                            timestamp=alert_data.get('timestamp', ''),
                            threat_type=alert_data.get('threat_type', 'unknown'),
                            severity=alert_data.get('severity', 'medium'),
                            source_ip=alert_data.get('source_ip', ''),
                            destination_ip=alert_data.get('destination_ip', ''),
                            protocol=alert_data.get('protocol', ''),
                            description=alert_data.get('description', ''),
                            industrial_context=alert_data.get('industrial_context', False)
                        )
                        alerts.append(alert)
                        
                except (json.JSONDecodeError, ValueError):
                    continue
        
        return alerts
    
    def _get_empty_alert_analysis(self) -> Dict[str, Any]:
        """Return empty alert analysis structure"""
        return {
            'recent_alerts_count': 0,
            'top_threats': [],
            'recent_threats': [],
            'severity_distribution': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
            'threat_trends': {},
            'temporal_analysis': {}
        }
    
    def _get_top_threats(self, alerts: List[AlertEntry]) -> List[Tuple[str, int]]:
        """Get top threat types by count"""
        threat_counts = Counter(alert.threat_type for alert in alerts)
        return threat_counts.most_common(10)
    
    def _get_recent_threats(self, alerts: List[AlertEntry]) -> List[Dict[str, Any]]:
        """Get most recent threats"""
        sorted_alerts = sorted(alerts, key=lambda x: x.timestamp, reverse=True)
        
        recent_threats = []
        for alert in sorted_alerts[:10]:
            recent_threats.append({
                'timestamp': alert.timestamp,
                'threat_type': alert.threat_type,
                'severity': alert.severity,
                'source_ip': alert.source_ip,
                'destination_ip': alert.destination_ip,
                'protocol': alert.protocol,
                'description': alert.description,
                'industrial_context': alert.industrial_context
            })
        
        return recent_threats
    
    def _analyze_severity_distribution(self, alerts: List[AlertEntry]) -> Dict[str, int]:
        """Analyze distribution of alert severities"""
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        
        for alert in alerts:
            if alert.severity in severity_counts:
                severity_counts[alert.severity] += 1
        
        return severity_counts
    
    def _analyze_threat_trends(self, alerts: List[AlertEntry]) -> Dict[str, Any]:
        """Analyze threat trends over time"""
        if not alerts:
            return {}
        
        # Group alerts by hour for trend analysis
        hourly_counts = defaultdict(int)
        threat_type_trends = defaultdict(list)
        
        for alert in alerts:
            try:
                alert_time = datetime.fromisoformat(alert.timestamp)
                hour_key = alert_time.strftime('%Y-%m-%d %H')
                hourly_counts[hour_key] += 1
                threat_type_trends[alert.threat_type].append(alert_time)
            except ValueError:
                continue
        
        return {
            'hourly_trend': dict(hourly_counts),
            'peak_hours': self._identify_peak_hours(hourly_counts),
            'trending_threats': self._identify_trending_threats(threat_type_trends)
        }
    
    def _analyze_temporal_patterns(self, alerts: List[AlertEntry]) -> Dict[str, Any]:
        """Analyze temporal patterns in alerts"""
        if not alerts:
            return {}
        
        hour_distribution = defaultdict(int)
        day_distribution = defaultdict(int)
        
        for alert in alerts:
            try:
                alert_time = datetime.fromisoformat(alert.timestamp)
                hour_distribution[alert_time.hour] += 1
                day_distribution[alert_time.strftime('%A')] += 1
            except ValueError:
                continue
        
        return {
            'hourly_distribution': dict(hour_distribution),
            'daily_distribution': dict(day_distribution),
            'busiest_hour': max(hour_distribution.items(), key=lambda x: x[1])[0] if hour_distribution else None,
            'busiest_day': max(day_distribution.items(), key=lambda x: x[1])[0] if day_distribution else None
        }
    
    def _identify_peak_hours(self, hourly_counts: Dict[str, int]) -> List[str]:
        """Identify peak activity hours"""
        if not hourly_counts:
            return []
        
        avg_count = sum(hourly_counts.values()) / len(hourly_counts)
        peak_hours = [hour for hour, count in hourly_counts.items() if count > avg_count * 1.5]
        
        return sorted(peak_hours)
    
    def _identify_trending_threats(self, threat_type_trends: Dict[str, List]) -> Dict[str, str]:
        """Identify trending threat types"""
        trending = {}
        
        for threat_type, timestamps in threat_type_trends.items():
            if len(timestamps) < 2:
                trending[threat_type] = 'stable'
                continue
            
            # Simple trend analysis based on frequency in first vs second half
            mid_point = len(timestamps) // 2
            first_half = len(timestamps[:mid_point])
            second_half = len(timestamps[mid_point:])
            
            if second_half > first_half * 1.5:
                trending[threat_type] = 'increasing'
            elif first_half > second_half * 1.5:
                trending[threat_type] = 'decreasing'
            else:
                trending[threat_type] = 'stable'
        
        return trending


class DPIStatisticsAggregator:
    """Main aggregator orchestrating all statistics collectors"""
    
    def __init__(self, 
                 stats_file: str = "/var/log/deepinspector/stats.json",
                 alert_log: str = "/var/log/deepinspector/alerts.log",
                 threat_log: str = "/var/log/deepinspector/threats.log"):
        """
        Initialize DPI statistics aggregator
        
        Args:
            stats_file: Path to statistics file
            alert_log: Path to alert log file
            threat_log: Path to threat log file
        """
        self.stats_file = stats_file
        self.alert_log = alert_log
        self.threat_log = threat_log
        
        # Initialize collectors
        self.packet_collector = PacketStatisticsCollector()
        self.threat_collector = ThreatStatisticsCollector()
        self.industrial_collector = IndustrialStatisticsCollector()
        self.performance_collector = PerformanceStatisticsCollector()
        self.alert_analyzer = AlertAnalyzer()
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get comprehensive DPI statistics
        
        Returns:
            Dict containing all collected statistics
        """
        try:
            # Initialize base statistics structure
            stats = {
                'timestamp': datetime.now().isoformat(),
                'collector_status': 'active',
                'data_sources': {
                    'stats_file': os.path.exists(self.stats_file),
                    'alert_log': os.path.exists(self.alert_log),
                    'threat_log': os.path.exists(self.threat_log)
                }
            }
            
            # Load base statistics
            base_stats = self._load_base_statistics()
            
            # Collect packet statistics
            packet_stats = self.packet_collector.collect(base_stats)
            stats.update(packet_stats)
            
            # Collect threat statistics
            threat_stats = self.threat_collector.collect(base_stats)
            stats.update(threat_stats)
            
            # Collect industrial statistics
            industrial_stats = self.industrial_collector.collect(base_stats)
            stats['industrial_stats'] = industrial_stats
            
            # Collect performance statistics
            performance_stats = self.performance_collector.collect(base_stats)
            stats['performance'] = performance_stats
            
            # Analyze alerts
            alert_analysis = self.alert_analyzer.analyze_alerts(self.alert_log)
            stats.update(alert_analysis)
            
            # Add legacy compatibility fields
            self._add_legacy_compatibility(stats, base_stats)
            
            return stats
            
        except Exception as e:
            return {
                'error': str(e),
                'packets_analyzed': 0,
                'threats_detected': 0,
                'timestamp': datetime.now().isoformat(),
                'collector_status': 'error'
            }
    
    def _load_base_statistics(self) -> Dict[str, Any]:
        """Load base statistics from stats file"""
        if not os.path.exists(self.stats_file):
            return {}
        
        try:
            with open(self.stats_file, 'r') as f:
                return json.load(f)
        except (IOError, json.JSONDecodeError):
            return {}
    
    def _add_legacy_compatibility(self, stats: Dict[str, Any], base_stats: Dict[str, Any]) -> None:
        """Add legacy compatibility fields for backward compatibility"""
        # Ensure legacy fields exist
        legacy_fields = {
            'packets_analyzed': 0,
            'threats_detected': 0,
            'false_positives': 0,
            'critical_alerts': 0
        }
        
        for field, default_value in legacy_fields.items():
            if field not in stats:
                stats[field] = base_stats.get(field, default_value)
        
        # Add detection rate trend if not present
        if 'detection_rate_trend' not in stats:
            stats['detection_rate_trend'] = base_stats.get('detection_rate_trend', [])
    
    def get_aggregator_status(self) -> Dict[str, Any]:
        """Get aggregator status and configuration"""
        return {
            'collectors': {
                'packet': self.packet_collector.get_collector_info(),
                'threat': self.threat_collector.get_collector_info(),
                'industrial': self.industrial_collector.get_collector_info(),
                'performance': self.performance_collector.get_collector_info()
            },
            'data_sources': {
                'stats_file': self.stats_file,
                'alert_log': self.alert_log,
                'threat_log': self.threat_log
            },
            'alert_analyzer_window_hours': self.alert_analyzer.time_window_hours,
            'status': 'operational',
            'last_check': datetime.now().isoformat()
        }
    
    def configure_alert_window(self, hours: int) -> None:
        """Configure alert analysis time window"""
        self.alert_analyzer = AlertAnalyzer(time_window_hours=hours)


def main():
    """Main function to run statistics collection"""
    aggregator = DPIStatisticsAggregator()
    
    # Show aggregator status
    status = aggregator.get_aggregator_status()
    print("DPI Statistics Aggregator Status:")
    print(f"  - Packet Collector: {status['collectors']['packet']['collector_type']}")
    print(f"  - Threat Collector: {status['collectors']['threat']['collector_type']}")
    print(f"  - Industrial Collector: {status['collectors']['industrial']['collector_type']}")
    print(f"  - Performance Collector: {status['collectors']['performance']['collector_type']}")
    print(f"  - Alert Analysis Window: {status['alert_analyzer_window_hours']} hours")
    
    # Show data source availability
    print("\nData Source Availability:")
    for source, available in status['data_sources'].items():
        status_text = "✓ Available" if available else "✗ Not Found"
        print(f"  - {source}: {status_text}")
    print()
    
    # Get and display comprehensive statistics
    stats = aggregator.get_stats()
    print(json.dumps(stats, indent=2))


if __name__ == "__main__":
    main()