#!/usr/local/bin/python3
"""
DeepInspector Industrial Protocol Statistics Analyzer - Object-Oriented Version
-------------------------------------------------------------------------------
Analyzes and collects comprehensive statistics for industrial protocol traffic
and security events from the DeepInspector DPI engine using a robust
object-oriented architecture for enhanced maintainability and extensibility.

Features:
- Modular statistics collection with specialized analyzer classes
- Real-time industrial protocol monitoring (Modbus, DNP3, OPC UA, etc.)
- Time-based alert analysis with configurable time windows
- Protocol distribution analytics and threat correlation
- SCADA-specific security event tracking and classification
- Latency monitoring for industrial network performance
- JSON-based statistics export with structured data format
- Graceful error handling with detailed logging capabilities
- Abstract base pattern for extensible analyzer architecture

Author: Pierpaolo Casati
Version: 1.0.0
"""

import os
import json
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
from abc import ABC, abstractmethod


class StatisticsError(Exception):
    """Custom exception for statistics collection errors"""
    pass


class StatisticsAnalyzer(ABC):
    """Abstract base class for statistics analyzers"""
    
    @abstractmethod
    def analyze(self, data: Any) -> Dict[str, Any]:
        """Analyze data and return statistics"""
        pass


class IndustrialStatsAnalyzer(StatisticsAnalyzer):
    """Analyzer for industrial protocol statistics"""
    
    def __init__(self):
        """Initialize industrial statistics analyzer"""
        self.supported_protocols = {
            'modbus': 'modbus_packets',
            'dnp3': 'dnp3_packets', 
            'opcua': 'opcua_packets',
            'iec61850': 'iec61850_packets',
            'ethernetip': 'ethernetip_packets'
        }
    
    def analyze(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze industrial statistics data
        
        Args:
            data: Raw statistics data from stats file
            
        Returns:
            Dict containing processed industrial statistics
        """
        industrial_stats = data.get('industrial_stats', {})
        
        stats = {
            'timestamp': datetime.now().isoformat(),
            'modbus_packets': industrial_stats.get('modbus_packets', 0),
            'dnp3_packets': industrial_stats.get('dnp3_packets', 0),
            'opcua_packets': industrial_stats.get('opcua_packets', 0),
            'scada_alerts': industrial_stats.get('scada_alerts', 0),
            'plc_communications': industrial_stats.get('plc_communications', 0),
            'industrial_threats': 0,
            'avg_latency': industrial_stats.get('avg_latency', 0),
            'protocol_distribution': {}
        }
        
        return stats


class AlertAnalyzer(StatisticsAnalyzer):
    """Analyzer for security alert processing"""
    
    def __init__(self, time_window_hours: int = 24):
        """
        Initialize alert analyzer
        
        Args:
            time_window_hours: Time window for alert analysis in hours
        """
        self.time_window_hours = time_window_hours
        self.cutoff_time = datetime.now() - timedelta(hours=time_window_hours)
    
    def analyze(self, alert_log_path: str) -> Dict[str, Any]:
        """
        Analyze alerts from log file
        
        Args:
            alert_log_path: Path to alert log file
            
        Returns:
            Dict containing alert analysis results
        """
        stats = {
            'industrial_threats': 0,
            'scada_alerts': 0,
            'protocol_distribution': {},
            'threat_timeline': [],
            'severity_distribution': {}
        }
        
        if not os.path.exists(alert_log_path):
            return stats
        
        try:
            with open(alert_log_path, 'r') as f:
                for line in f:
                    alert_data = self._parse_alert_line(line.strip())
                    if alert_data and self._is_recent_alert(alert_data):
                        self._process_alert(alert_data, stats)
        except IOError as e:
            raise StatisticsError(f"Error reading alert log: {e}")
        
        return stats
    
    def _parse_alert_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse a single alert log line"""
        try:
            return json.loads(line) if line.strip() else None
        except json.JSONDecodeError:
            return None
    
    def _is_recent_alert(self, alert: Dict[str, Any]) -> bool:
        """Check if alert is within the time window"""
        try:
            alert_time = datetime.fromisoformat(alert.get('timestamp', ''))
            return alert_time > self.cutoff_time
        except (ValueError, TypeError):
            return False
    
    def _process_alert(self, alert: Dict[str, Any], stats: Dict[str, Any]) -> None:
        """Process a single alert and update statistics"""
        # Count industrial threats
        if alert.get('industrial_context', False):
            stats['industrial_threats'] += 1
            
            # Add to timeline
            stats['threat_timeline'].append({
                'timestamp': alert.get('timestamp'),
                'threat_type': alert.get('threat_type', 'unknown'),
                'protocol': alert.get('industrial_protocol', 'unknown')
            })
        
        # Count SCADA alerts
        threat_type = alert.get('threat_type', '').lower()
        if 'scada' in threat_type:
            stats['scada_alerts'] += 1
        
        # Count by protocol
        protocol = alert.get('industrial_protocol', '')
        if protocol:
            stats['protocol_distribution'][protocol] = \
                stats['protocol_distribution'].get(protocol, 0) + 1
        
        # Count by severity
        severity = alert.get('severity', 'unknown')
        stats['severity_distribution'][severity] = \
            stats['severity_distribution'].get(severity, 0) + 1


class ProtocolAnalyzer(StatisticsAnalyzer):
    """Analyzer for protocol-specific analysis"""
    
    def __init__(self):
        """Initialize protocol analyzer"""
        self.protocol_metrics = {
            'modbus': ['function_codes', 'register_access', 'exceptions'],
            'dnp3': ['data_objects', 'control_operations', 'authentication'],
            'opcua': ['service_calls', 'subscriptions', 'security_events']
        }
    
    def analyze(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze protocol-specific metrics
        
        Args:
            data: Protocol data for analysis
            
        Returns:
            Dict containing protocol analysis results
        """
        analysis = {
            'protocol_health': {},
            'performance_metrics': {},
            'security_indicators': {}
        }
        
        for protocol, metrics in self.protocol_metrics.items():
            protocol_data = data.get(f'{protocol}_data', {})
            analysis['protocol_health'][protocol] = self._analyze_protocol_health(
                protocol, protocol_data, metrics
            )
        
        return analysis
    
    def _analyze_protocol_health(self, protocol: str, data: Dict[str, Any], 
                                metrics: List[str]) -> Dict[str, Any]:
        """Analyze health metrics for a specific protocol"""
        health = {
            'status': 'healthy',
            'packet_count': data.get('packet_count', 0),
            'error_rate': data.get('error_rate', 0),
            'last_seen': data.get('last_seen', None)
        }
        
        # Determine health status based on metrics
        if health['error_rate'] > 0.1:  # 10% error rate threshold
            health['status'] = 'degraded'
        elif health['packet_count'] == 0:
            health['status'] = 'inactive'
        
        return health


class StatisticsCollector:
    """Main statistics collector orchestrating all analyzers"""
    
    def __init__(self, stats_file: str = "/var/log/deepinspector/stats.json",
                 alert_log: str = "/var/log/deepinspector/alerts.log"):
        """
        Initialize statistics collector
        
        Args:
            stats_file: Path to statistics file
            alert_log: Path to alert log file
        """
        self.stats_file = stats_file
        self.alert_log = alert_log
        
        # Initialize analyzers
        self.industrial_analyzer = IndustrialStatsAnalyzer()
        self.alert_analyzer = AlertAnalyzer()
        self.protocol_analyzer = ProtocolAnalyzer()
    
    def get_industrial_stats(self) -> Dict[str, Any]:
        """
        Get comprehensive industrial protocol statistics
        
        Returns:
            Dict containing complete industrial statistics
        """
        try:
            # Load current stats
            current_stats = self._load_current_stats()
            
            # Analyze industrial statistics
            industrial_stats = self.industrial_analyzer.analyze(current_stats)
            
            # Analyze alerts
            alert_stats = self.alert_analyzer.analyze(self.alert_log)
            
            # Merge alert statistics into industrial stats
            industrial_stats.update({
                'industrial_threats': alert_stats['industrial_threats'],
                'scada_alerts': alert_stats['scada_alerts'],
                'protocol_distribution': alert_stats['protocol_distribution'],
                'threat_timeline': alert_stats['threat_timeline'][-10:],  # Last 10 threats
                'severity_distribution': alert_stats['severity_distribution']
            })
            
            # Add protocol analysis
            protocol_analysis = self.protocol_analyzer.analyze(current_stats)
            industrial_stats['protocol_analysis'] = protocol_analysis
            
            return industrial_stats
            
        except Exception as e:
            return {
                'error': str(e),
                'timestamp': datetime.now().isoformat(),
                'collector_status': 'error'
            }
    
    def _load_current_stats(self) -> Dict[str, Any]:
        """Load current statistics from file"""
        if not os.path.exists(self.stats_file):
            return {}
        
        try:
            with open(self.stats_file, 'r') as f:
                return json.load(f)
        except (IOError, json.JSONDecodeError) as e:
            raise StatisticsError(f"Error loading stats file: {e}")
    
    def get_stats_summary(self) -> Dict[str, Any]:
        """
        Get a summary of statistics collection status
        
        Returns:
            Dict containing collection status and basic metrics
        """
        summary = {
            'stats_file_exists': os.path.exists(self.stats_file),
            'alert_log_exists': os.path.exists(self.alert_log),
            'last_collection': datetime.now().isoformat(),
            'analyzers_active': len([self.industrial_analyzer, self.alert_analyzer, 
                                   self.protocol_analyzer])
        }
        
        if summary['stats_file_exists']:
            try:
                stats = self._load_current_stats()
                summary['total_protocols'] = len(stats.get('industrial_stats', {}))
                summary['last_update'] = stats.get('timestamp', 'unknown')
            except Exception:
                summary['stats_file_error'] = True
        
        return summary
    
    def set_alert_time_window(self, hours: int) -> None:
        """
        Set the time window for alert analysis
        
        Args:
            hours: Time window in hours
        """
        self.alert_analyzer = AlertAnalyzer(time_window_hours=hours)


def main():
    """Main function to run the statistics collection"""
    collector = StatisticsCollector()
    
    # Show collection summary
    summary = collector.get_stats_summary()
    print("Statistics Collection Summary:")
    print(f"  - Stats file exists: {summary['stats_file_exists']}")
    print(f"  - Alert log exists: {summary['alert_log_exists']}")
    print(f"  - Active analyzers: {summary['analyzers_active']}")
    if 'total_protocols' in summary:
        print(f"  - Tracked protocols: {summary['total_protocols']}")
    print()
    
    # Get and display industrial statistics
    stats = collector.get_industrial_stats()
    print(json.dumps(stats, indent=2))


if __name__ == "__main__":
    main()