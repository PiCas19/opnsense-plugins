#!/usr/local/bin/python3
"""
DeepInspector Industrial Latency Metrics Analyzer - Object-Oriented Version
---------------------------------------------------------------------------
Analyzes and monitors network latency metrics specifically optimized for
industrial environments where microsecond precision and real-time response
are critical for operational safety and efficiency.

Features:
- Real-time latency monitoring with configurable time windows
- Industrial-grade threshold analysis with multi-level impact assessment
- Statistical distribution analysis with histogram generation
- Violation tracking and alerting for critical latency breaches
- Trend analysis and predictive indicators for proactive maintenance
- Protocol-specific latency profiling for industrial communications
- Performance degradation detection with root cause indicators
- Historical data aggregation with rolling window statistics

Author: Pierpaolo Casati
Version: 1.0.0
"""

import os
import json
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from abc import ABC, abstractmethod
from statistics import mean, median, stdev


class LatencyAnalysisError(Exception):
    """Custom exception for latency analysis errors"""
    pass


class LatencyAnalyzer(ABC):
    """Abstract base class for latency analyzers"""
    
    @abstractmethod
    def analyze(self, data: Any) -> Dict[str, Any]:
        """Analyze latency data and return metrics"""
        pass


class RealTimeLatencyAnalyzer(LatencyAnalyzer):
    """Analyzer for real-time latency metrics processing"""
    
    def __init__(self, time_window_hours: int = 1):
        """
        Initialize real-time latency analyzer
        
        Args:
            time_window_hours: Time window for analysis in hours
        """
        self.time_window_hours = time_window_hours
        self.cutoff_time = datetime.now() - timedelta(hours=time_window_hours)
    
    def analyze(self, latency_data: List[float]) -> Dict[str, Any]:
        """
        Analyze real-time latency data
        
        Args:
            latency_data: List of latency measurements in microseconds
            
        Returns:
            Dict containing real-time latency analysis
        """
        if not latency_data:
            return self._get_empty_metrics()
        
        metrics = {
            'avg_latency': mean(latency_data),
            'max_latency': max(latency_data),
            'min_latency': min(latency_data),
            'median_latency': median(latency_data),
            'sample_count': len(latency_data),
            'time_window_hours': self.time_window_hours
        }
        
        # Add standard deviation if we have enough samples
        if len(latency_data) > 1:
            metrics['std_deviation'] = stdev(latency_data)
            metrics['coefficient_variation'] = metrics['std_deviation'] / metrics['avg_latency']
        else:
            metrics['std_deviation'] = 0
            metrics['coefficient_variation'] = 0
        
        # Calculate percentiles
        sorted_data = sorted(latency_data)
        metrics['p95_latency'] = self._calculate_percentile(sorted_data, 0.95)
        metrics['p99_latency'] = self._calculate_percentile(sorted_data, 0.99)
        
        return metrics
    
    def _get_empty_metrics(self) -> Dict[str, Any]:
        """Return empty metrics structure"""
        return {
            'avg_latency': 0,
            'max_latency': 0,
            'min_latency': 0,
            'median_latency': 0,
            'std_deviation': 0,
            'coefficient_variation': 0,
            'p95_latency': 0,
            'p99_latency': 0,
            'sample_count': 0,
            'time_window_hours': self.time_window_hours
        }
    
    def _calculate_percentile(self, sorted_data: List[float], percentile: float) -> float:
        """Calculate percentile value from sorted data"""
        if not sorted_data:
            return 0
        index = int(percentile * (len(sorted_data) - 1))
        return sorted_data[index]


class ThresholdAnalyzer(LatencyAnalyzer):
    """Analyzer for industrial threshold violation detection"""
    
    def __init__(self, custom_thresholds: Optional[Dict[str, float]] = None):
        """
        Initialize threshold analyzer
        
        Args:
            custom_thresholds: Custom threshold definitions in microseconds
        """
        self.thresholds = custom_thresholds or {
            'critical': 1000,  # 1ms
            'high': 500,      # 500μs
            'medium': 100,    # 100μs
            'low': 50         # 50μs
        }
    
    def analyze(self, latency_data: List[float]) -> Dict[str, Any]:
        """
        Analyze threshold violations
        
        Args:
            latency_data: List of latency measurements
            
        Returns:
            Dict containing threshold analysis results
        """
        violations = {
            'total_samples': len(latency_data),
            'violations_by_level': {},
            'violation_percentage': {},
            'consecutive_violations': 0,
            'max_consecutive_violations': 0
        }
        
        if not latency_data:
            return violations
        
        # Count violations by threshold level
        for level, threshold in self.thresholds.items():
            level_violations = sum(1 for latency in latency_data if latency > threshold)
            violations['violations_by_level'][level] = level_violations
            violations['violation_percentage'][level] = (
                (level_violations / len(latency_data)) * 100 if latency_data else 0
            )
        
        # Detect consecutive violations (using medium threshold as baseline)
        consecutive_count = 0
        max_consecutive = 0
        threshold = self.thresholds.get('medium', 100)
        
        for latency in latency_data:
            if latency > threshold:
                consecutive_count += 1
                max_consecutive = max(max_consecutive, consecutive_count)
            else:
                consecutive_count = 0
        
        violations['consecutive_violations'] = consecutive_count
        violations['max_consecutive_violations'] = max_consecutive
        
        return violations


class DistributionAnalyzer(LatencyAnalyzer):
    """Analyzer for latency distribution and histogram generation"""
    
    def __init__(self, custom_buckets: Optional[List[float]] = None):
        """
        Initialize distribution analyzer
        
        Args:
            custom_buckets: Custom histogram buckets in microseconds
        """
        self.buckets = custom_buckets or [0, 50, 100, 200, 500, 1000, 2000, 5000, 10000]
    
    def analyze(self, latency_data: List[float]) -> Dict[str, Any]:
        """
        Analyze latency distribution
        
        Args:
            latency_data: List of latency measurements
            
        Returns:
            Dict containing distribution analysis
        """
        distribution = {
            'buckets': self.buckets,
            'labels': [f'≤{bucket}μs' for bucket in self.buckets],
            'counts': [0] * len(self.buckets),
            'percentages': [0] * len(self.buckets),
            'histogram_data': []
        }
        
        if not latency_data:
            return distribution
        
        # Distribute latencies into buckets
        for latency in latency_data:
            placed = False
            for i, bucket in enumerate(self.buckets):
                if latency <= bucket:
                    distribution['counts'][i] += 1
                    placed = True
                    break
            
            # Handle values exceeding the highest bucket
            if not placed:
                distribution['counts'][-1] += 1
        
        # Calculate percentages
        total_samples = len(latency_data)
        distribution['percentages'] = [
            (count / total_samples) * 100 for count in distribution['counts']
        ]
        
        # Prepare histogram data for visualization
        distribution['histogram_data'] = [
            {'range': label, 'count': count, 'percentage': percentage}
            for label, count, percentage in zip(
                distribution['labels'], 
                distribution['counts'], 
                distribution['percentages']
            )
        ]
        
        return distribution


class ImpactAssessment(LatencyAnalyzer):
    """Analyzer for industrial impact evaluation"""
    
    def __init__(self):
        """Initialize impact assessment analyzer"""
        self.impact_levels = {
            'critical': {'threshold': 1000, 'description': 'Unacceptable for real-time control'},
            'high': {'threshold': 500, 'description': 'Degraded performance, monitoring required'},
            'medium': {'threshold': 100, 'description': 'Acceptable but suboptimal'},
            'low': {'threshold': 0, 'description': 'Optimal for industrial applications'}
        }
    
    def analyze(self, avg_latency: float) -> Dict[str, Any]:
        """
        Assess industrial impact based on average latency
        
        Args:
            avg_latency: Average latency in microseconds
            
        Returns:
            Dict containing impact assessment
        """
        impact_level = self._determine_impact_level(avg_latency)
        
        assessment = {
            'industrial_impact': impact_level,
            'impact_description': self.impact_levels[impact_level]['description'],
            'recommended_action': self._get_recommended_action(impact_level),
            'sla_compliance': self._check_sla_compliance(avg_latency),
            'risk_factors': self._identify_risk_factors(avg_latency, impact_level)
        }
        
        return assessment
    
    def _determine_impact_level(self, avg_latency: float) -> str:
        """Determine impact level based on latency"""
        if avg_latency > 1000:
            return 'critical'
        elif avg_latency > 500:
            return 'high'
        elif avg_latency > 100:
            return 'medium'
        else:
            return 'low'
    
    def _get_recommended_action(self, impact_level: str) -> str:
        """Get recommended action for impact level"""
        recommendations = {
            'critical': 'Immediate intervention required - system performance unacceptable',
            'high': 'Investigation and optimization needed within 24 hours',
            'medium': 'Monitor closely and consider optimization',
            'low': 'Continue normal operations'
        }
        return recommendations.get(impact_level, 'Monitor system')
    
    def _check_sla_compliance(self, avg_latency: float) -> Dict[str, Any]:
        """Check compliance with industrial SLA standards"""
        return {
            'iec_61850_compliant': avg_latency <= 100,  # IEC 61850 standard
            'scada_acceptable': avg_latency <= 500,     # SCADA acceptable range
            'real_time_suitable': avg_latency <= 50     # Hard real-time suitable
        }
    
    def _identify_risk_factors(self, avg_latency: float, impact_level: str) -> List[str]:
        """Identify risk factors based on latency metrics"""
        risks = []
        
        if avg_latency > 1000:
            risks.extend([
                'Safety system response time compromised',
                'Control loop instability risk',
                'Process interruption possible'
            ])
        elif avg_latency > 500:
            risks.extend([
                'Performance degradation detected',
                'Increased jitter likely'
            ])
        elif avg_latency > 100:
            risks.append('Suboptimal for precision control applications')
        
        return risks


class LatencyMetricsCollector:
    """Main collector orchestrating all latency analyzers"""
    
    def __init__(self, latency_log: str = "/var/log/deepinspector/latency.log",
                 stats_file: str = "/var/log/deepinspector/stats.json"):
        """
        Initialize latency metrics collector
        
        Args:
            latency_log: Path to latency log file
            stats_file: Path to statistics file
        """
        self.latency_log = latency_log
        self.stats_file = stats_file
        
        # Initialize analyzers
        self.realtime_analyzer = RealTimeLatencyAnalyzer()
        self.threshold_analyzer = ThresholdAnalyzer()
        self.distribution_analyzer = DistributionAnalyzer()
        self.impact_assessor = ImpactAssessment()
    
    def get_latency_metrics(self) -> Dict[str, Any]:
        """
        Get comprehensive latency metrics for industrial environments
        
        Returns:
            Dict containing complete latency analysis
        """
        try:
            # Initialize base metrics structure
            metrics = {
                'timestamp': datetime.now().isoformat(),
                'collector_status': 'active',
                'data_sources': {
                    'latency_log': os.path.exists(self.latency_log),
                    'stats_file': os.path.exists(self.stats_file)
                }
            }
            
            # Load baseline metrics from stats file
            baseline_metrics = self._load_baseline_metrics()
            metrics.update(baseline_metrics)
            
            # Load and analyze latency log data
            latency_data = self._load_latency_data()
            
            if latency_data:
                # Real-time analysis
                realtime_metrics = self.realtime_analyzer.analyze(latency_data)
                metrics.update(realtime_metrics)
                
                # Threshold analysis
                threshold_analysis = self.threshold_analyzer.analyze(latency_data)
                metrics['threshold_analysis'] = threshold_analysis
                
                # Distribution analysis
                distribution = self.distribution_analyzer.analyze(latency_data)
                metrics['latency_distribution'] = distribution
                
                # Impact assessment
                impact = self.impact_assessor.analyze(realtime_metrics['avg_latency'])
                metrics.update(impact)
                
                # Add legacy compatibility fields
                metrics['threshold_violations'] = threshold_analysis['violations_by_level'].get('medium', 0)
            
            return metrics
            
        except Exception as e:
            return {
                'error': str(e),
                'timestamp': datetime.now().isoformat(),
                'collector_status': 'error'
            }
    
    def _load_baseline_metrics(self) -> Dict[str, Any]:
        """Load baseline metrics from stats file"""
        baseline = {'avg_latency': 0, 'baseline_source': None}
        
        if os.path.exists(self.stats_file):
            try:
                with open(self.stats_file, 'r') as f:
                    stats = json.load(f)
                baseline['avg_latency'] = stats.get('performance', {}).get('latency_avg', 0)
                baseline['baseline_source'] = 'stats_file'
            except (IOError, json.JSONDecodeError):
                pass
        
        return baseline
    
    def _load_latency_data(self) -> List[float]:
        """Load latency data from log file within time window"""
        latency_data = []
        
        if not os.path.exists(self.latency_log):
            return latency_data
        
        cutoff_time = datetime.now() - timedelta(hours=self.realtime_analyzer.time_window_hours)
        
        try:
            with open(self.latency_log, 'r') as f:
                for line in f:
                    try:
                        entry = json.loads(line.strip())
                        entry_time = datetime.fromisoformat(entry.get('timestamp', ''))
                        
                        if entry_time > cutoff_time:
                            latency = entry.get('latency', 0)
                            if isinstance(latency, (int, float)) and latency >= 0:
                                latency_data.append(float(latency))
                    except (json.JSONDecodeError, ValueError, TypeError):
                        continue
        except IOError as e:
            raise LatencyAnalysisError(f"Error reading latency log: {e}")
        
        return latency_data
    
    def set_time_window(self, hours: int) -> None:
        """
        Set analysis time window
        
        Args:
            hours: Time window in hours
        """
        self.realtime_analyzer = RealTimeLatencyAnalyzer(time_window_hours=hours)
    
    def set_custom_thresholds(self, thresholds: Dict[str, float]) -> None:
        """
        Set custom latency thresholds
        
        Args:
            thresholds: Dictionary of threshold levels and values
        """
        self.threshold_analyzer = ThresholdAnalyzer(custom_thresholds=thresholds)
    
    def get_collector_status(self) -> Dict[str, Any]:
        """Get collector status and configuration"""
        return {
            'latency_log_path': self.latency_log,
            'stats_file_path': self.stats_file,
            'log_exists': os.path.exists(self.latency_log),
            'stats_exists': os.path.exists(self.stats_file),
            'time_window_hours': self.realtime_analyzer.time_window_hours,
            'thresholds': self.threshold_analyzer.thresholds,
            'bucket_configuration': self.distribution_analyzer.buckets
        }


def main():
    """Main function to run latency metrics collection"""
    collector = LatencyMetricsCollector()
    
    # Show collector status
    status = collector.get_collector_status()
    print("Latency Metrics Collector Status:")
    print(f"  - Latency log exists: {status['log_exists']}")
    print(f"  - Stats file exists: {status['stats_exists']}")
    print(f"  - Time window: {status['time_window_hours']} hours")
    print(f"  - Thresholds: {status['thresholds']}")
    print()
    
    # Get and display latency metrics
    metrics = collector.get_latency_metrics()
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()