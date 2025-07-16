#!/usr/local/bin/python3
# get_latency_metrics.py - Get latency metrics for industrial environments

import os
import json
from datetime import datetime, timedelta
from collections import deque

LATENCY_LOG = "/var/log/deepinspector/latency.log"
STATS_FILE = "/var/log/deepinspector/stats.json"

def get_latency_metrics():
    """Get latency metrics for industrial environments"""
    try:
        metrics = {
            'timestamp': datetime.now().isoformat(),
            'avg_latency': 0,
            'max_latency': 0,
            'min_latency': 0,
            'latency_distribution': {
                'labels': [],
                'data': []
            },
            'threshold_violations': 0,
            'industrial_impact': 'none'
        }

        # Load current stats
        if os.path.exists(STATS_FILE):
            with open(STATS_FILE, 'r') as f:
                stats = json.load(f)
                metrics['avg_latency'] = stats.get('performance', {}).get('latency_avg', 0)

        # Analyze latency log if available
        if os.path.exists(LATENCY_LOG):
            latencies = []
            cutoff_time = datetime.now() - timedelta(hours=1)
            
            with open(LATENCY_LOG, 'r') as f:
                for line in f:
                    try:
                        entry = json.loads(line.strip())
                        entry_time = datetime.fromisoformat(entry.get('timestamp', ''))
                        if entry_time > cutoff_time:
                            latencies.append(entry.get('latency', 0))
                    except:
                        continue

            if latencies:
                metrics['avg_latency'] = sum(latencies) / len(latencies)
                metrics['max_latency'] = max(latencies)
                metrics['min_latency'] = min(latencies)
                
                # Count threshold violations (assuming 100 microseconds threshold)
                threshold = 100
                metrics['threshold_violations'] = sum(1 for l in latencies if l > threshold)
                
                # Determine industrial impact
                if metrics['avg_latency'] > 1000:  # > 1ms
                    metrics['industrial_impact'] = 'critical'
                elif metrics['avg_latency'] > 500:  # > 500μs
                    metrics['industrial_impact'] = 'high'
                elif metrics['avg_latency'] > 100:  # > 100μs
                    metrics['industrial_impact'] = 'medium'
                else:
                    metrics['industrial_impact'] = 'low'

                # Create latency distribution for chart
                buckets = [0, 50, 100, 200, 500, 1000, 2000, 5000]
                distribution = [0] * len(buckets)
                
                for latency in latencies:
                    for i, bucket in enumerate(buckets):
                        if latency <= bucket:
                            distribution[i] += 1
                            break
                    else:
                        distribution[-1] += 1

                metrics['latency_distribution']['labels'] = [f'≤{b}μs' for b in buckets]
                metrics['latency_distribution']['data'] = distribution

        return metrics

    except Exception as e:
        return {
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }

if __name__ == "__main__":
    metrics = get_latency_metrics()
    print(json.dumps(metrics, indent=2))
