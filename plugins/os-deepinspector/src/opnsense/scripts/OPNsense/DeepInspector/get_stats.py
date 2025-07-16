#!/usr/local/bin/python3
# get_stats.py - Get current DPI statistics

import os
import json
from datetime import datetime, timedelta

STATS_FILE = "/var/log/deepinspector/stats.json"
ALERT_LOG = "/var/log/deepinspector/alerts.log"
THREAT_LOG = "/var/log/deepinspector/threats.log"

def get_stats():
    """Get current DPI statistics"""
    try:
        stats = {
            'packets_analyzed': 0,
            'threats_detected': 0,
            'false_positives': 0,
            'critical_alerts': 0,
            'protocols': {},
            'top_threats': [],
            'recent_threats': [],
            'threats_by_severity': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
            'detection_rate_trend': [],
            'industrial_stats': {
                'modbus_packets': 0,
                'dnp3_packets': 0,
                'opcua_packets': 0,
                'scada_alerts': 0,
                'avg_latency': 0
            },
            'performance': {
                'cpu_usage': 0,
                'memory_usage': 0,
                'throughput_mbps': 0,
                'latency_avg': 0
            },
            'timestamp': datetime.now().isoformat()
        }

        # Load current stats if available
        if os.path.exists(STATS_FILE):
            with open(STATS_FILE, 'r') as f:
                current_stats = json.load(f)
                stats.update(current_stats)

        # Analyze recent alerts for trends
        if os.path.exists(ALERT_LOG):
            recent_alerts = []
            cutoff_time = datetime.now() - timedelta(hours=24)
            
            with open(ALERT_LOG, 'r') as f:
                for line in f:
                    try:
                        alert = json.loads(line.strip())
                        alert_time = datetime.fromisoformat(alert.get('timestamp', ''))
                        if alert_time > cutoff_time:
                            recent_alerts.append(alert)
                    except:
                        continue

            # Count threats by severity
            for alert in recent_alerts:
                severity = alert.get('severity', 'medium')
                if severity in stats['threats_by_severity']:
                    stats['threats_by_severity'][severity] += 1

            # Get top threat types
            threat_counts = {}
            for alert in recent_alerts:
                threat_type = alert.get('threat_type', 'unknown')
                threat_counts[threat_type] = threat_counts.get(threat_type, 0) + 1

            stats['top_threats'] = sorted(threat_counts.items(),
                                        key=lambda x: x[1], reverse=True)[:10]
            
            # Get recent threats (last 10)
            stats['recent_threats'] = sorted(recent_alerts, 
                                           key=lambda x: x.get('timestamp', ''), 
                                           reverse=True)[:10]

        return stats

    except Exception as e:
        return {
            'error': str(e),
            'packets_analyzed': 0,
            'threats_detected': 0,
            'timestamp': datetime.now().isoformat()
        }

if __name__ == "__main__":
    stats = get_stats()
    print(json.dumps(stats, indent=2))