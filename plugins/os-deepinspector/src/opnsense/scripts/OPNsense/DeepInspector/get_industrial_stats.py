#!/usr/local/bin/python3
# get_industrial_stats.py - Get industrial protocol statistics

import os
import json
from datetime import datetime, timedelta

STATS_FILE = "/var/log/deepinspector/stats.json"
ALERT_LOG = "/var/log/deepinspector/alerts.log"

def get_industrial_stats():
    """Get industrial protocol statistics"""
    try:
        stats = {
            'timestamp': datetime.now().isoformat(),
            'modbus_packets': 0,
            'dnp3_packets': 0,
            'opcua_packets': 0,
            'scada_alerts': 0,
            'plc_communications': 0,
            'industrial_threats': 0,
            'avg_latency': 0,
            'protocol_distribution': {}
        }

        # Load current stats
        if os.path.exists(STATS_FILE):
            with open(STATS_FILE, 'r') as f:
                current_stats = json.load(f)
                industrial_stats = current_stats.get('industrial_stats', {})
                stats.update(industrial_stats)

        # Analyze recent industrial alerts
        if os.path.exists(ALERT_LOG):
            cutoff_time = datetime.now() - timedelta(hours=24)
            
            with open(ALERT_LOG, 'r') as f:
                for line in f:
                    try:
                        alert = json.loads(line.strip())
                        alert_time = datetime.fromisoformat(alert.get('timestamp', ''))
                        
                        if alert_time > cutoff_time:
                            # Count industrial threats
                            if alert.get('industrial_context', False):
                                stats['industrial_threats'] += 1
                                
                            # Count SCADA alerts
                            if 'scada' in alert.get('threat_type', '').lower():
                                stats['scada_alerts'] += 1
                                
                            # Count by protocol
                            protocol = alert.get('industrial_protocol', '')
                            if protocol:
                                stats['protocol_distribution'][protocol] = \
                                    stats['protocol_distribution'].get(protocol, 0) + 1
                    except:
                        continue

        return stats

    except Exception as e:
        return {
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }

if __name__ == "__main__":
    stats = get_industrial_stats()
    print(json.dumps(stats, indent=2))

