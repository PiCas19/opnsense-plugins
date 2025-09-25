#!/usr/local/bin/python3
"""
DeepInspector DPI Statistics Collector
--------------------------------------
Collects current Deep Packet Inspection statistics including:
- Packets analyzed
- Threats detected by severity
- Top and recent threats
- Industrial protocol stats
- Performance metrics (CPU, memory, throughput, latency)

Author: Pierpaolo Casati
Version: 1.0
"""

import json
import os
from datetime import datetime, timedelta
from typing import Dict, Any, List


class DPIStatsCollector:
    """
    Collector class for current DPI engine statistics.
    """

    def __init__(
        self,
        stats_file: str = "/var/log/deepinspector/stats.json",
        alert_log: str = "/var/log/deepinspector/alerts.log",
        threat_log: str = "/var/log/deepinspector/threats.log",
    ):
        """
        Initialize the DPI statistics collector.

        Args:
            stats_file: Path to JSON file storing historical stats.
            alert_log: Path to JSONL alert log file.
            threat_log: Path to JSONL threat log file.
        """
        self.stats_file = stats_file
        self.alert_log = alert_log
        self.threat_log = threat_log

    def _load_json_file(self, path: str) -> Any:
        """
        Safely load JSON data from a file.

        Args:
            path: Path to the JSON file.

        Returns:
            Loaded JSON object or empty dict/list on failure.
        """
        if os.path.exists(path):
            try:
                with open(path, "r") as f:
                    return json.load(f)
            except Exception:
                pass
        return {}

    def _analyze_recent_alerts(self, hours: int = 24) -> List[Dict[str, Any]]:
        """
        Analyze alerts within the last `hours` hours.

        Args:
            hours: Time window in hours for recent alerts.

        Returns:
            List of recent alert dictionaries.
        """
        recent_alerts: List[Dict[str, Any]] = []
        cutoff_time = datetime.now() - timedelta(hours=hours)

        if os.path.exists(self.alert_log):
            with open(self.alert_log, "r") as f:
                for line in f:
                    try:
                        alert = json.loads(line.strip())
                        alert_time = datetime.fromisoformat(alert.get("timestamp", ""))
                        if alert_time > cutoff_time:
                            recent_alerts.append(alert)
                    except Exception:
                        continue
        return recent_alerts

    def collect(self) -> Dict[str, Any]:
        """
        Collect DPI statistics.

        Returns:
            Dictionary with aggregated statistics.
        """
        stats: Dict[str, Any] = {
            "packets_analyzed": 0,
            "threats_detected": 0,
            "false_positives": 0,
            "critical_alerts": 0,
            "protocols": {},
            "top_threats": [],
            "recent_threats": [],
            "threats_by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "detection_rate_trend": [],
            "industrial_stats": {
                "modbus_packets": 0,
                "dnp3_packets": 0,
                "opcua_packets": 0,
                "scada_alerts": 0,
                "avg_latency": 0,
            },
            "performance": {
                "cpu_usage": 0,
                "memory_usage": 0,
                "throughput_mbps": 0,
                "latency_avg": 0,
            },
            "timestamp": datetime.now().isoformat(),
        }

        try:
            # Load historical stats if available
            current_stats = self._load_json_file(self.stats_file)
            if isinstance(current_stats, dict):
                stats.update(current_stats)

            # Analyze recent alerts
            recent_alerts = self._analyze_recent_alerts()
            for alert in recent_alerts:
                severity = alert.get("severity", "medium")
                if severity in stats["threats_by_severity"]:
                    stats["threats_by_severity"][severity] += 1

            # Aggregate top threats
            threat_counts: Dict[str, int] = {}
            for alert in recent_alerts:
                threat_type = alert.get("threat_type", "unknown")
                threat_counts[threat_type] = threat_counts.get(threat_type, 0) + 1

            stats["top_threats"] = sorted(
                threat_counts.items(), key=lambda x: x[1], reverse=True
            )[:10]

            # Store recent threats (last 10)
            stats["recent_threats"] = sorted(
                recent_alerts, key=lambda x: x.get("timestamp", ""), reverse=True
            )[:10]

        except Exception as exc:
            stats["error"] = str(exc)

        return stats


def main() -> None:
    """
    CLI entry point for printing DPI statistics in JSON format.
    """
    collector = DPIStatsCollector()
    stats = collector.collect()
    print(json.dumps(stats, indent=2))


if __name__ == "__main__":
    main()
