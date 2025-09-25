#!/usr/local/bin/python3
"""
DeepInspector Industrial Statistics Collector
---------------------------------------------
Reads DeepInspector runtime logs and computes statistics related
to industrial/SCADA protocols. Designed for integration with
OPNsense dashboards or scheduled tasks.

Features
--------
- Collects packet counts and alert metrics for Modbus, DNP3, OPC UA
- Counts SCADA-related alerts within a 24-hour window
- Aggregates protocol distribution for recent alerts
- Outputs JSON for easy integration with UI or API calls

Author: Pierpaolo Casati
Version: 1.0
"""

import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any


class IndustrialStatsCollector:
    """
    Handles collection and aggregation of industrial protocol statistics.
    """

    def __init__(self,
                 stats_file: str = "/var/log/deepinspector/stats.json",
                 alert_log: str = "/var/log/deepinspector/alerts.log"):
        """
        Initialize the collector.

        Args:
            stats_file: Path to JSON file storing cumulative statistics.
            alert_log: Path to log file containing alert entries (one JSON per line).
        """
        self.stats_path = Path(stats_file)
        self.alert_log_path = Path(alert_log)

    def _base_stats(self) -> Dict[str, Any]:
        """
        Base statistics template.

        Returns:
            Dictionary with default zeroed metrics.
        """
        return {
            "timestamp": datetime.now().isoformat(),
            "modbus_packets": 0,
            "dnp3_packets": 0,
            "opcua_packets": 0,
            "scada_alerts": 0,
            "plc_communications": 0,
            "industrial_threats": 0,
            "avg_latency": 0,
            "protocol_distribution": {}
        }

    def _load_existing_stats(self) -> Dict[str, Any]:
        """
        Load existing statistics from the persistent stats file.

        Returns:
            Dictionary of previously saved industrial statistics.
        """
        if self.stats_path.exists():
            try:
                with self.stats_path.open("r", encoding="utf-8") as f:
                    current = json.load(f)
                return current.get("industrial_stats", {})
            except (json.JSONDecodeError, OSError):
                # If corrupted or unreadable, return empty stats
                return {}
        return {}

    def _analyze_recent_alerts(self, stats: Dict[str, Any]) -> None:
        """
        Analyze alerts from the past 24 hours to update statistics.

        Args:
            stats: Dictionary to be updated with alert-derived metrics.
        """
        if not self.alert_log_path.exists():
            return

        cutoff_time = datetime.now() - timedelta(hours=24)

        try:
            with self.alert_log_path.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        alert = json.loads(line)
                        # Validate timestamp
                        ts = alert.get("timestamp")
                        if not ts:
                            continue
                        alert_time = datetime.fromisoformat(ts)
                        if alert_time <= cutoff_time:
                            continue

                        # Industrial threat counting
                        if alert.get("industrial_context", False):
                            stats["industrial_threats"] += 1

                        # SCADA alerts
                        threat_type = alert.get("threat_type", "").lower()
                        if "scada" in threat_type:
                            stats["scada_alerts"] += 1

                        # Protocol distribution
                        protocol = alert.get("industrial_protocol", "")
                        if protocol:
                            stats["protocol_distribution"][protocol] = \
                                stats["protocol_distribution"].get(protocol, 0) + 1
                    except (json.JSONDecodeError, ValueError):
                        # Skip invalid lines
                        continue
        except OSError as exc:
            stats["error"] = f"Alert log read error: {exc}"

    def collect(self) -> Dict[str, Any]:
        """
        Collect and merge current industrial statistics.

        Returns:
            Dictionary with updated industrial metrics.
        """
        stats = self._base_stats()

        # Merge with existing stats if available
        existing = self._load_existing_stats()
        stats.update(existing)

        # Analyze alerts from the last 24 hours
        self._analyze_recent_alerts(stats)

        return stats


def main() -> None:
    """
    Command-line entry point.
    Prints the collected industrial statistics in JSON format.
    """
    collector = IndustrialStatsCollector()
    stats = collector.collect()
    print(json.dumps(stats, indent=2))


if __name__ == "__main__":
    main()
