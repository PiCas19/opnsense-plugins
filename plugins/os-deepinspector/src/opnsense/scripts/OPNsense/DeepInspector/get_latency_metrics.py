#!/usr/local/bin/python3
"""
DeepInspector Latency Metrics Collector
---------------------------------------
Collects latency-related statistics for industrial environments
(e.g., SCADA/ICS networks) from DeepInspector logs.

Features
--------
- Calculates average, maximum, and minimum latency over the last hour
- Builds latency distribution buckets for charting
- Counts threshold violations (default 100 microseconds)
- Determines overall industrial impact level
- Merges historical averages from persistent stats file

Author: Pierpaolo Casati
Version: 1.0
"""

import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, List


class LatencyMetricsCollector:
    """
    Handles collection and aggregation of latency metrics.
    """

    def __init__(self,
                 latency_log: str = "/var/log/deepinspector/latency.log",
                 stats_file: str = "/var/log/deepinspector/stats.json",
                 threshold_us: int = 100):
        """
        Initialize the collector.

        Args:
            latency_log: Path to the latency log file (JSON lines).
            stats_file: Path to the persistent stats JSON file.
            threshold_us: Latency threshold (microseconds) for violations.
        """
        self.latency_log = Path(latency_log)
        self.stats_file = Path(stats_file)
        self.threshold = threshold_us

    def _base_metrics(self) -> Dict[str, Any]:
        """
        Provide default metrics structure.

        Returns:
            Dictionary with default latency metrics.
        """
        return {
            "timestamp": datetime.now().isoformat(),
            "avg_latency": 0,
            "max_latency": 0,
            "min_latency": 0,
            "latency_distribution": {
                "labels": [],
                "data": []
            },
            "threshold_violations": 0,
            "industrial_impact": "none"
        }

    def _load_historical_average(self, metrics: Dict[str, Any]) -> None:
        """
        Load historical average latency from the persistent stats file.

        Args:
            metrics: Metrics dictionary to update.
        """
        if not self.stats_file.exists():
            return
        try:
            with self.stats_file.open("r", encoding="utf-8") as f:
                stats = json.load(f)
                metrics["avg_latency"] = stats.get("performance", {}).get("latency_avg", 0)
        except (json.JSONDecodeError, OSError):
            # Ignore corrupted or unreadable stats file
            pass

    def _analyze_recent_latencies(self, metrics: Dict[str, Any]) -> None:
        """
        Analyze the last hour of latency logs.

        Args:
            metrics: Metrics dictionary to update.
        """
        if not self.latency_log.exists():
            return

        cutoff_time = datetime.now() - timedelta(hours=1)
        latencies: List[float] = []

        try:
            with self.latency_log.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        ts = entry.get("timestamp")
                        if not ts:
                            continue
                        entry_time = datetime.fromisoformat(ts)
                        if entry_time > cutoff_time:
                            latencies.append(entry.get("latency", 0))
                    except (json.JSONDecodeError, ValueError):
                        # Skip malformed entries
                        continue
        except OSError as exc:
            metrics["error"] = f"Latency log read error: {exc}"
            return

        if not latencies:
            return

        metrics["avg_latency"] = sum(latencies) / len(latencies)
        metrics["max_latency"] = max(latencies)
        metrics["min_latency"] = min(latencies)
        metrics["threshold_violations"] = sum(1 for l in latencies if l > self.threshold)

        # Determine industrial impact levels
        avg = metrics["avg_latency"]
        if avg > 1000:  # > 1 ms
            metrics["industrial_impact"] = "critical"
        elif avg > 500:  # > 500 μs
            metrics["industrial_impact"] = "high"
        elif avg > 100:  # > 100 μs
            metrics["industrial_impact"] = "medium"
        else:
            metrics["industrial_impact"] = "low"

        # Build latency distribution buckets for charting
        buckets = [0, 50, 100, 200, 500, 1000, 2000, 5000]
        distribution = [0] * len(buckets)

        for latency in latencies:
            for i, bucket in enumerate(buckets):
                if latency <= bucket:
                    distribution[i] += 1
                    break
            else:
                # Greater than the largest bucket
                distribution[-1] += 1

        metrics["latency_distribution"]["labels"] = [f"≤{b}μs" for b in buckets]
        metrics["latency_distribution"]["data"] = distribution

    def collect(self) -> Dict[str, Any]:
        """
        Collect and compute latency metrics.

        Returns:
            Dictionary containing computed latency metrics.
        """
        metrics = self._base_metrics()
        self._load_historical_average(metrics)
        self._analyze_recent_latencies(metrics)
        return metrics


def main() -> None:
    """
    Command-line entry point.
    Prints collected latency metrics as formatted JSON.
    """
    collector = LatencyMetricsCollector()
    results = collector.collect()
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()