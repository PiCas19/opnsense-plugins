#!/usr/local/bin/python3
"""
DeepInspector Performance Metrics Collector
-------------------------------------------
Collects system, DPI engine, and network interface metrics for
monitoring performance inside an OPNsense environment.

Features
--------
- System metrics: CPU, memory, disk usage, load averages
- DPI engine process metrics: CPU, memory, thread count, status
- Per–network interface statistics (packets, errors, drops)

Author: Pierpaolo Casati
Version: 1.0
"""

import json
import os
import subprocess
from datetime import datetime
from typing import Dict, Any, Optional

import psutil


class PerformanceMetricsCollector:
    """
    Collects performance metrics for the system and the DeepInspector engine.
    """

    def __init__(self, engine_name: str = "deepinspector_engine") -> None:
        """
        Initialize the collector.

        Args:
            engine_name: Name or unique pattern of the DeepInspector engine process.
        """
        self.engine_name = engine_name

    # --------------------------- System Metrics --------------------------- #
    def _system_metrics(self) -> Dict[str, Any]:
        """
        Gather system-wide resource usage metrics.

        Returns:
            Dictionary of CPU, memory, disk and load averages.
        """
        return {
            "cpu_usage": psutil.cpu_percent(interval=1),
            "memory_usage": psutil.virtual_memory().percent,
            "disk_usage": psutil.disk_usage("/").percent,
            "load_average": list(os.getloadavg())
        }

    # --------------------------- Engine Metrics --------------------------- #
    def _find_engine_pid(self) -> Optional[int]:
        """
        Locate the DeepInspector engine process ID using pgrep.

        Returns:
            PID of the engine process, or None if not found.
        """
        try:
            result = subprocess.run(
                ["pgrep", "-f", self.engine_name],
                capture_output=True,
                text=True,
                check=False
            )
            if result.returncode == 0:
                return int(result.stdout.strip().split("\n")[0])
        except Exception:
            pass
        return None

    def _engine_metrics(self) -> Dict[str, Any]:
        """
        Collect resource metrics specific to the DeepInspector engine.

        Returns:
            Dictionary of engine process metrics or status.
        """
        pid = self._find_engine_pid()
        if pid is None:
            return {"status": "not_found"}

        try:
            proc = psutil.Process(pid)
            return {
                "pid": pid,
                "cpu_percent": proc.cpu_percent(),
                "memory_percent": proc.memory_percent(),
                "memory_rss": proc.memory_info().rss,
                "num_threads": proc.num_threads(),
                "status": proc.status(),
                "create_time": proc.create_time()
            }
        except psutil.NoSuchProcess:
            return {"status": "not_running"}

    # --------------------------- Network Metrics -------------------------- #
    def _network_metrics(self) -> Dict[str, Any]:
        """
        Gather per-interface network I/O counters.

        Returns:
            Dictionary of metrics for each network interface.
        """
        metrics: Dict[str, Any] = {}
        for iface, stats in psutil.net_io_counters(pernic=True).items():
            metrics[iface] = {
                "bytes_sent": stats.bytes_sent,
                "bytes_recv": stats.bytes_recv,
                "packets_sent": stats.packets_sent,
                "packets_recv": stats.packets_recv,
                "errin": stats.errin,
                "errout": stats.errout,
                "dropin": stats.dropin,
                "dropout": stats.dropout,
            }
        return metrics

    # ------------------------------ Public API ---------------------------- #
    def collect(self) -> Dict[str, Any]:
        """
        Collect all available metrics.

        Returns:
            Structured dictionary with timestamp, system, engine, and network metrics.
        """
        try:
            return {
                "timestamp": datetime.now().isoformat(),
                "system": self._system_metrics(),
                "engine": self._engine_metrics(),
                "network": self._network_metrics()
            }
        except Exception as exc:
            return {
                "error": str(exc),
                "timestamp": datetime.now().isoformat()
            }


def main() -> None:
    """
    Command-line entry point.
    Prints collected performance metrics as formatted JSON.
    """
    collector = PerformanceMetricsCollector()
    metrics = collector.collect()
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
