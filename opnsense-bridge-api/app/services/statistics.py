import re
from typing import Dict, Any, List
from datetime import datetime, timezone
from collections import defaultdict

import logging

from app.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

class StatisticsService:
    """Service for calculating statistics and generating reports"""
    
    def __init__(self):
        # DMZ and debug settings from .env
        self.dmz_offline_mode = settings.dmz_offline_mode
        self.debug = settings.debug
        
        # Thresholds from .env
        self.cpu_warning_threshold = settings.cpu_warning_threshold
        self.cpu_critical_threshold = settings.cpu_critical_threshold
        self.memory_warning_threshold = settings.memory_warning_threshold
        self.memory_critical_threshold = settings.memory_critical_threshold
        
        # Logging configuration details
        logger.info("StatisticsService initialized")
        logger.info(f"   DMZ Offline Mode: {self.dmz_offline_mode}")
        logger.info(f"   Debug Mode: {self.debug}")
        logger.info(f"   CPU Thresholds: Warning={self.cpu_warning_threshold}%, Critical={self.cpu_critical_threshold}%")
        logger.info(f"   Memory Thresholds: Warning={self.memory_warning_threshold}%, Critical={self.memory_critical_threshold}%")
    
    def calculate_firewall_stats(self, rules: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate comprehensive firewall statistics"""
        if self.dmz_offline_mode:
            logger.warning("DMZ offline mode enabled - returning empty firewall stats")
            return {
                "total_rules": 0,
                "by_action": {},
                "by_interface": {},
                "by_protocol": {},
                "enabled_vs_disabled": {"enabled": 0, "disabled": 0}
            }
        
        if not rules:
            logger.debug("No firewall rules provided for statistics")
            return {
                "total_rules": 0,
                "by_action": {},
                "by_interface": {},
                "by_protocol": {},
                "enabled_vs_disabled": {"enabled": 0, "disabled": 0}
            }
        
        stats = {
            "total_rules": len(rules),
            "by_action": defaultdict(int),
            "by_interface": defaultdict(int),
            "by_protocol": defaultdict(int),
            "enabled_vs_disabled": {"enabled": 0, "disabled": 0},
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        for rule in rules:
            # Count by action
            action = rule.get("action", "unknown")
            stats["by_action"][action] += 1
            
            # Count by interface
            interface = rule.get("interface", "unknown")
            stats["by_interface"][interface] += 1
            
            # Count by protocol
            protocol = rule.get("protocol", "unknown")
            stats["by_protocol"][protocol] += 1
            
            # Count enabled vs disabled
            if rule.get("enabled") == "1":
                stats["enabled_vs_disabled"]["enabled"] += 1
            else:
                stats["enabled_vs_disabled"]["disabled"] += 1
        
        # Convert defaultdict to regular dict
        stats["by_action"] = dict(stats["by_action"])
        stats["by_interface"] = dict(stats["by_interface"])
        stats["by_protocol"] = dict(stats["by_protocol"])
        
        if self.debug:
            logger.debug(f"Firewall stats calculated: {stats}")
        
        return stats
    
    def calculate_system_performance_stats(self, system_status: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate system performance statistics"""
        if self.dmz_offline_mode:
            logger.warning("DMZ offline mode enabled - returning mock system performance stats")
            return {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "cpu": {"usage_percent": 0.0, "status": "offline"},
                "memory": {"usage_percent": 0.0, "status": "offline"},
                "uptime": {"raw": "unknown", "hours": 0.0},
                "version": "unknown",
                "hostname": "unknown"
            }
        
        stats = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "cpu": {
                "usage_percent": self._extract_numeric_value(system_status.get("cpu", {})),
                "status": self._get_status_level(
                    self._extract_numeric_value(system_status.get("cpu", {})),
                    self.cpu_warning_threshold,
                    self.cpu_critical_threshold
                )
            },
            "memory": {
                "usage_percent": self._extract_numeric_value(system_status.get("memory", {})),
                "status": self._get_status_level(
                    self._extract_numeric_value(system_status.get("memory", {})),
                    self.memory_warning_threshold,
                    self.memory_critical_threshold
                )
            },
            "uptime": {
                "raw": system_status.get("uptime", "unknown"),
                "hours": self._parse_uptime_hours(system_status.get("uptime", "0"))
            },
            "version": system_status.get("version", "unknown"),
            "hostname": system_status.get("hostname", "unknown")
        }
        
        if self.debug:
            logger.debug(f"System performance stats calculated: {stats}")
        
        return stats
    
    def _extract_numeric_value(self, value: Any) -> float:
        """Extract numeric value from various formats"""
        try:
            if isinstance(value, (int, float)):
                return float(value)
            elif isinstance(value, str):
                # Remove % and other non-numeric characters
                numeric_str = ''.join(c for c in value if c.isdigit() or c == '.')
                return float(numeric_str) if numeric_str else 0.0
            elif isinstance(value, dict):
                # Try common keys
                for key in ["usage", "percent", "value"]:
                    if key in value:
                        return self._extract_numeric_value(value[key])
                return 0.0
            else:
                return 0.0
        except Exception as e:
            logger.debug(f"Failed to extract numeric value: {e}")
            return 0.0
    
    def _get_status_level(self, value: float, warning_threshold: float, critical_threshold: float) -> str:
        """Get status level based on thresholds"""
        if value >= critical_threshold:
            return "critical"
        elif value >= warning_threshold:
            return "warning"
        else:
            return "ok"
    
    def _parse_uptime_hours(self, uptime_str: str) -> float:
        """Parse uptime string to hours"""
        try:
            if "day" in uptime_str:
                days = int(re.findall(r'(\d+)\s*day', uptime_str)[0])
                return days * 24.0
            elif "hour" in uptime_str:
                hours = int(re.findall(r'(\d+)\s*hour', uptime_str)[0])
                return float(hours)
            return 0.0
        except Exception as e:
            logger.debug(f"Failed to parse uptime: {e}")
            return 0.0