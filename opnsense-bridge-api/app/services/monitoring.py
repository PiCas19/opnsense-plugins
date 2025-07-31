import re
from typing import Dict, Any, List
from datetime import datetime, timezone

import logging

from app.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

class MonitoringService:
    """Service for monitoring metrics and analysis"""
    
    def __init__(self):
        # DMZ and debug settings from .env
        self.dmz_offline_mode = settings.dmz_offline_mode
        self.debug = settings.debug
        
        # Thresholds from .env
        self.cpu_warning_threshold = settings.cpu_warning_threshold
        self.cpu_critical_threshold = settings.cpu_critical_threshold
        self.memory_warning_threshold = settings.memory_warning_threshold
        self.memory_critical_threshold = settings.memory_critical_threshold
        self.firewall_rules_warning = settings.firewall_rules_warning
        self.firewall_rules_critical = settings.firewall_rules_critical
        
        # Logging configuration details
        logger.info("MonitoringService initialized")
        logger.info(f"   DMZ Offline Mode: {self.dmz_offline_mode}")
        logger.info(f"   Debug Mode: {self.debug}")
        logger.info(f"   CPU Thresholds: Warning={self.cpu_warning_threshold}%, Critical={self.cpu_critical_threshold}%")
        logger.info(f"   Memory Thresholds: Warning={self.memory_warning_threshold}%, Critical={self.memory_critical_threshold}%")
        logger.info(f"   Firewall Rules Thresholds: Warning={self.firewall_rules_warning}, Critical={self.firewall_rules_critical}")
    
    def parse_uptime(self, uptime_str: str) -> float:
        """Parse uptime string to hours"""
        if self.dmz_offline_mode:
            logger.warning("DMZ offline mode enabled - returning 0.0 uptime")
            return 0.0
        
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
    
    def calculate_memory_usage(self, system_status: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate memory usage percentage with status"""
        if self.dmz_offline_mode:
            logger.warning("DMZ offline mode enabled - returning mock memory usage")
            return {"usage_percent": 0.0, "status": "offline"}
        
        try:
            memory = system_status.get("memory", {})
            usage_percent = 0.0
            
            if isinstance(memory, str) and "%" in memory:
                usage_percent = float(memory.replace("%", ""))
            elif isinstance(memory, dict):
                used = memory.get("used", 0)
                total = memory.get("total", 1)
                usage_percent = (used / total) * 100.0 if total > 0 else 0.0
            
            status = self._get_status_level(usage_percent, self.memory_warning_threshold, self.memory_critical_threshold)
            
            if self.debug:
                logger.debug(f"Memory usage: {usage_percent}%, Status: {status}")
            
            return {"usage_percent": usage_percent, "status": status}
        except Exception as e:
            logger.debug(f"Failed to calculate memory usage: {e}")
            return {"usage_percent": 0.0, "status": "error"}
    
    def calculate_cpu_usage(self, system_status: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate CPU usage percentage with status"""
        if self.dmz_offline_mode:
            logger.warning("DMZ offline mode enabled - returning mock CPU usage")
            return {"usage_percent": 0.0, "status": "offline"}
        
        try:
            cpu = system_status.get("cpu", {})
            usage_percent = 0.0
            
            if isinstance(cpu, str) and "%" in cpu:
                usage_percent = float(cpu.replace("%", ""))
            elif isinstance(cpu, dict):
                usage_percent = float(cpu.get("usage", 0))
            
            status = self._get_status_level(usage_percent, self.cpu_warning_threshold, self.cpu_critical_threshold)
            
            if self.debug:
                logger.debug(f"CPU usage: {usage_percent}%, Status: {status}")
            
            return {"usage_percent": usage_percent, "status": status}
        except Exception as e:
            logger.debug(f"Failed to calculate CPU usage: {e}")
            return {"usage_percent": 0.0, "status": "error"}
    
    def analyze_firewall_performance(self, rules: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze firewall performance metrics"""
        if self.dmz_offline_mode:
            logger.warning("DMZ offline mode enabled - returning mock firewall performance")
            return {
                "total_rules": 0,
                "rule_types": {},
                "interfaces": [],
                "performance_score": 0,
                "status": "offline",
                "analysis_timestamp": datetime.now(timezone.utc).isoformat()
            }
        
        if not rules:
            logger.debug("No firewall rules provided for performance analysis")
            return {
                "total_rules": 0,
                "rule_types": {},
                "interfaces": [],
                "performance_score": 0,
                "status": "ok",
                "analysis_timestamp": datetime.now(timezone.utc).isoformat()
            }
        
        # Count rule types and interfaces
        rule_types = {}
        interfaces = set()
        
        for rule in rules:
            action = rule.get("action", "unknown")
            interface = rule.get("interface", "unknown")
            
            rule_types[action] = rule_types.get(action, 0) + 1
            interfaces.add(interface)
        
        # Calculate performance score based on rule count and thresholds
        total_rules = len(rules)
        performance_score = max(0, 100 - (total_rules * 2))  # Adjusted heuristic: 2 points per rule
        status = self._get_status_level(total_rules, self.firewall_rules_warning, self.firewall_rules_critical)
        
        result = {
            "total_rules": total_rules,
            "rule_types": rule_types,
            "interfaces": list(interfaces),
            "performance_score": performance_score,
            "status": status,
            "analysis_timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        if self.debug:
            logger.debug(f"Firewall performance analysis: {result}")
        
        return result
    
    def _get_status_level(self, value: float, warning_threshold: float, critical_threshold: float) -> str:
        """Get status level based on thresholds"""
        if value >= critical_threshold:
            return "critical"
        elif value >= warning_threshold:
            return "warning"
        else:
            return "ok"