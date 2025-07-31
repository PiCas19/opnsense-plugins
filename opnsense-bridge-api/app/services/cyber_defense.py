from typing import Dict, Any, List
from collections import Counter
from datetime import datetime, timezone

import logging

from app.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

class CyberDefenseService:
    """Service for cyber defense operations"""
    
    def __init__(self):
        # DMZ and debug settings from .env
        self.dmz_offline_mode = settings.dmz_offline_mode
        self.debug = settings.debug
        
        # Threat detection thresholds from .env
        self.blocked_events_warning = settings.blocked_events_warning
        self.blocked_events_critical = settings.blocked_events_critical
        self.risk_score_warning = settings.risk_score_warning
        self.risk_score_critical = settings.risk_score_critical
        self.failed_logins_warning = settings.failed_logins_warning
        self.failed_logins_critical = settings.failed_logins_critical
        
        # Configurable ports for threat detection
        self.port_scan_ports = ["22", "23", "80", "443", "3389", "21", "25"]  # Could be made configurable in .env
        self.brute_force_ports = ["22", "3389"]  # Could be made configurable in .env
        
        # Logging configuration details
        logger.info("CyberDefenseService initialized")
        logger.info(f"   DMZ Offline Mode: {self.dmz_offline_mode}")
        logger.info(f"   Debug Mode: {self.debug}")
        logger.info(f"   Blocked Events Thresholds: Warning={self.blocked_events_warning}, Critical={self.blocked_events_critical}")
        logger.info(f"   Risk Score Thresholds: Warning={self.risk_score_warning}, Critical={self.risk_score_critical}")
        logger.info(f"   Failed Logins Thresholds: Warning={self.failed_logins_warning}, Critical={self.failed_logins_critical}")
        logger.info(f"   Port Scan Ports: {', '.join(self.port_scan_ports)}")
        logger.info(f"   Brute Force Ports: {', '.join(self.brute_force_ports)}")
    
    def analyze_threat_patterns(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze logs for threat patterns"""
        if self.dmz_offline_mode:
            logger.warning("DMZ offline mode enabled - returning empty threat patterns")
            return {
                "port_scans": 0,
                "brute_force": 0,
                "ddos_indicators": 0,
                "suspicious_patterns": [],
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "status": "offline"
            }
        
        if not logs:
            logger.debug("No logs provided for threat analysis")
            return {
                "port_scans": 0,
                "brute_force": 0,
                "ddos_indicators": 0,
                "suspicious_patterns": [],
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "status": "ok"
            }
        
        patterns = {
            "port_scans": 0,
            "brute_force": 0,
            "ddos_indicators": 0,
            "suspicious_patterns": [],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "status": "ok"
        }
        
        # Count by source IP
        ip_counts = Counter(log.get("src_ip", "") for log in logs if log.get("src_ip"))
        
        # Detect patterns
        for log in logs:
            dst_port = str(log.get("dst_port", ""))
            src_ip = log.get("src_ip", "")
            action = log.get("action", "").lower()
            
            # Port scan detection
            if dst_port in self.port_scan_ports:
                patterns["port_scans"] += 1
                if self.debug:
                    logger.debug(f"Port scan detected: src_ip={src_ip}, dst_port={dst_port}")
            
            # Brute force detection
            if dst_port in self.brute_force_ports and ip_counts.get(src_ip, 0) > self.failed_logins_warning:
                patterns["brute_force"] += 1
                patterns["suspicious_patterns"].append({
                    "type": "brute_force",
                    "src_ip": src_ip,
                    "dst_port": dst_port,
                    "count": ip_counts[src_ip],
                    "timestamp": log.get("timestamp", datetime.now(timezone.utc).isoformat())
                })
                if self.debug:
                    logger.debug(f"Brute force detected: src_ip={src_ip}, dst_port={dst_port}, count={ip_counts[src_ip]}")
            
            # DDoS indicators
            if ip_counts.get(src_ip, 0) > self.blocked_events_warning:
                patterns["ddos_indicators"] += 1
                patterns["suspicious_patterns"].append({
                    "type": "ddos",
                    "src_ip": src_ip,
                    "count": ip_counts[src_ip],
                    "timestamp": log.get("timestamp", datetime.now(timezone.utc).isoformat())
                })
                if self.debug:
                    logger.debug(f"DDoS indicator detected: src_ip={src_ip}, count={ip_counts[src_ip]}")
        
        # Determine overall status
        total_threats = patterns["port_scans"] + patterns["brute_force"] + patterns["ddos_indicators"]
        patterns["status"] = self._get_status_level(total_threats, self.blocked_events_warning, self.blocked_events_critical)
        
        if self.debug:
            logger.debug(f"Threat patterns analyzed: {patterns}")
        
        return patterns
    
    def calculate_risk_score(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate risk score 0-100 with status"""
        if self.dmz_offline_mode:
            logger.warning("DMZ offline mode enabled - returning mock risk score")
            return {"score": 0, "status": "offline", "timestamp": datetime.now(timezone.utc).isoformat()}
        
        if not logs:
            logger.debug("No logs provided for risk score calculation")
            return {"score": 0, "status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}
        
        # Calculate risk score
        unique_ips = len(set(log.get("src_ip", "") for log in logs if log.get("src_ip")))
        blocks_per_hour = len(logs)  # Assuming logs are from last hour
        
        # Weighted risk calculation
        ip_weight = 2  # Weight for unique IPs
        block_weight = 0.1  # Weight for blocks per hour
        risk_score = min(100, (unique_ips * ip_weight) + (blocks_per_hour * block_weight))
        
        # Determine status based on risk score thresholds
        status = self._get_status_level(risk_score, self.risk_score_warning, self.risk_score_critical)
        
        result = {
            "score": int(risk_score),
            "status": status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "unique_ips": unique_ips,
            "blocks_per_hour": blocks_per_hour
        }
        
        if self.debug:
            logger.debug(f"Risk score calculated: {result}")
        
        return result
    
    def _get_status_level(self, value: float, warning_threshold: float, critical_threshold: float) -> str:
        """Get status level based on thresholds"""
        if value >= critical_threshold:
            return "critical"
        elif value >= warning_threshold:
            return "warning"
        else:
            return "ok"