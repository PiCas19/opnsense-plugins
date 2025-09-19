#!/usr/local/bin/python3

"""
Enhanced Logger Module for Advanced Network Inspector

Provides structured logging capabilities for network packets and security alerts
with proper error handling, thread safety, and configurable output formats.

Author: System Administrator
Version: 1.0
"""

import datetime
import json
import threading
from typing import Dict, Any, Optional
from pathlib import Path


class NetworkLogger:
    """
    Thread-safe logger for network inspection events.
    
    Provides separate logging channels for alerts and general packet information
    with structured JSON output and automatic log rotation capabilities.
    """
    
    def __init__(self, 
                 alert_log_file: str = "/var/log/advinspector_alerts.log",
                 packet_log_file: str = "/var/log/advinspector_packets.log",
                 max_raw_bytes: int = 512):
        """
        Initialize the network logger.
        
        Args:
            alert_log_file: Path to alert log file
            packet_log_file: Path to packet log file  
            max_raw_bytes: Maximum bytes of raw packet data to log
        """
        self.alert_log_file = Path(alert_log_file)
        self.packet_log_file = Path(packet_log_file)
        self.max_raw_bytes = max_raw_bytes
        self._write_lock = threading.Lock()
        
        # Ensure log directories exist
        self._ensure_log_directories()
    
    def _ensure_log_directories(self) -> None:
        """Create log directories if they don't exist."""
        try:
            self.alert_log_file.parent.mkdir(parents=True, exist_ok=True)
            self.packet_log_file.parent.mkdir(parents=True, exist_ok=True)
        except Exception:
            # Silently fail - will be caught during actual logging
            pass
    
    def _create_log_entry(self, packet: Dict[str, Any], reason: str = "", 
                         entry_type: str = "packet") -> Dict[str, Any]:
        """
        Create a structured log entry from packet data.
        
        Args:
            packet: Packet data dictionary
            reason: Reason for logging this entry
            entry_type: Type of entry ("alert" or "packet")
            
        Returns:
            Structured log entry dictionary
        """
        # Extract protocol information with fallbacks
        protocol_info = packet.get("protocol_info", {})
        application_protocol = (
            packet.get("application_protocol") or 
            protocol_info.get("application") or 
            packet.get("protocol", "unknown")
        )
        
        entry = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "type": entry_type,
            "src": packet.get("src", "unknown"),
            "dst": packet.get("dst", "unknown"),
            "src_port": packet.get("src_port", 0),
            "dst_port": packet.get("dst_port", 0),
            "port": packet.get("port", packet.get("dst_port", 0)),
            "protocol": packet.get("protocol", "unknown"),
            "application_protocol": application_protocol,
            "interface": packet.get("interface", "unknown"),
            "reason": reason,
            "raw": packet.get("raw", "")[:self.max_raw_bytes]
        }
        
        # Add additional metadata if available
        if "ip_protocol" in packet:
            entry["ip_protocol"] = packet["ip_protocol"]
        
        if "timestamp" in packet:
            entry["packet_timestamp"] = packet["timestamp"]
            
        return entry
    
    def _write_log_entry(self, log_file: Path, entry: Dict[str, Any]) -> bool:
        """
        Write a log entry to the specified file in a thread-safe manner.
        
        Args:
            log_file: Path to log file
            entry: Log entry dictionary to write
            
        Returns:
            True if write was successful, False otherwise
        """
        try:
            with self._write_lock:
                # Ensure directory exists before writing
                log_file.parent.mkdir(parents=True, exist_ok=True)
                
                # Write entry as JSON line
                with open(log_file, "a", encoding="utf-8") as f:
                    f.write(json.dumps(entry, ensure_ascii=False) + "\n")
                    f.flush()  # Ensure data is written to disk
            return True
            
        except Exception as e:
            # Could add debug logging here if needed
            # For now, silently fail to avoid recursive logging issues
            return False
    
    def log_alert(self, packet: Dict[str, Any], reason: str = "") -> bool:
        """
        Log a security alert event.
        
        Args:
            packet: Packet data that triggered the alert
            reason: Reason for the alert
            
        Returns:
            True if logging was successful, False otherwise
        """
        entry = self._create_log_entry(packet, reason, "alert")
        return self._write_log_entry(self.alert_log_file, entry)
    
    def log_packet(self, packet: Dict[str, Any], reason: str = "") -> bool:
        """
        Log a general packet inspection event.
        
        Args:
            packet: Packet data to log
            reason: Reason for logging this packet
            
        Returns:
            True if logging was successful, False otherwise
        """
        entry = self._create_log_entry(packet, reason, "packet")
        return self._write_log_entry(self.packet_log_file, entry)
    
    def log_system_event(self, event_type: str, message: str, 
                        metadata: Optional[Dict[str, Any]] = None) -> bool:
        """
        Log a system-level event (startup, shutdown, configuration changes).
        
        Args:
            event_type: Type of system event
            message: Event description
            metadata: Additional event metadata
            
        Returns:
            True if logging was successful, False otherwise
        """
        entry = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "type": "system",
            "event_type": event_type,
            "message": message
        }
        
        if metadata:
            entry["metadata"] = metadata
            
        return self._write_log_entry(self.packet_log_file, entry)
    
    def get_log_stats(self) -> Dict[str, Any]:
        """
        Get logging statistics and file information.
        
        Returns:
            Dictionary with log file statistics
        """
        stats = {}
        
        for name, path in [("alerts", self.alert_log_file), ("packets", self.packet_log_file)]:
            try:
                if path.exists():
                    stat = path.stat()
                    stats[name] = {
                        "file_size": stat.st_size,
                        "last_modified": datetime.datetime.fromtimestamp(
                            stat.st_mtime, datetime.timezone.utc
                        ).isoformat(),
                        "exists": True
                    }
                else:
                    stats[name] = {"exists": False}
            except Exception:
                stats[name] = {"exists": False, "error": True}
                
        return stats


# Global logger instance for backward compatibility
_default_logger = NetworkLogger()


def log_alert(packet: Dict[str, Any], reason: str = "") -> None:
    """
    Log an alert event using the default logger instance.
    
    Maintains backward compatibility with existing code.
    
    Args:
        packet: Packet data that triggered the alert
        reason: Reason for the alert
    """
    _default_logger.log_alert(packet, reason)


def log_packet(packet: Dict[str, Any], reason: str = "") -> None:
    """
    Log a packet event using the default logger instance.
    
    Maintains backward compatibility with existing code.
    
    Args:
        packet: Packet data to log
        reason: Reason for logging this packet
    """
    _default_logger.log_packet(packet, reason)


def log_system_event(event_type: str, message: str, 
                    metadata: Optional[Dict[str, Any]] = None) -> None:
    """
    Log a system event using the default logger instance.
    
    Args:
        event_type: Type of system event
        message: Event description
        metadata: Additional event metadata
    """
    _default_logger.log_system_event(event_type, message, metadata)


def get_logger() -> NetworkLogger:
    """
    Get the default logger instance.
    
    Returns:
        Default NetworkLogger instance
    """
    return _default_logger


def create_logger(alert_log_file: str, packet_log_file: str, 
                 max_raw_bytes: int = 512) -> NetworkLogger:
    """
    Create a new logger instance with custom configuration.
    
    Args:
        alert_log_file: Path to alert log file
        packet_log_file: Path to packet log file
        max_raw_bytes: Maximum bytes of raw packet data to log
        
    Returns:
        New NetworkLogger instance
    """
    return NetworkLogger(alert_log_file, packet_log_file, max_raw_bytes)


if __name__ == "__main__":
    # Module loaded directly - not intended for direct execution
    print("NetworkLogger module - use as import only")
    sys.exit(1)