#!/usr/local/bin/python3
"""
logger.py - OPNsense Advanced Inspector Logging System

This module provides a comprehensive logging system for the Advanced Inspector
with support for different log levels, file rotation, and structured logging.
It handles both alert and packet logging with proper error handling.

Author: Pierpaolo Casati
Version: 2.0
License: BSD 2-Clause
"""

import datetime
import json
import os
import logging
import logging.handlers
from typing import Dict, Any, Optional
from pathlib import Path
from dataclasses import dataclass
from enum import Enum


class LogLevel(Enum):
    """Log levels for the inspector."""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class LogType(Enum):
    """Types of logs."""
    ALERT = "alert"
    PACKET = "packet"
    SYSTEM = "system"


@dataclass
class LogConfig:
    """Configuration for logging system."""
    alert_log_path: Path = Path("/var/log/advinspector_alerts.log")
    packet_log_path: Path = Path("/var/log/advinspector_packets.log")
    system_log_path: Path = Path("/var/log/advinspector_system.log")
    max_log_size: int = 10 * 1024 * 1024  # 10MB
    backup_count: int = 5
    log_format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    enable_console: bool = False
    max_raw_data_length: int = 512


class InspectorLogger:
    """
    Advanced logging system for the packet inspector.
    
    This class provides structured logging with file rotation, different log types,
    and proper error handling. It supports both JSON and standard log formats.
    """
    
    def __init__(self, config: Optional[LogConfig] = None):
        """
        Initialize the inspector logger.
        
        Args:
            config: Logging configuration. Uses default if None.
        """
        self.config = config or LogConfig()
        self._loggers: Dict[str, logging.Logger] = {}
        self._setup_loggers()
        
    def _setup_loggers(self) -> None:
        """
        Set up all logger instances with appropriate handlers.
        """
        # Create log directories
        for log_path in [self.config.alert_log_path, self.config.packet_log_path, self.config.system_log_path]:
            log_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Setup alert logger
        self._loggers['alert'] = self._create_logger(
            'inspector_alerts',
            self.config.alert_log_path,
            logging.INFO
        )
        
        # Setup packet logger
        self._loggers['packet'] = self._create_logger(
            'inspector_packets',
            self.config.packet_log_path,
            logging.INFO
        )
        
        # Setup system logger
        self._loggers['system'] = self._create_logger(
            'inspector_system',
            self.config.system_log_path,
            logging.INFO
        )
    
    def _create_logger(self, name: str, log_path: Path, level: int) -> logging.Logger:
        """
        Create a logger with file rotation.
        
        Args:
            name: Logger name
            log_path: Path to log file
            level: Log level
            
        Returns:
            Configured logger instance
        """
        logger = logging.getLogger(name)
        logger.setLevel(level)
        
        # Clear existing handlers
        logger.handlers.clear()
        
        # Create rotating file handler
        file_handler = logging.handlers.RotatingFileHandler(
            log_path,
            maxBytes=self.config.max_log_size,
            backupCount=self.config.backup_count
        )
        file_handler.setLevel(level)
        
        # Create formatter
        formatter = logging.Formatter(self.config.log_format)
        file_handler.setFormatter(formatter)
        
        # Add handler to logger
        logger.addHandler(file_handler)
        
        # Add console handler if enabled
        if self.config.enable_console:
            console_handler = logging.StreamHandler()
            console_handler.setLevel(level)
            console_handler.setFormatter(formatter)
            logger.addHandler(console_handler)
        
        return logger
    
    def _prepare_packet_data(self, packet: Dict[str, Any]) -> Dict[str, Any]:
        """
        Prepare packet data for logging.
        
        Args:
            packet: Raw packet data
            
        Returns:
            Cleaned packet data for logging
        """
        cleaned_packet = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "src": packet.get("src", "unknown"),
            "dst": packet.get("dst", "unknown"),
            "src_port": packet.get("src_port", 0),
            "dst_port": packet.get("dst_port", 0),
            "port": packet.get("port", 0),
            "protocol": packet.get("protocol", "unknown"),
            "interface": packet.get("interface", "unknown"),
            "application_protocol": packet.get("application_protocol", ""),
            "ip_protocol": packet.get("ip_protocol", 0)
        }
        
        # Include limited raw data if available
        raw_data = packet.get("raw", "")
        if raw_data:
            cleaned_packet["raw"] = raw_data[:self.config.max_raw_data_length]
            cleaned_packet["raw_truncated"] = len(raw_data) > self.config.max_raw_data_length
        
        return cleaned_packet
    
    def log_alert(self, packet: Dict[str, Any], reason: str = "", severity: str = "medium") -> None:
        """
        Log a security alert.
        
        Args:
            packet: Packet information
            reason: Reason for the alert
            severity: Alert severity (low, medium, high, critical)
        """
        try:
            alert_data = self._prepare_packet_data(packet)
            alert_data.update({
                "log_type": "alert",
                "reason": reason,
                "severity": severity
            })
            
            # Log as JSON for structured logging
            self._loggers['alert'].info(json.dumps(alert_data, ensure_ascii=False))
            
        except Exception as e:
            self._log_error(f"Failed to log alert: {e}")
    
    def log_packet(self, packet: Dict[str, Any], reason: str = "", action: str = "inspected") -> None:
        """
        Log a packet inspection event.
        
        Args:
            packet: Packet information
            reason: Reason for logging
            action: Action taken (allowed, blocked, alerted, etc.)
        """
        try:
            packet_data = self._prepare_packet_data(packet)
            packet_data.update({
                "log_type": "packet",
                "reason": reason,
                "action": action
            })
            
            # Log as JSON for structured logging
            self._loggers['packet'].info(json.dumps(packet_data, ensure_ascii=False))
            
        except Exception as e:
            self._log_error(f"Failed to log packet: {e}")
    
    def log_system(self, message: str, level: LogLevel = LogLevel.INFO, extra_data: Optional[Dict] = None) -> None:
        """
        Log a system event.
        
        Args:
            message: Log message
            level: Log level
            extra_data: Additional data to include
        """
        try:
            log_entry = {
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "log_type": "system",
                "message": message,
                "level": level.value
            }
            
            if extra_data:
                log_entry["extra"] = extra_data
            
            # Map our log level to logging module level
            log_level_map = {
                LogLevel.DEBUG: logging.DEBUG,
                LogLevel.INFO: logging.INFO,
                LogLevel.WARNING: logging.WARNING,
                LogLevel.ERROR: logging.ERROR,
                LogLevel.CRITICAL: logging.CRITICAL
            }
            
            python_level = log_level_map.get(level, logging.INFO)
            
            # Log as JSON
            self._loggers['system'].log(python_level, json.dumps(log_entry, ensure_ascii=False))
            
        except Exception as e:
            self._log_error(f"Failed to log system event: {e}")
    
    def _log_error(self, error_message: str) -> None:
        """
        Log an internal logging error.
        
        Args:
            error_message: Error message to log
        """
        try:
            # Use the system logger if available, otherwise fall back to stderr
            if 'system' in self._loggers:
                error_entry = {
                    "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "log_type": "logging_error",
                    "message": error_message
                }
                self._loggers['system'].error(json.dumps(error_entry, ensure_ascii=False))
            else:
                print(f"LOGGING ERROR: {error_message}", file=os.sys.stderr)
        except Exception:
            # Last resort - write to stderr
            print(f"CRITICAL LOGGING ERROR: {error_message}", file=os.sys.stderr)
    
    def get_log_statistics(self) -> Dict[str, Any]:
        """
        Get logging statistics.
        
        Returns:
            Dictionary containing logging statistics
        """
        stats = {
            "loggers": list(self._loggers.keys()),
            "config": {
                "alert_log_path": str(self.config.alert_log_path),
                "packet_log_path": str(self.config.packet_log_path),
                "system_log_path": str(self.config.system_log_path),
                "max_log_size": self.config.max_log_size,
                "backup_count": self.config.backup_count
            },
            "log_files": {}
        }
        
        # Check log file sizes
        for log_type, path in [("alert", self.config.alert_log_path),
                              ("packet", self.config.packet_log_path),
                              ("system", self.config.system_log_path)]:
            if path.exists():
                stats["log_files"][log_type] = {
                    "size": path.stat().st_size,
                    "exists": True,
                    "path": str(path)
                }
            else:
                stats["log_files"][log_type] = {
                    "exists": False,
                    "path": str(path)
                }
        
        return stats


# Global logger instance
_inspector_logger = InspectorLogger()


# Legacy functions for backward compatibility
def log_alert(packet: Dict[str, Any], reason: str = "") -> None:
    """Legacy function - use InspectorLogger.log_alert() instead."""
    _inspector_logger.log_alert(packet, reason)


def log_packet(packet: Dict[str, Any], reason: str = "") -> None:
    """Legacy function - use InspectorLogger.log_packet() instead."""
    _inspector_logger.log_packet(packet, reason)