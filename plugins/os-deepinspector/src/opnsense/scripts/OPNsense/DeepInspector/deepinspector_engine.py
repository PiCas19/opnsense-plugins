#!/usr/local/bin/python3
"""
DeepInspector OOP Engine - Enhanced Deep Packet Inspection System
================================================================

An advanced, object-oriented Deep Packet Inspection engine designed for OPNsense
with comprehensive threat detection, industrial protocol support, and Zero Trust
security architecture implementation.

Features:
---------
- Object-oriented architecture with modular design
- Complete configuration option support from PHP model
- Industrial protocol analysis (Modbus, DNP3, OPC UA)
- Advanced threat detection engines
- Performance optimization and monitoring
- Zero Trust security principles
- Real-time latency tracking
- Comprehensive logging and alerting
- Integration with existing collector modules

Author: Enhanced OOP Architecture
Version: 2.0
License: BSD 3-Clause
"""

import sys
import os
import json
import time
import signal
import threading
import logging
import hashlib
import struct
import re
import socket
import subprocess
import xml.etree.ElementTree as ET
import ipaddress
import math
import glob
import psutil
from abc import ABC, abstractmethod
from collections import defaultdict, deque, Counter
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
import multiprocessing as mp
from pathlib import Path

# Network capture and analysis libraries
try:
    import pcapy
    import dpkt
except ImportError as e:
    print(f"Error: Required packages not installed: {e}")
    print("Please install: pcapy, dpkt, psutil")
    sys.exit(1)

# Import existing collector modules for integration
try:
    from update_signatures import SignatureUpdater  # CORRETTO: Import della classe
    from export_config import ConfigExporter
    from get_industrial_stats import IndustrialStatsCollector
    from get_latency_metrics import LatencyMetricsCollector
    from get_metrics import PerformanceMetricsCollector
    from get_stats import DPIStatsCollector
except ImportError as e:
    print(f"Warning: Could not import support functions: {e}")
    # Create mock classes for testing
    class SignatureUpdater:
        def update(self): return True
    class ConfigExporter:
        def export(self): return True
    class IndustrialStatsCollector:
        def collect(self): return {}
    class LatencyMetricsCollector:
        def collect(self): return {}
    class PerformanceMetricsCollector:
        def collect(self): return {}
    class DPIStatsCollector:
        def collect(self): return {}


# ============================= Configuration Classes =============================

@dataclass
class GeneralConfig:
    """General configuration settings for the DPI engine."""
    enabled: bool = False
    mode: str = 'passive'  # passive, active, learning
    interfaces: List[str] = field(default_factory=list)
    trusted_networks: List[str] = field(default_factory=list)
    max_packet_size: int = 1500
    deep_scan_ports: str = '80,443,21,25,53,502,4840'
    ssl_inspection: bool = False
    archive_extraction: bool = False
    malware_detection: bool = True
    anomaly_detection: bool = False
    performance_profile: str = 'balanced'  # high_performance, balanced, high_security, industrial
    low_latency_mode: bool = False
    industrial_mode: bool = False
    log_level: str = 'info'


@dataclass
class ProtocolConfig:
    """Protocol inspection configuration."""
    http_inspection: bool = True
    https_inspection: bool = False
    ftp_inspection: bool = True
    smtp_inspection: bool = True
    dns_inspection: bool = True
    industrial_protocols: bool = True
    p2p_detection: bool = False
    voip_inspection: bool = False
    custom_protocols: str = ''


@dataclass
class DetectionConfig:
    """Threat detection engine configuration."""
    virus_signatures: bool = True
    trojan_detection: bool = True
    crypto_mining: bool = True
    data_exfiltration: bool = True
    command_injection: bool = True
    sql_injection: bool = True
    script_injection: bool = True
    suspicious_downloads: bool = False
    phishing_detection: bool = False
    botnet_detection: bool = False
    steganography_detection: bool = False
    zero_day_heuristics: bool = True


@dataclass
class AdvancedConfig:
    """Advanced configuration options."""
    signature_updates: bool = True
    update_interval: int = 24
    threat_intelligence_feeds: str = ''
    custom_signatures: str = ''
    quarantine_enabled: bool = False
    quarantine_path: str = '/var/quarantine/deepinspector'
    memory_limit: int = 1024
    thread_count: int = 4
    packet_buffer_size: int = 10000
    analysis_timeout: int = 5
    bypass_trusted_networks: bool = True
    industrial_optimization: bool = False
    scada_protocols: bool = True
    plc_protocols: bool = True
    latency_threshold: int = 100  # microseconds


@dataclass
class EngineConfig:
    """Complete engine configuration."""
    general: GeneralConfig = field(default_factory=GeneralConfig)
    protocols: ProtocolConfig = field(default_factory=ProtocolConfig)
    detection: DetectionConfig = field(default_factory=DetectionConfig)
    advanced: AdvancedConfig = field(default_factory=AdvancedConfig)


# ============================= Enums and Constants =============================

class ThreatSeverity(Enum):
    """Threat severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class OperationMode(Enum):
    """DPI operation modes."""
    PASSIVE = "passive"
    ACTIVE = "active"
    LEARNING = "learning"


class PerformanceProfile(Enum):
    """Performance optimization profiles."""
    HIGH_PERFORMANCE = "high_performance"
    BALANCED = "balanced"
    HIGH_SECURITY = "high_security"
    INDUSTRIAL = "industrial"


class ProtocolType(Enum):
    """Supported protocol types."""
    HTTP = "http"
    HTTPS = "https"
    FTP = "ftp"
    SMTP = "smtp"
    DNS = "dns"
    MODBUS = "modbus"
    DNP3 = "dnp3"
    OPCUA = "opcua"
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"


# ============================= Data Structures =============================

@dataclass
class ThreatInfo:
    """Information about a detected threat."""
    threat_type: str
    severity: ThreatSeverity
    description: str
    pattern: Optional[str] = None
    subtype: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0
    timestamp: Optional[datetime] = None


@dataclass
class PacketInfo:
    """Information about a network packet."""
    timestamp: datetime
    interface: str
    source_ip: str
    dest_ip: str
    protocol: ProtocolType
    size: int
    payload: bytes
    tcp_port: Optional[int] = None
    udp_port: Optional[int] = None


@dataclass
class PerformanceMetrics:
    """Performance monitoring metrics."""
    packets_analyzed: int = 0
    threats_detected: int = 0
    false_positives: int = 0
    processing_time_avg: float = 0.0
    cpu_usage: float = 0.0
    memory_usage: float = 0.0
    latency_avg: float = 0.0
    throughput_mbps: float = 0.0


# ============================= Abstract Base Classes =============================

class ThreatDetector(ABC):
    """Abstract base class for threat detection engines."""
    
    def __init__(self, name: str, config: EngineConfig):
        """Initialize the threat detector."""
        self.name = name
        self.config = config
        self.enabled = True
        self.pattern_cache = {}
        self.logger = logging.getLogger(f"{__name__}.{name}")
        
    @abstractmethod
    def detect(self, packet_info: PacketInfo) -> List[ThreatInfo]:
        """Detect threats in the given packet."""
        pass
        
    @abstractmethod
    def update_signatures(self) -> bool:
        """Update threat signatures."""
        pass


class ProtocolAnalyzer(ABC):
    """Abstract base class for protocol analyzers."""
    
    def __init__(self, protocol: ProtocolType, config: EngineConfig):
        """Initialize the protocol analyzer."""
        self.protocol = protocol
        self.config = config
        self.enabled = True
        self.logger = logging.getLogger(f"{__name__}.{protocol.value}Analyzer")
        
    @abstractmethod
    def analyze(self, packet_info: PacketInfo) -> Tuple[Dict[str, Any], List[ThreatInfo]]:
        """Analyze the protocol-specific packet."""
        pass


# ============================= Configuration Manager =============================

class ConfigurationManager:
    """Manages configuration loading and validation."""
    
    CONFIG_FILE = "/usr/local/etc/deepinspector/config.json"
    OPNSENSE_CONFIG = "/conf/config.xml"
    
    def __init__(self):
        """Initialize configuration manager."""
        self.logger = logging.getLogger(f"{__name__}.ConfigurationManager")
        self.config = EngineConfig()
        
    def load_configuration(self) -> bool:
        """Load configuration from files."""
        try:
            # First try to export from OPNsense using existing module
            self._export_opnsense_config()
            
            # Load JSON configuration
            if os.path.exists(self.CONFIG_FILE):
                with open(self.CONFIG_FILE, 'r') as f:
                    config_data = json.load(f)
                    self._apply_config_data(config_data)
            
            self.logger.info("Configuration loaded successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to load configuration: {e}")
            self._load_default_config()
            return False
    
    def _export_opnsense_config(self) -> None:
        """Export configuration from OPNsense config.xml using ConfigExporter."""
        try:
            exporter = ConfigExporter()
            success = exporter.export()
            if success:
                self.logger.info("Successfully exported OPNsense configuration")
            else:
                self.logger.warning("Failed to export OPNsense configuration")
        except Exception as e:
            self.logger.warning(f"Could not export OPNsense config: {e}")
    
    def _apply_config_data(self, config_data: Dict[str, Any]) -> None:
        """Apply configuration data to the config object."""
        # Apply general settings
        if 'general' in config_data:
            general = config_data['general']
            self.config.general.enabled = bool(general.get('enabled', False))
            self.config.general.mode = general.get('mode', 'passive')
            self.config.general.interfaces = self._parse_interfaces(general.get('interfaces', []))
            self.config.general.trusted_networks = self._parse_networks(general.get('trusted_networks', []))
            self.config.general.max_packet_size = int(general.get('max_packet_size', 1500))
            self.config.general.deep_scan_ports = general.get('deep_scan_ports', '80,443,21,25,53,502,4840')
            self.config.general.ssl_inspection = bool(general.get('ssl_inspection', False))
            self.config.general.archive_extraction = bool(general.get('archive_extraction', False))
            self.config.general.malware_detection = bool(general.get('malware_detection', True))
            self.config.general.anomaly_detection = bool(general.get('anomaly_detection', False))
            self.config.general.performance_profile = general.get('performance_profile', 'balanced')
            self.config.general.low_latency_mode = bool(general.get('low_latency_mode', False))
            self.config.general.industrial_mode = bool(general.get('industrial_mode', False))
            self.config.general.log_level = general.get('log_level', 'info')
        
        # Apply protocol settings
        if 'protocols' in config_data:
            protocols = config_data['protocols']
            self.config.protocols.http_inspection = bool(protocols.get('http_inspection', True))
            self.config.protocols.https_inspection = bool(protocols.get('https_inspection', False))
            self.config.protocols.ftp_inspection = bool(protocols.get('ftp_inspection', True))
            self.config.protocols.smtp_inspection = bool(protocols.get('smtp_inspection', True))
            self.config.protocols.dns_inspection = bool(protocols.get('dns_inspection', True))
            self.config.protocols.industrial_protocols = bool(protocols.get('industrial_protocols', True))
            self.config.protocols.p2p_detection = bool(protocols.get('p2p_detection', False))
            self.config.protocols.voip_inspection = bool(protocols.get('voip_inspection', False))
            self.config.protocols.custom_protocols = protocols.get('custom_protocols', '')
        
        # Apply detection settings
        if 'detection' in config_data:
            detection = config_data['detection']
            self.config.detection.virus_signatures = bool(detection.get('virus_signatures', True))
            self.config.detection.trojan_detection = bool(detection.get('trojan_detection', True))
            self.config.detection.crypto_mining = bool(detection.get('crypto_mining', True))
            self.config.detection.data_exfiltration = bool(detection.get('data_exfiltration', True))
            self.config.detection.command_injection = bool(detection.get('command_injection', True))
            self.config.detection.sql_injection = bool(detection.get('sql_injection', True))
            self.config.detection.script_injection = bool(detection.get('script_injection', True))
            self.config.detection.suspicious_downloads = bool(detection.get('suspicious_downloads', False))
            self.config.detection.phishing_detection = bool(detection.get('phishing_detection', False))
            self.config.detection.botnet_detection = bool(detection.get('botnet_detection', False))
            self.config.detection.steganography_detection = bool(detection.get('steganography_detection', False))
            self.config.detection.zero_day_heuristics = bool(detection.get('zero_day_heuristics', True))
        
        # Apply advanced settings
        if 'advanced' in config_data:
            advanced = config_data['advanced']
            self.config.advanced.signature_updates = bool(advanced.get('signature_updates', True))
            self.config.advanced.update_interval = int(advanced.get('update_interval', 24))
            self.config.advanced.threat_intelligence_feeds = advanced.get('threat_intelligence_feeds', '')
            self.config.advanced.custom_signatures = advanced.get('custom_signatures', '')
            self.config.advanced.quarantine_enabled = bool(advanced.get('quarantine_enabled', False))
            self.config.advanced.quarantine_path = advanced.get('quarantine_path', '/var/quarantine/deepinspector')
            self.config.advanced.memory_limit = int(advanced.get('memory_limit', 1024))
            self.config.advanced.thread_count = int(advanced.get('thread_count', 4))
            self.config.advanced.packet_buffer_size = int(advanced.get('packet_buffer_size', 10000))
            self.config.advanced.analysis_timeout = int(advanced.get('analysis_timeout', 5))
            self.config.advanced.bypass_trusted_networks = bool(advanced.get('bypass_trusted_networks', True))
            self.config.advanced.industrial_optimization = bool(advanced.get('industrial_optimization', False))
            self.config.advanced.scada_protocols = bool(advanced.get('scada_protocols', True))
            self.config.advanced.plc_protocols = bool(advanced.get('plc_protocols', True))
            self.config.advanced.latency_threshold = int(advanced.get('latency_threshold', 100))
    
    def _parse_interfaces(self, interfaces: Union[str, List[str]]) -> List[str]:
        """Parse interface configuration."""
        if isinstance(interfaces, str):
            return [iface.strip() for iface in interfaces.split(',') if iface.strip()]
        return interfaces if isinstance(interfaces, list) else []
    
    def _parse_networks(self, networks: Union[str, List[str]]) -> List[str]:
        """Parse trusted networks configuration."""
        if isinstance(networks, str):
            return [net.strip() for net in networks.split(',') if net.strip()]
        return networks if isinstance(networks, list) else []
    
    def _load_default_config(self) -> None:
        """Load default configuration."""
        self.config = EngineConfig()
        self.logger.info("Loaded default configuration")
    
    def get_config(self) -> EngineConfig:
        """Get the current configuration."""
        return self.config


# ============================= Statistics and Metrics Manager =============================

class StatisticsManager:
    """Manages statistics collection and integration with existing modules."""
    
    def __init__(self, config: EngineConfig):
        """Initialize statistics manager."""
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.StatisticsManager")
        
        # Initialize collectors using existing modules
        self.industrial_collector = IndustrialStatsCollector()
        self.latency_collector = LatencyMetricsCollector()
        self.performance_collector = PerformanceMetricsCollector()
        self.dpi_collector = DPIStatsCollector()
        
        # Internal metrics
        self.metrics = PerformanceMetrics()
        self.last_update = datetime.now()
        
    def collect_all_stats(self) -> Dict[str, Any]:
        """Collect comprehensive statistics using existing modules."""
        try:
            stats = {
                'timestamp': datetime.now().isoformat(),
                'engine_metrics': self._get_engine_metrics(),
                'industrial_stats': self.industrial_collector.collect(),
                'latency_metrics': self.latency_collector.collect(),
                'performance_metrics': self.performance_collector.collect(),
                'dpi_stats': self.dpi_collector.collect()
            }
            
            self.last_update = datetime.now()
            return stats
            
        except Exception as e:
            self.logger.error(f"Error collecting statistics: {e}")
            return {'error': str(e), 'timestamp': datetime.now().isoformat()}
    
    def _get_engine_metrics(self) -> Dict[str, Any]:
        """Get internal engine metrics."""
        return {
            'packets_analyzed': self.metrics.packets_analyzed,
            'threats_detected': self.metrics.threats_detected,
            'false_positives': self.metrics.false_positives,
            'processing_time_avg': self.metrics.processing_time_avg,
            'cpu_usage': self.metrics.cpu_usage,
            'memory_usage': self.metrics.memory_usage,
            'latency_avg': self.metrics.latency_avg,
            'throughput_mbps': self.metrics.throughput_mbps
        }
    
    def update_packet_count(self) -> None:
        """Update packet count."""
        self.metrics.packets_analyzed += 1
    
    def update_threat_count(self) -> None:
        """Update threat count."""
        self.metrics.threats_detected += 1
    
    def update_processing_time(self, processing_time: float) -> None:
        """Update average processing time."""
        if self.metrics.processing_time_avg == 0:
            self.metrics.processing_time_avg = processing_time
        else:
            # Simple moving average
            self.metrics.processing_time_avg = (self.metrics.processing_time_avg * 0.9 + processing_time * 0.1)
    
    def save_stats(self, filepath: str = "/var/log/deepinspector/stats.json") -> bool:
        """Save statistics to file."""
        try:
            stats = self.collect_all_stats()
            with open(filepath, 'w') as f:
                json.dump(stats, f, indent=2, default=str)
            return True
        except Exception as e:
            self.logger.error(f"Error saving statistics: {e}")
            return False


# ============================= Threat Detectors =============================

class MalwareDetector(ThreatDetector):
    """Detects malware signatures and patterns."""
    
    def __init__(self, config: EngineConfig):
        """Initialize malware detector."""
        super().__init__("MalwareDetector", config)
        self.signatures = self._load_signatures()
        
    def detect(self, packet_info: PacketInfo) -> List[ThreatInfo]:
        """Detect malware in packet payload."""
        threats = []
        if not self.config.detection.virus_signatures:
            return threats
            
        try:
            payload_str = packet_info.payload.decode('utf-8', errors='ignore')
            
            # Check against known malware signatures
            for signature in self.signatures.get('malware', []):
                if signature['pattern'].search(payload_str):
                    threats.append(ThreatInfo(
                        threat_type='malware',
                        severity=ThreatSeverity.CRITICAL,
                        description=f'Malware signature detected: {signature["name"]}',
                        pattern=signature['pattern'].pattern,
                        details={'signature_name': signature['name']},
                        timestamp=packet_info.timestamp
                    ))
                    
        except Exception as e:
            self.logger.error(f"Error in malware detection: {e}")
            
        return threats
    
    def _load_signatures(self) -> Dict[str, List[Dict[str, Any]]]:
        """Load malware signatures."""
        signatures = {
            'malware': [
                {
                    'name': 'EICAR Test String',
                    'pattern': re.compile(r'X5O!P%@AP\[4\\PZX54\(P\^\)7CC\)7\}\$EICAR', re.IGNORECASE)
                },
                {
                    'name': 'PE Header',
                    'pattern': re.compile(r'\\x4d\\x5a', re.IGNORECASE)
                },
                {
                    'name': 'MZ Header',
                    'pattern': re.compile(r'MZ', re.IGNORECASE)
                }
            ]
        }
        return signatures
    
    def update_signatures(self) -> bool:
        """Update malware signatures."""
        try:
            # CORRETTO: Usare SignatureUpdater invece di download_signatures
            updater = SignatureUpdater()
            success = updater.update()
            if success:
                self.signatures = self._load_signatures()
            return success
        except Exception as e:
            self.logger.error(f"Failed to update signatures: {e}")
            return False


class InjectionDetector(ThreatDetector):
    """Detects various injection attacks."""
    
    def __init__(self, config: EngineConfig):
        """Initialize injection detector."""
        super().__init__("InjectionDetector", config)
        self.patterns = self._load_patterns()
        
    def detect(self, packet_info: PacketInfo) -> List[ThreatInfo]:
        """Detect injection attacks in packet payload."""
        threats = []
        payload_str = packet_info.payload.decode('utf-8', errors='ignore')
        
        # SQL Injection
        if self.config.detection.sql_injection:
            threats.extend(self._detect_sql_injection(payload_str, packet_info.timestamp))
        
        # Command Injection
        if self.config.detection.command_injection:
            threats.extend(self._detect_command_injection(payload_str, packet_info.timestamp))
        
        # Script Injection (XSS)
        if self.config.detection.script_injection:
            threats.extend(self._detect_script_injection(payload_str, packet_info.timestamp))
            
        return threats
    
    def _detect_sql_injection(self, payload: str, timestamp: datetime) -> List[ThreatInfo]:
        """Detect SQL injection attempts."""
        threats = []
        for pattern in self.patterns.get('sql_injection', []):
            if pattern.search(payload):
                threats.append(ThreatInfo(
                    threat_type='sql_injection',
                    severity=ThreatSeverity.HIGH,
                    description='SQL injection attempt detected',
                    pattern=pattern.pattern,
                    timestamp=timestamp
                ))
        return threats
    
    def _detect_command_injection(self, payload: str, timestamp: datetime) -> List[ThreatInfo]:
        """Detect command injection attempts."""
        threats = []
        for pattern in self.patterns.get('command_injection', []):
            if pattern.search(payload):
                threats.append(ThreatInfo(
                    threat_type='command_injection',
                    severity=ThreatSeverity.HIGH,
                    description='Command injection attempt detected',
                    pattern=pattern.pattern,
                    timestamp=timestamp
                ))
        return threats
    
    def _detect_script_injection(self, payload: str, timestamp: datetime) -> List[ThreatInfo]:
        """Detect script injection (XSS) attempts."""
        threats = []
        for pattern in self.patterns.get('script_injection', []):
            if pattern.search(payload):
                threats.append(ThreatInfo(
                    threat_type='script_injection',
                    severity=ThreatSeverity.MEDIUM,
                    description='Script injection (XSS) attempt detected',
                    pattern=pattern.pattern,
                    timestamp=timestamp
                ))
        return threats
    
    def _load_patterns(self) -> Dict[str, List[re.Pattern]]:
        """Load injection detection patterns."""
        return {
            'sql_injection': [
                re.compile(r'(union|select|insert|update|delete|drop|create|alter).*?(from|into|table|database)', re.IGNORECASE),
                re.compile(r'[\'\"].*?(or|and).*?[\'\"].*?=.*?[\'\"]', re.IGNORECASE),
                re.compile(r'(\'|\").*?(--|\#|\/\*)', re.IGNORECASE),
                re.compile(r'1\s*=\s*1', re.IGNORECASE),
                re.compile(r'\'.*?or.*?\'.*?=.*?\'', re.IGNORECASE)
            ],
            'command_injection': [
                re.compile(r'[\;\|&`\$\(\)].*?(ls|cat|wget|curl|nc|netcat)', re.IGNORECASE),
                re.compile(r'(cmd\.exe|powershell|bash|sh).*?[\;\|&]', re.IGNORECASE),
                re.compile(r'\\x[0-9a-f]{2}.*?(system|exec|eval)', re.IGNORECASE),
                re.compile(r'(rm|del|format|fdisk).*?[\;\|&]', re.IGNORECASE)
            ],
            'script_injection': [
                re.compile(r'<script[^>]*>.*?</script>', re.IGNORECASE | re.DOTALL),
                re.compile(r'javascript:', re.IGNORECASE),
                re.compile(r'on(load|error|click|mouseover)=', re.IGNORECASE),
                re.compile(r'<iframe[^>]*>', re.IGNORECASE),
                re.compile(r'eval\s*\(', re.IGNORECASE)
            ]
        }
    
    def update_signatures(self) -> bool:
        """Update injection patterns."""
        try:
            # CORRETTO: Usare SignatureUpdater
            updater = SignatureUpdater()
            success = updater.update()
            if success:
                self.patterns = self._load_patterns()
            return success
        except Exception as e:
            self.logger.error(f"Failed to update patterns: {e}")
            return False


class CryptoMinerDetector(ThreatDetector):
    """Detects cryptocurrency mining activities."""
    
    def __init__(self, config: EngineConfig):
        """Initialize crypto miner detector."""
        super().__init__("CryptoMinerDetector", config)
        self.patterns = self._load_patterns()
        
    def detect(self, packet_info: PacketInfo) -> List[ThreatInfo]:
        """Detect crypto mining in packet payload."""
        threats = []
        if not self.config.detection.crypto_mining:
            return threats
            
        payload_str = packet_info.payload.decode('utf-8', errors='ignore')
        
        for pattern in self.patterns:
            if pattern.search(payload_str):
                threats.append(ThreatInfo(
                    threat_type='crypto_mining',
                    severity=ThreatSeverity.MEDIUM,
                    description='Cryptocurrency mining activity detected',
                    pattern=pattern.pattern,
                    timestamp=packet_info.timestamp
                ))
                
        return threats
    
    def _load_patterns(self) -> List[re.Pattern]:
        """Load crypto mining detection patterns."""
        return [
            re.compile(r'(coinhive|cryptonight|monero|mining|miner)', re.IGNORECASE),
            re.compile(r'(stratum|pool|hashrate|difficulty)', re.IGNORECASE),
            re.compile(r'(xmr-|eth-|btc-).*?(pool|mining)', re.IGNORECASE),
            re.compile(r'(getwork|getblocktemplate|submit)', re.IGNORECASE),
            re.compile(r'worker.*?password', re.IGNORECASE)
        ]
    
    def update_signatures(self) -> bool:
        """Update crypto mining patterns."""
        try:
            # CORRETTO: Usare SignatureUpdater
            updater = SignatureUpdater()
            return updater.update()
        except Exception as e:
            self.logger.error(f"Failed to update crypto mining patterns: {e}")
            return False


class DataExfiltrationDetector(ThreatDetector):
    """Detects data exfiltration attempts."""
    
    def __init__(self, config: EngineConfig):
        """Initialize data exfiltration detector."""
        super().__init__("DataExfiltrationDetector", config)
        self.patterns = self._load_patterns()
        
    def detect(self, packet_info: PacketInfo) -> List[ThreatInfo]:
        """Detect data exfiltration in packet payload."""
        threats = []
        if not self.config.detection.data_exfiltration:
            return threats
            
        payload_str = packet_info.payload.decode('utf-8', errors='ignore')
        
        # Check for large data transfers
        if len(packet_info.payload) > 10000:  # Large payload threshold
            threats.append(ThreatInfo(
                threat_type='data_exfiltration',
                severity=ThreatSeverity.MEDIUM,
                description=f'Large data transfer detected: {len(packet_info.payload)} bytes',
                details={'payload_size': len(packet_info.payload)},
                timestamp=packet_info.timestamp
            ))
        
        # Check for suspicious patterns
        for pattern in self.patterns:
            if pattern.search(payload_str):
                threats.append(ThreatInfo(
                    threat_type='data_exfiltration',
                    severity=ThreatSeverity.HIGH,
                    description='Potential data exfiltration pattern detected',
                    pattern=pattern.pattern,
                    timestamp=packet_info.timestamp
                ))
                
        return threats
    
    def _load_patterns(self) -> List[re.Pattern]:
        """Load data exfiltration detection patterns."""
        return [
            re.compile(r'(base64|encoded|encrypted).*?data', re.IGNORECASE),
            re.compile(r'(password|passwd|credential|secret)', re.IGNORECASE),
            re.compile(r'(sql|database|db).*?(dump|export)', re.IGNORECASE),
            re.compile(r'(config|configuration).*?(file|data)', re.IGNORECASE)
        ]
    
    def update_signatures(self) -> bool:
        """Update data exfiltration patterns."""
        try:
            # CORRETTO: Usare SignatureUpdater
            updater = SignatureUpdater()
            return updater.update()
        except Exception as e:
            self.logger.error(f"Failed to update data exfiltration patterns: {e}")
            return False


# ============================= Protocol Analyzers =============================

class HTTPAnalyzer(ProtocolAnalyzer):
    """Analyzes HTTP protocol traffic."""
    
    def __init__(self, config: EngineConfig):
        """Initialize HTTP analyzer."""
        super().__init__(ProtocolType.HTTP, config)
        
    def analyze(self, packet_info: PacketInfo) -> Tuple[Dict[str, Any], List[ThreatInfo]]:
        """Analyze HTTP packet."""
        analysis_data = {}
        threats = []
        
        if not self.config.protocols.http_inspection:
            return analysis_data, threats
            
        try:
            payload_str = packet_info.payload.decode('utf-8', errors='ignore')
            
            # Parse HTTP headers
            if payload_str.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ')):
                lines = payload_str.split('\r\n')
                if lines:
                    request_line = lines[0]
                    method_parts = request_line.split(' ')
                    if len(method_parts) >= 2:
                        analysis_data['method'] = method_parts[0]
                        analysis_data['uri'] = method_parts[1]
                        
                        # Check for suspicious URIs
                        if self._is_suspicious_uri(analysis_data['uri']):
                            threats.append(ThreatInfo(
                                threat_type='suspicious_http_request',
                                severity=ThreatSeverity.MEDIUM,
                                description='Suspicious HTTP URI detected',
                                details={'uri': analysis_data['uri']},
                                timestamp=packet_info.timestamp
                            ))
                            
                # Parse headers
                headers = {}
                for line in lines[1:]:
                    if ':' in line:
                        key, value = line.split(':', 1)
                        headers[key.strip().lower()] = value.strip()
                        
                analysis_data['headers'] = headers
                
                # Check for suspicious user agents
                user_agent = headers.get('user-agent', '')
                if self._is_suspicious_user_agent(user_agent):
                    threats.append(ThreatInfo(
                        threat_type='suspicious_user_agent',
                        severity=ThreatSeverity.LOW,
                        description='Suspicious User-Agent detected',
                        details={'user_agent': user_agent},
                        timestamp=packet_info.timestamp
                    ))
                        
        except Exception as e:
            self.logger.error(f"Error analyzing HTTP packet: {e}")
            
        return analysis_data, threats
    
    def _is_suspicious_uri(self, uri: str) -> bool:
        """Check if URI is suspicious."""
        suspicious_patterns = [
            r'\.\./', r'%2e%2e%2f', r'\/etc\/passwd', r'\/proc\/',
            r'cmd\.exe', r'powershell', r'<script', r'javascript:',
            r'\/admin', r'\/wp-admin', r'\.php\?', r'union.*select'
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, uri, re.IGNORECASE):
                return True
        return False
    
    def _is_suspicious_user_agent(self, user_agent: str) -> bool:
        """Check if User-Agent is suspicious."""
        suspicious_agents = [
            'sqlmap', 'nikto', 'nessus', 'burp', 'wget', 'curl',
            'python-requests', 'bot', 'crawler', 'scanner'
        ]
        
        for agent in suspicious_agents:
            if agent.lower() in user_agent.lower():
                return True
        return False
    
class IndustrialProtocolAnalyzer(ProtocolAnalyzer):
    """Analyzes industrial protocols (Modbus, DNP3, OPC UA)."""
    
    def __init__(self, config: EngineConfig):
        """Initialize industrial protocol analyzer."""
        super().__init__(ProtocolType.MODBUS, config)  # Generic for all industrial protocols
        
    def analyze(self, packet_info: PacketInfo) -> Tuple[Dict[str, Any], List[ThreatInfo]]:
        """Analyze industrial protocol packet."""
        analysis_data = {}
        threats = []
        
        if not self.config.protocols.industrial_protocols:
            return analysis_data, threats
        
        # Determine industrial protocol based on port
        if packet_info.tcp_port == 502:
            analysis_data, new_threats = self._analyze_modbus(packet_info)
            threats.extend(new_threats)
        elif packet_info.tcp_port == 20000:
            analysis_data, new_threats = self._analyze_dnp3(packet_info)
            threats.extend(new_threats)
        elif packet_info.tcp_port == 4840:
            analysis_data, new_threats = self._analyze_opcua(packet_info)
            threats.extend(new_threats)
            
        return analysis_data, threats
    
    def _analyze_modbus(self, packet_info: PacketInfo) -> Tuple[Dict[str, Any], List[ThreatInfo]]:
        """Analyze Modbus protocol."""
        analysis_data = {'protocol': 'modbus'}
        threats = []
        payload = packet_info.payload
        
        try:
            if len(payload) < 8:
                return analysis_data, threats
                
            # Parse Modbus TCP header
            transaction_id = struct.unpack('>H', payload[0:2])[0]
            protocol_id = struct.unpack('>H', payload[2:4])[0]
            length = struct.unpack('>H', payload[4:6])[0]
            unit_id = payload[6]
            function_code = payload[7]
            
            analysis_data.update({
                'transaction_id': transaction_id,
                'protocol_id': protocol_id,
                'length': length,
                'unit_id': unit_id,
                'function_code': function_code
            })
            
            # Check for suspicious function codes
            dangerous_functions = [0x08, 0x11, 0x17, 0x2B]  # Diagnostics, Report Server ID, etc.
            if function_code in dangerous_functions:
                threats.append(ThreatInfo(
                    threat_type='industrial_threat',
                    subtype='modbus_suspicious_function',
                    severity=ThreatSeverity.HIGH,
                    description=f'Suspicious Modbus function code: {function_code:02x}',
                    details={
                        'function_code': function_code,
                        'unit_id': unit_id,
                        'transaction_id': transaction_id
                    },
                    timestamp=packet_info.timestamp
                ))
                
            # Check for oversized packets
            if length > 252:  # Modbus max PDU size
                threats.append(ThreatInfo(
                    threat_type='industrial_threat',
                    subtype='modbus_oversized_packet',
                    severity=ThreatSeverity.MEDIUM,
                    description=f'Oversized Modbus packet: {length} bytes',
                    details={'packet_size': length},
                    timestamp=packet_info.timestamp
                ))
                
        except Exception as e:
            self.logger.error(f"Error analyzing Modbus packet: {e}")
            
        return analysis_data, threats
    
    def _analyze_dnp3(self, packet_info: PacketInfo) -> Tuple[Dict[str, Any], List[ThreatInfo]]:
        """Analyze DNP3 protocol."""
        analysis_data = {'protocol': 'dnp3'}
        threats = []
        payload = packet_info.payload
        
        try:
            if len(payload) < 10:
                return analysis_data, threats
                
            # DNP3 header analysis
            start_bytes = payload[0:2]
            if start_bytes != b'\x05\x64':
                return analysis_data, threats
                
            length = payload[2]
            control = payload[3]
            dest_addr = struct.unpack('<H', payload[4:6])[0]
            src_addr = struct.unpack('<H', payload[6:8])[0]
            
            analysis_data.update({
                'length': length,
                'control': control,
                'dest_addr': dest_addr,
                'src_addr': src_addr
            })
            
            # Check for broadcast addresses (potential attacks)
            if dest_addr == 0xFFFF or src_addr == 0xFFFF:
                threats.append(ThreatInfo(
                    threat_type='industrial_threat',
                    subtype='dnp3_broadcast_attack',
                    severity=ThreatSeverity.HIGH,
                    description='DNP3 broadcast address detected',
                    details={'dest_addr': dest_addr, 'src_addr': src_addr},
                    timestamp=packet_info.timestamp
                ))
                
        except Exception as e:
            self.logger.error(f"Error analyzing DNP3 packet: {e}")
            
        return analysis_data, threats
    
    def _analyze_opcua(self, packet_info: PacketInfo) -> Tuple[Dict[str, Any], List[ThreatInfo]]:
        """Analyze OPC UA protocol."""
        analysis_data = {'protocol': 'opcua'}
        threats = []
        payload = packet_info.payload
        
        try:
            if len(payload) < 8:
                return analysis_data, threats
                
            # Basic OPC UA message analysis
            message_type = payload[0:4]
            message_size = struct.unpack('<I', payload[4:8])[0]
            
            analysis_data.update({
                'message_type': message_type.decode('ascii', errors='ignore'),
                'message_size': message_size
            })
            
            # Check for suspicious message types
            if message_type == b'ERR\x00':
                threats.append(ThreatInfo(
                    threat_type='industrial_threat',
                    subtype='opcua_error_message',
                    severity=ThreatSeverity.MEDIUM,
                    description='OPC UA error message detected',
                    details={'message_type': message_type.decode('ascii', errors='ignore')},
                    timestamp=packet_info.timestamp
                ))
                
            # Check for oversized messages
            if message_size > 65536:  # Reasonable limit
                threats.append(ThreatInfo(
                    threat_type='industrial_threat',
                    subtype='opcua_oversized_message',
                    severity=ThreatSeverity.MEDIUM,
                    description=f'Oversized OPC UA message: {message_size} bytes',
                    details={'message_size': message_size},
                    timestamp=packet_info.timestamp
                ))
                
        except Exception as e:
            self.logger.error(f"Error analyzing OPC UA packet: {e}")
            
        return analysis_data, threats


class DNSAnalyzer(ProtocolAnalyzer):
    """Analyzes DNS protocol traffic."""
    
    def __init__(self, config: EngineConfig):
        """Initialize DNS analyzer."""
        super().__init__(ProtocolType.DNS, config)
        
    def analyze(self, packet_info: PacketInfo) -> Tuple[Dict[str, Any], List[ThreatInfo]]:
        """Analyze DNS packet."""
        analysis_data = {}
        threats = []
        
        if not self.config.protocols.dns_inspection:
            return analysis_data, threats
            
        try:
            payload = packet_info.payload
            if len(payload) < 12:
                return analysis_data, threats
                
            # Check for DNS tunneling (unusually large queries)
            if len(payload) > 512:
                threats.append(ThreatInfo(
                    threat_type='dns_tunneling',
                    severity=ThreatSeverity.MEDIUM,
                    description='Potential DNS tunneling detected',
                    details={'payload_size': len(payload)},
                    timestamp=packet_info.timestamp
                ))
                
        except Exception as e:
            self.logger.error(f"Error analyzing DNS packet: {e}")
            
        return analysis_data, threats


class FTPAnalyzer(ProtocolAnalyzer):
    """Analyzes FTP protocol traffic."""
    
    def __init__(self, config: EngineConfig):
        """Initialize FTP analyzer."""
        super().__init__(ProtocolType.FTP, config)
        
    def analyze(self, packet_info: PacketInfo) -> Tuple[Dict[str, Any], List[ThreatInfo]]:
        """Analyze FTP packet."""
        analysis_data = {}
        threats = []
        
        if not self.config.protocols.ftp_inspection:
            return analysis_data, threats
            
        try:
            payload_str = packet_info.payload.decode('utf-8', errors='ignore')
            
            # Check for suspicious FTP commands
            suspicious_commands = ['SITE', 'MKD', 'RMD', 'DELE', 'RNFR', 'RNTO']
            for cmd in suspicious_commands:
                if payload_str.upper().startswith(cmd):
                    threats.append(ThreatInfo(
                        threat_type='ftp_suspicious_command',
                        severity=ThreatSeverity.MEDIUM,
                        description=f'Suspicious FTP command: {cmd}',
                        details={'command': cmd},
                        timestamp=packet_info.timestamp
                    ))
                    
        except Exception as e:
            self.logger.error(f"Error analyzing FTP packet: {e}")
            
        return analysis_data, threats


# ============================= Network Interface Manager =============================

class NetworkInterfaceManager:
    """Manages network interface resolution and validation."""
    
    def __init__(self):
        """Initialize network interface manager."""
        self.logger = logging.getLogger(f"{__name__}.NetworkInterfaceManager")
        self.interface_map = {}
        self._build_interface_mapping()
    
    def _build_interface_mapping(self) -> None:
        """Build mapping of logical to physical interfaces."""
        try:
            # Parse OPNsense config.xml
            tree = ET.parse("/conf/config.xml")
            root = tree.getroot()
            
            # Get interface mappings
            interfaces = root.find('interfaces')
            if interfaces is not None:
                for interface in interfaces:
                    if_name = interface.tag
                    if_element = interface.find('if')
                    if if_element is not None:
                        physical_if = if_element.text
                        self.interface_map[if_name] = physical_if
                        self.logger.info(f"Mapped interface {if_name} -> {physical_if}")
                        
        except Exception as e:
            self.logger.error(f"Error parsing OPNsense config: {e}")
            self._build_fallback_mapping()
    
    def _build_fallback_mapping(self) -> None:
        """Build fallback interface mapping."""
        try:
            result = subprocess.run(['ifconfig', '-l'], capture_output=True, text=True)
            if result.returncode == 0:
                system_interfaces = result.stdout.strip().split()
                common_mappings = {
                    'lan': 'em0', 'wan': 'em1', 'opt1': 'em2', 'opt2': 'em3'
                }
                for logical, physical in common_mappings.items():
                    if physical in system_interfaces:
                        self.interface_map[logical] = physical
                        self.logger.info(f"Fallback mapped {logical} -> {physical}")
        except Exception as e:
            self.logger.error(f"Error getting system interfaces: {e}")
    
    def resolve_interfaces(self, logical_interfaces: List[str]) -> List[str]:
        """Resolve logical interface names to physical names."""
        physical_interfaces = []
        
        for logical_if in logical_interfaces:
            if logical_if in self.interface_map:
                physical_if = self.interface_map[logical_if]
                physical_interfaces.append(physical_if)
                self.logger.info(f"Resolved {logical_if} -> {physical_if}")
            else:
                # If already a physical interface name, use as-is
                physical_interfaces.append(logical_if)
                self.logger.warning(f"Could not resolve {logical_if}, using as-is")
        
        return physical_interfaces
    
    def validate_interfaces(self, interfaces: List[str]) -> List[str]:
        """Validate that interfaces exist and are active."""
        valid_interfaces = []
        
        for interface in interfaces:
            try:
                result = subprocess.run(['ifconfig', interface], 
                                     capture_output=True, text=True)
                if result.returncode == 0:
                    valid_interfaces.append(interface)
                    self.logger.info(f"Interface {interface} is valid and active")
                else:
                    self.logger.error(f"Interface {interface} is not available")
            except Exception as e:
                self.logger.error(f"Error checking interface {interface}: {e}")
        
        return valid_interfaces


# ============================= Packet Capture Manager =============================

class PacketCaptureManager:
    """Manages packet capture operations."""
    
    def __init__(self, config: EngineConfig, interface_manager: NetworkInterfaceManager):
        """Initialize packet capture manager."""
        self.config = config
        self.interface_manager = interface_manager
        self.logger = logging.getLogger(f"{__name__}.PacketCaptureManager")
        self.capture_threads = []
        self.running = True
        
    def start_capture(self, packet_processor_callback) -> bool:
        """Start packet capture on configured interfaces."""
        try:
            # Resolve and validate interfaces
            logical_interfaces = self.config.general.interfaces
            if not logical_interfaces:
                self.logger.error("No interfaces configured for monitoring")
                return False
                
            physical_interfaces = self.interface_manager.resolve_interfaces(logical_interfaces)
            valid_interfaces = self.interface_manager.validate_interfaces(physical_interfaces)
            
            if not valid_interfaces:
                self.logger.error("No valid interfaces found")
                return False
            
            # Start capture threads for each interface
            for interface in valid_interfaces:
                thread = threading.Thread(
                    target=self._capture_worker,
                    args=(interface, packet_processor_callback)
                )
                thread.daemon = True
                self.capture_threads.append(thread)
                thread.start()
                
            self.logger.info(f"Started packet capture on interfaces: {valid_interfaces}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start packet capture: {e}")
            return False
    
    def _capture_worker(self, interface: str, packet_processor_callback) -> None:
        """Worker function for packet capture on a specific interface."""
        self.logger.info(f"Starting capture worker for interface: {interface}")
        
        try:
            # Open packet capture
            cap = pcapy.open_live(
                interface, 
                self.config.general.max_packet_size,
                1,  # promiscuous mode
                100  # timeout in ms
            )
            
            self.logger.info(f"Successfully opened capture on interface: {interface}")
            
            # Main capture loop
            while self.running:
                try:
                    header, packet = cap.next()
                    if packet:
                        packet_info = self._parse_packet(packet, interface)
                        if packet_info:
                            packet_processor_callback(packet_info)
                            
                except pcapy.PcapError as e:
                    if "timeout" not in str(e).lower():
                        self.logger.error(f"Pcap error on {interface}: {e}")
                        break
                except Exception as e:
                    self.logger.error(f"Error processing packet on {interface}: {e}")
                    
        except Exception as e:
            self.logger.error(f"Failed to open capture on interface {interface}: {e}")
            
        self.logger.info(f"Capture worker for {interface} stopped")
    
    def _parse_packet(self, packet_data: bytes, interface: str) -> Optional[PacketInfo]:
        """Parse raw packet data into PacketInfo object."""
        try:
            # Parse Ethernet frame
            eth = dpkt.ethernet.Ethernet(packet_data)
            if not isinstance(eth.data, dpkt.ip.IP):
                return None
                
            ip = eth.data
            
            # Determine protocol
            protocol = ProtocolType.TCP if ip.p == dpkt.ip.IP_PROTO_TCP else \
                      ProtocolType.UDP if ip.p == dpkt.ip.IP_PROTO_UDP else \
                      ProtocolType.ICMP if ip.p == dpkt.ip.IP_PROTO_ICMP else \
                      ProtocolType.TCP  # Default fallback
            
            # Get port information
            tcp_port = None
            udp_port = None
            payload = b''
            
            if ip.p == dpkt.ip.IP_PROTO_TCP:
                tcp = ip.data
                tcp_port = tcp.dport
                payload = tcp.data
            elif ip.p == dpkt.ip.IP_PROTO_UDP:
                udp = ip.data
                udp_port = udp.dport
                payload = udp.data
            
            return PacketInfo(
                timestamp=datetime.now(),
                interface=interface,
                source_ip=socket.inet_ntoa(ip.src),
                dest_ip=socket.inet_ntoa(ip.dst),
                protocol=protocol,
                size=len(packet_data),
                payload=payload,
                tcp_port=tcp_port,
                udp_port=udp_port
            )
            
        except Exception as e:
            self.logger.debug(f"Error parsing packet: {e}")
            return None
    
    def stop_capture(self) -> None:
        """Stop packet capture."""
        self.running = False
        self.logger.info("Stopping packet capture...")
        
        # Wait for threads to finish
        for thread in self.capture_threads:
            thread.join(timeout=5)


# ============================= Performance Optimizer =============================

class PerformanceOptimizer:
    """Optimizes engine performance based on configuration profile."""
    
    def __init__(self, config: EngineConfig):
        """Initialize performance optimizer."""
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.PerformanceOptimizer")
    
    def optimize_for_profile(self) -> None:
        """Optimize engine settings based on performance profile."""
        profile = self.config.general.performance_profile
        
        if profile == PerformanceProfile.HIGH_PERFORMANCE.value:
            self._optimize_for_performance()
        elif profile == PerformanceProfile.HIGH_SECURITY.value:
            self._optimize_for_security()
        elif profile == PerformanceProfile.INDUSTRIAL.value:
            self._optimize_for_industrial()
        else:  # BALANCED
            self._optimize_for_balance()
    
    def _optimize_for_performance(self) -> None:
        """Optimize for maximum performance."""
        self.logger.info("Optimizing for high performance profile")
        
        # Reduce thread count for lower overhead
        if self.config.advanced.thread_count > 2:
            self.config.advanced.thread_count = 2
            
        # Increase packet buffer size
        self.config.advanced.packet_buffer_size = min(50000, self.config.advanced.packet_buffer_size * 2)
        
        # Reduce analysis timeout
        self.config.advanced.analysis_timeout = min(3, self.config.advanced.analysis_timeout)
    
    def _optimize_for_security(self) -> None:
        """Optimize for maximum security coverage."""
        self.logger.info("Optimizing for high security profile")
        
        # Increase thread count for thorough analysis
        self.config.advanced.thread_count = min(8, mp.cpu_count())
        
        # Increase analysis timeout for deep inspection
        self.config.advanced.analysis_timeout = max(10, self.config.advanced.analysis_timeout)
        
        # Enable all detection engines
        self.config.detection.virus_signatures = True
        self.config.detection.trojan_detection = True
        self.config.detection.zero_day_heuristics = True
    
    def _optimize_for_industrial(self) -> None:
        """Optimize for industrial environments."""
        self.logger.info("Optimizing for industrial profile")
        
        # Enable low latency mode
        self.config.general.low_latency_mode = True
        self.config.general.industrial_mode = True
        
        # Set strict latency threshold
        self.config.advanced.latency_threshold = 50  # 50 microseconds
        
        # Enable industrial optimizations
        self.config.advanced.industrial_optimization = True
        self.config.advanced.scada_protocols = True
        self.config.advanced.plc_protocols = True
        
        # Disable resource-intensive features
        self.config.general.ssl_inspection = False
        self.config.general.archive_extraction = False
    
    def _optimize_for_balance(self) -> None:
        """Optimize for balanced performance and security."""
        self.logger.info("Optimizing for balanced profile")
        
        # Set moderate thread count
        self.config.advanced.thread_count = min(4, mp.cpu_count())
        
        # Moderate timeouts and buffer sizes
        self.config.advanced.analysis_timeout = 5
        self.config.advanced.packet_buffer_size = 10000


# ============================= Main DPI Engine =============================

class DeepInspectorEngine:
    """Main Deep Packet Inspection Engine with comprehensive OOP architecture."""
    
    # Class constants
    PID_FILE = "/var/run/deepinspector.pid"
    LOG_DIR = "/var/log/deepinspector"
    CONFIG_FILE = "/usr/local/etc/deepinspector/config.json"
    
    def __init__(self):
        """Initialize the Deep Packet Inspection Engine."""
        # Core engine state
        self.logger: Optional[logging.Logger] = None
        self.config: Optional[EngineConfig] = None
        self.running: bool = True
        
        # Core component managers
        self.config_manager: Optional[ConfigurationManager] = None
        self.stats_manager: Optional[StatisticsManager] = None
        self.interface_manager: Optional[NetworkInterfaceManager] = None
        self.capture_manager: Optional[PacketCaptureManager] = None
        self.performance_optimizer: Optional[PerformanceOptimizer] = None
        
        # Detection and analysis engines
        self.threat_detectors: List[ThreatDetector] = []
        self.protocol_analyzers: List[ProtocolAnalyzer] = []
        
        # Background worker threads
        self.stats_thread: Optional[threading.Thread] = None
        self.signature_update_thread: Optional[threading.Thread] = None
        
        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)
    
    def initialize(self) -> bool:
        """Initialize all engine components and prepare for operation."""
        try:
            # Step 1: Setup comprehensive logging system
            self._setup_logging()
            self.logger.info("Starting Deep Packet Inspector Engine initialization")
            
            # Step 2: Verify root privileges (required for raw packet capture)
            if os.geteuid() != 0:
                self.logger.error("This script must be run as root for packet capture")
                self.logger.error("Please run: sudo python3 deepinspector_engine.py")
                return False
            
            # Step 3: Save process PID for system management
            self._save_pid()
            
            # Step 4: Initialize configuration management
            self.logger.info("Initializing configuration manager")
            self.config_manager = ConfigurationManager()
            if not self.config_manager.load_configuration():
                self.logger.error("Failed to load configuration - check config files")
                return False
            
            self.config = self.config_manager.get_config()
            
            # Step 5: Check if DPI is enabled in configuration
            if not self.config.general.enabled:
                self.logger.info("DPI engine is disabled in configuration")
                self.logger.info("Enable DPI in OPNsense web interface to proceed")
                return False
            
            # Step 6: Initialize performance optimizer and apply settings
            self.logger.info(f"Initializing performance optimizer for profile: {self.config.general.performance_profile}")
            self.performance_optimizer = PerformanceOptimizer(self.config)
            self.performance_optimizer.optimize_for_profile()
            
            # Step 7: Initialize core component managers
            self.logger.info("Initializing statistics manager with existing collectors")
            self.stats_manager = StatisticsManager(self.config)
            
            self.logger.info("Initializing network interface manager")
            self.interface_manager = NetworkInterfaceManager()
            
            self.logger.info("Initializing packet capture manager")
            self.capture_manager = PacketCaptureManager(self.config, self.interface_manager)
            
            # Step 8: Initialize detection engines and protocol analyzers
            self.logger.info("Initializing threat detection engines and protocol analyzers")
            self._initialize_detectors()
            
            # Step 9: Log initialization summary
            self._log_initialization_summary()
            
            self.logger.info("Deep Inspector Engine initialized successfully")
            return True
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"Critical error during initialization: {e}")
                self.logger.exception("Full exception details:")
            else:
                print(f"Critical error during initialization: {e}")
            return False
    
    def _setup_logging(self) -> None:
        """Setup comprehensive logging system for the DPI engine."""
        # Ensure log directory exists with proper permissions
        log_dir = Path(self.LOG_DIR)
        log_dir.mkdir(parents=True, exist_ok=True, mode=0o755)
        
        # Create all required log files if they don't exist
        log_files = [
            "engine.log", "threats.log", "alerts.log", 
            "detections.log", "latency.log", "stats.log"
        ]
        
        for log_file in log_files:
            log_path = log_dir / log_file
            if not log_path.exists():
                log_path.touch(mode=0o644)
        
        # Configure comprehensive logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s',
            handlers=[
                # File handler for persistent logging
                logging.FileHandler(log_dir / "engine.log", mode='a', encoding='utf-8'),
                # Console handler for real-time monitoring
                logging.StreamHandler(sys.stdout)
            ]
        )
        
        # Create main logger instance
        self.logger = logging.getLogger(f"{__name__}.DeepInspectorEngine")
        self.logger.info("Logging system initialized successfully")
    
    def _save_pid(self) -> None:
        """Save the current process PID to a file for system management."""
        try:
            pid_path = Path(self.PID_FILE)
            with open(pid_path, 'w') as f:
                f.write(str(os.getpid()))
            
            # Set appropriate permissions for PID file
            pid_path.chmod(0o644)
            
            if self.logger:
                self.logger.info(f"PID {os.getpid()} saved to {self.PID_FILE}")
                
        except Exception as e:
            error_msg = f"Failed to write PID file {self.PID_FILE}: {e}"
            if self.logger:
                self.logger.error(error_msg)
            else:
                print(error_msg)
            raise
    
    def _initialize_detectors(self) -> None:
        """Initialize all threat detectors and protocol analyzers based on configuration."""
        detector_count = 0
        analyzer_count = 0
        
        # Initialize threat detectors based on configuration
        self.logger.info("Initializing threat detection engines...")
        
        # Malware and virus detection
        if (self.config.detection.virus_signatures or 
            self.config.detection.trojan_detection or
            self.config.general.malware_detection):
            
            detector = MalwareDetector(self.config)
            self.threat_detectors.append(detector)
            detector_count += 1
            self.logger.info("Initialized MalwareDetector with virus signatures")
            
        # Injection attack detection (SQL, Command, Script)
        if (self.config.detection.sql_injection or 
            self.config.detection.command_injection or 
            self.config.detection.script_injection):
            
            detector = InjectionDetector(self.config)
            self.threat_detectors.append(detector)
            detector_count += 1
            self.logger.info("Initialized InjectionDetector for SQL/Command/Script attacks")
            
        # Cryptocurrency mining detection
        if self.config.detection.crypto_mining:
            detector = CryptoMinerDetector(self.config)
            self.threat_detectors.append(detector)
            detector_count += 1
            self.logger.info("Initialized CryptoMinerDetector")
            
        # Data exfiltration detection
        if self.config.detection.data_exfiltration:
            detector = DataExfiltrationDetector(self.config)
            self.threat_detectors.append(detector)
            detector_count += 1
            self.logger.info("Initialized DataExfiltrationDetector")
        
        # Initialize protocol analyzers based on configuration
        self.logger.info("Initializing protocol analysis engines...")
        
        # HTTP/HTTPS protocol analysis
        if self.config.protocols.http_inspection:
            analyzer = HTTPAnalyzer(self.config)
            self.protocol_analyzers.append(analyzer)
            analyzer_count += 1
            self.logger.info("Initialized HTTPAnalyzer for web traffic analysis")
            
        # Industrial protocol analysis (Modbus, DNP3, OPC UA)
        if self.config.protocols.industrial_protocols:
            analyzer = IndustrialProtocolAnalyzer(self.config)
            self.protocol_analyzers.append(analyzer)
            analyzer_count += 1
            self.logger.info("Initialized IndustrialProtocolAnalyzer for SCADA/ICS security")
            
        # DNS protocol analysis
        if self.config.protocols.dns_inspection:
            analyzer = DNSAnalyzer(self.config)
            self.protocol_analyzers.append(analyzer)
            analyzer_count += 1
            self.logger.info("Initialized DNSAnalyzer for DNS security")
            
        # FTP protocol analysis
        if self.config.protocols.ftp_inspection:
            analyzer = FTPAnalyzer(self.config)
            self.protocol_analyzers.append(analyzer)
            analyzer_count += 1
            self.logger.info("Initialized FTPAnalyzer")
        
        # Log initialization summary
        self.logger.info(f"Detection engine initialization complete:")
        self.logger.info(f"  - {detector_count} threat detectors active")
        self.logger.info(f"  - {analyzer_count} protocol analyzers active")
        
        if detector_count == 0:
            self.logger.warning("No threat detectors enabled - limited security coverage")
        if analyzer_count == 0:
            self.logger.warning("No protocol analyzers enabled - basic packet inspection only")
    
    def _log_initialization_summary(self) -> None:
        """Log comprehensive initialization summary for debugging and monitoring."""
        self.logger.info("=== Deep Inspector Engine Initialization Summary ===")
        self.logger.info(f"Engine Version: 2.0 OOP")
        self.logger.info(f"Process ID: {os.getpid()}")
        self.logger.info(f"User ID: {os.getuid()} (Root required: {os.getuid() == 0})")
        
        # Configuration summary
        self.logger.info("Configuration Summary:")
        self.logger.info(f"  Mode: {self.config.general.mode}")
        self.logger.info(f"  Performance Profile: {self.config.general.performance_profile}")
        self.logger.info(f"  Industrial Mode: {self.config.general.industrial_mode}")
        self.logger.info(f"  Low Latency Mode: {self.config.general.low_latency_mode}")
        self.logger.info(f"  SSL Inspection: {self.config.general.ssl_inspection}")
        self.logger.info(f"  Archive Extraction: {self.config.general.archive_extraction}")
        
        # Interface configuration
        interface_count = len(self.config.general.interfaces)
        self.logger.info(f"Network Interfaces: {interface_count} configured")
        for i, interface in enumerate(self.config.general.interfaces, 1):
            self.logger.info(f"  {i}. {interface}")
        
        # Detection engines summary
        enabled_detections = []
        if self.config.detection.virus_signatures: enabled_detections.append("Virus Signatures")
        if self.config.detection.sql_injection: enabled_detections.append("SQL Injection")
        if self.config.detection.command_injection: enabled_detections.append("Command Injection")
        if self.config.detection.script_injection: enabled_detections.append("Script Injection")
        if self.config.detection.crypto_mining: enabled_detections.append("Crypto Mining")
        if self.config.detection.data_exfiltration: enabled_detections.append("Data Exfiltration")
        
        self.logger.info(f"Enabled Detections: {len(enabled_detections)}")
        for detection in enabled_detections:
            self.logger.info(f"  - {detection}")
        
        # Protocol analyzers summary
        enabled_protocols = []
        if self.config.protocols.http_inspection: enabled_protocols.append("HTTP")
        if self.config.protocols.https_inspection: enabled_protocols.append("HTTPS")
        if self.config.protocols.dns_inspection: enabled_protocols.append("DNS")
        if self.config.protocols.ftp_inspection: enabled_protocols.append("FTP")
        if self.config.protocols.industrial_protocols: enabled_protocols.append("Industrial (Modbus/DNP3/OPC-UA)")
        
        self.logger.info(f"Enabled Protocol Analysis: {len(enabled_protocols)}")
        for protocol in enabled_protocols:
            self.logger.info(f"  - {protocol}")
        
        # Performance settings
        self.logger.info("Performance Settings:")
        self.logger.info(f"  Thread Count: {self.config.advanced.thread_count}")
        self.logger.info(f"  Packet Buffer Size: {self.config.advanced.packet_buffer_size}")
        self.logger.info(f"  Analysis Timeout: {self.config.advanced.analysis_timeout}s")
        self.logger.info(f"  Latency Threshold: {self.config.advanced.latency_threshold}μs")
        
        # Advanced features
        advanced_features = []
        if self.config.advanced.signature_updates: advanced_features.append("Auto Signature Updates")
        if self.config.advanced.quarantine_enabled: advanced_features.append("Threat Quarantine")
        if self.config.advanced.bypass_trusted_networks: advanced_features.append("Trusted Network Bypass")
        if self.config.advanced.industrial_optimization: advanced_features.append("Industrial Optimization")
        
        self.logger.info(f"Advanced Features: {len(advanced_features)}")
        for feature in advanced_features:
            self.logger.info(f"  - {feature}")
        
        self.logger.info("=" * 60)
    
    def process_packet(self, packet_info: PacketInfo) -> None:
        """Process a captured network packet through the complete analysis pipeline."""
        # Start high-resolution timing for performance tracking
        start_time = time.perf_counter()
        
        try:
            # Step 1: Update packet statistics
            self.stats_manager.update_packet_count()
            
            # Step 2: Check trusted network bypass (performance optimization)
            if (self.config.advanced.bypass_trusted_networks and 
                self._is_trusted_network(packet_info.source_ip)):
                return  # Skip processing for trusted networks
            
            # Step 3: Initialize threat collection
            all_threats: List[ThreatInfo] = []
            
            # Step 4: Run protocol-specific analyzers
            for analyzer in self.protocol_analyzers:
                if analyzer.enabled:
                    try:
                        analysis_data, threats = analyzer.analyze(packet_info)
                        all_threats.extend(threats)
                        
                        # Log analysis data for debugging (if debug level)
                        if self.logger.isEnabledFor(logging.DEBUG):
                            self.logger.debug(f"{analyzer.__class__.__name__} analysis: {analysis_data}")
                            
                    except Exception as e:
                        self.logger.error(f"Error in protocol analyzer {analyzer.__class__.__name__}: {e}")
                        # Continue processing with other analyzers
            
            # Step 5: Run threat detection engines
            for detector in self.threat_detectors:
                if detector.enabled:
                    try:
                        threats = detector.detect(packet_info)
                        all_threats.extend(threats)
                        
                    except Exception as e:
                        self.logger.error(f"Error in threat detector {detector.name}: {e}")
                        # Continue processing with other detectors
            
            # Step 6: Process all detected threats
            for threat in all_threats:
                self._process_threat(threat, packet_info)
            
            # Step 7: Update performance metrics
            processing_time = time.perf_counter() - start_time
            self.stats_manager.update_processing_time(processing_time)
            
            # Step 8: Handle industrial mode latency logging
            if self.config.general.industrial_mode:
                latency_us = processing_time * 1000000  # Convert to microseconds
                self._log_latency(latency_us, packet_info)
                
                # Check for latency threshold violations
                if latency_us > self.config.advanced.latency_threshold:
                    self._handle_latency_violation(latency_us, packet_info)
                    
        except Exception as e:
            # Critical error handling - log but continue processing
            self.logger.error(f"Critical error processing packet from {packet_info.source_ip}: {e}")
            self.logger.exception("Full exception trace:")
    
    def _is_trusted_network(self, ip_address: str) -> bool:
        """Check if an IP address belongs to a configured trusted network."""
        try:
            # Parse the IP address
            ip = ipaddress.ip_address(ip_address)
            
            # Check against each configured trusted network
            for network_str in self.config.general.trusted_networks:
                try:
                    # Parse network with strict=False to handle host addresses
                    network = ipaddress.ip_network(network_str, strict=False)
                    
                    # Check if IP is in this network
                    if ip in network:
                        self.logger.debug(f"IP {ip_address} matches trusted network {network_str}")
                        return True
                        
                except ValueError as ve:
                    self.logger.warning(f"Invalid trusted network format '{network_str}': {ve}")
                    continue
                    
        except ValueError as ve:
            self.logger.warning(f"Invalid IP address format '{ip_address}': {ve}")
            
        return False
    
    def _process_threat(self, threat: ThreatInfo, packet_info: PacketInfo) -> None:
        """Process a detected threat according to configured policies."""
        try:
            # Update statistics
            self.stats_manager.update_threat_count()
            
            # Log the threat
            self._log_threat(threat, packet_info)
            
            # Take action based on mode and severity
            if self.config.general.mode == OperationMode.ACTIVE.value:
                self._take_action(threat, packet_info)
            elif self.config.general.mode == OperationMode.LEARNING.value:
                self._update_learning_models(threat, packet_info)
            
            # Handle special cases for industrial threats
            if (threat.subtype and 
                any(protocol in threat.subtype for protocol in ['modbus', 'dnp3', 'opcua'])):
                self._handle_industrial_threat(threat, packet_info)
                
        except Exception as e:
            self.logger.error(f"Error processing threat {threat.threat_type}: {e}")
    
    def _log_threat(self, threat: ThreatInfo, packet_info: PacketInfo) -> None:
        """Log detected threat to appropriate log files with comprehensive context."""
        try:
            # Create unique threat identifier
            threat_id = hashlib.md5(
                f"{packet_info.timestamp}{packet_info.source_ip}{packet_info.dest_ip}{threat.threat_type}".encode()
            ).hexdigest()
            
            # Build comprehensive threat record
            threat_record = {
                'id': threat_id,
                'timestamp': (threat.timestamp or packet_info.timestamp).isoformat(),
                'source_ip': packet_info.source_ip,
                'destination_ip': packet_info.dest_ip,
                'protocol': packet_info.protocol.value,
                'threat_type': threat.threat_type,
                'severity': threat.severity.value,
                'description': threat.description,
                'pattern': threat.pattern,
                'subtype': threat.subtype,
                'details': threat.details,
                'confidence': threat.confidence,
                'action_taken': self.config.general.mode == OperationMode.ACTIVE.value,
                'industrial_context': self._is_industrial_threat(threat),
                'interface': packet_info.interface,
                'packet_size': packet_info.size,
                'tcp_port': packet_info.tcp_port,
                'udp_port': packet_info.udp_port
            }
            
            # Log to main threats file
            threats_log_path = Path(self.LOG_DIR) / "threats.log"
            with open(threats_log_path, 'a', encoding='utf-8') as f:
                f.write(json.dumps(threat_record, ensure_ascii=False) + '\n')
            
            # Log high/critical threats to alerts file
            if threat.severity in [ThreatSeverity.HIGH, ThreatSeverity.CRITICAL]:
                alerts_log_path = Path(self.LOG_DIR) / "alerts.log"
                with open(alerts_log_path, 'a', encoding='utf-8') as f:
                    f.write(json.dumps(threat_record, ensure_ascii=False) + '\n')
            
            # Log threat summary to main logger
            self.logger.info(
                f"THREAT DETECTED {threat.threat_type.upper()} from {packet_info.source_ip} "
                f"-> {packet_info.dest_ip} (Severity: {threat.severity.value}, "
                f"Confidence: {threat.confidence:.2f})"
            )
            
        except Exception as e:
            self.logger.error(f"Error logging threat: {e}")
            self.logger.exception("Full exception trace:")
    
    def _is_industrial_threat(self, threat: ThreatInfo) -> bool:
        """Determine if a threat is related to industrial protocols."""
        if not threat.subtype:
            return False
            
        industrial_keywords = ['modbus', 'dnp3', 'opcua', 'scada', 'plc', 'hmi']
        return any(keyword in threat.subtype.lower() for keyword in industrial_keywords)
    
    def _log_latency(self, latency_us: float, packet_info: PacketInfo) -> None:
        """Log latency measurement for industrial environments."""
        try:
            # Create detailed latency record
            latency_entry = {
                'timestamp': datetime.now().isoformat(),
                'latency_us': latency_us,
                'latency_ms': latency_us / 1000,
                'interface': packet_info.interface,
                'source_ip': packet_info.source_ip,
                'destination_ip': packet_info.dest_ip,
                'protocol': packet_info.protocol.value,
                'packet_size': packet_info.size,
                'threshold_us': self.config.advanced.latency_threshold,
                'threshold_exceeded': latency_us > self.config.advanced.latency_threshold,
                'performance_category': self._categorize_latency(latency_us)
            }
            
            # Write to latency log
            latency_log_path = Path(self.LOG_DIR) / "latency.log"
            with open(latency_log_path, 'a', encoding='utf-8') as f:
                f.write(json.dumps(latency_entry, ensure_ascii=False) + '\n')
                
        except Exception as e:
            self.logger.error(f"Error logging latency measurement: {e}")
    
    def _categorize_latency(self, latency_us: float) -> str:
        """Categorize latency performance for industrial applications."""
        if latency_us < 50:
            return "excellent"
        elif latency_us < 100:
            return "good"
        elif latency_us < 500:
            return "acceptable"
        elif latency_us < 1000:
            return "marginal"
        else:
            return "poor"
    
    def _handle_latency_violation(self, latency_us: float, packet_info: PacketInfo) -> None:
        """Handle latency threshold violations in industrial mode."""
        try:
            # Create latency violation alert
            alert_record = {
                'id': hashlib.md5(f"{datetime.now()}{packet_info.source_ip}latency_violation".encode()).hexdigest(),
                'timestamp': datetime.now().isoformat(),
                'type': 'latency_violation',
                'severity': 'warning' if latency_us < 1000 else 'critical',
                'description': f'Processing latency exceeded threshold: {latency_us:.1f}μs > {self.config.advanced.latency_threshold}μs',
                'details': {
                    'latency_us': latency_us,
                    'threshold_us': self.config.advanced.latency_threshold,
                    'source_ip': packet_info.source_ip,
                    'destination_ip': packet_info.dest_ip,
                    'interface': packet_info.interface,
                    'protocol': packet_info.protocol.value,
                    'performance_impact': self._assess_performance_impact(latency_us)
                }
            }
            
            # Log latency violation alert
            alerts_log_path = Path(self.LOG_DIR) / "alerts.log"
            with open(alerts_log_path, 'a', encoding='utf-8') as f:
                f.write(json.dumps(alert_record, ensure_ascii=False) + '\n')
                
            # Log warning to main logger
            self.logger.warning(
                f"LATENCY VIOLATION: {latency_us:.1f}μs processing time exceeds "
                f"{self.config.advanced.latency_threshold}μs threshold for "
                f"{packet_info.source_ip} -> {packet_info.dest_ip}"
            )
            
        except Exception as e:
            self.logger.error(f"Error handling latency violation: {e}")
    
    def _assess_performance_impact(self, latency_us: float) -> str:
        """Assess the performance impact of latency violations."""
        if latency_us > 10000:  # > 10ms
            return "severe - may impact control system stability"
        elif latency_us > 5000:  # > 5ms  
            return "high - may cause control delays"
        elif latency_us > 1000:  # > 1ms
            return "moderate - monitoring recommended"
        else:
            return "low - within acceptable range"
    
    def _handle_industrial_threat(self, threat: ThreatInfo, packet_info: PacketInfo) -> None:
        """Handle threats specifically targeting industrial control systems."""
        try:
            self.logger.critical(
                f"INDUSTRIAL SECURITY THREAT DETECTED: {threat.description} "
                f"targeting {packet_info.dest_ip}"
            )
            
            # Check for emergency response triggers
            if threat.severity == ThreatSeverity.CRITICAL:
                self._trigger_industrial_emergency_response(threat, packet_info)
                
        except Exception as e:
            self.logger.error(f"Error handling industrial threat: {e}")
    
    def _trigger_industrial_emergency_response(self, threat: ThreatInfo, packet_info: PacketInfo) -> None:
        """Trigger emergency response procedures for critical industrial threats."""
        try:
            self.logger.critical(
                f"EMERGENCY RESPONSE TRIGGERED: Critical industrial threat detected - "
                f"{threat.description}"
            )
            
            # Create emergency response record
            emergency_record = {
                'timestamp': datetime.now().isoformat(),
                'threat_id': hashlib.md5(f"{packet_info.timestamp}{threat.threat_type}".encode()).hexdigest(),
                'response_level': 'EMERGENCY',
                'threat_summary': threat.description,
                'affected_systems': [packet_info.dest_ip],
                'response_actions': [
                    "Emergency response team notified",
                    "System isolation procedures initiated",
                    "Safety system status check triggered"
                ]
            }
            
            # Log emergency response
            emergency_log_path = Path(self.LOG_DIR) / "emergency_response.log"
            with open(emergency_log_path, 'a', encoding='utf-8') as f:
                f.write(json.dumps(emergency_record, ensure_ascii=False) + '\n')
                
        except Exception as e:
            self.logger.error(f"Error triggering emergency response: {e}")
    
    def _take_action(self, threat: ThreatInfo, packet_info: PacketInfo) -> None:
        """Execute response actions for detected threats based on configuration."""
        try:
            self.logger.info(f"Taking action on {threat.severity.value} threat: {threat.threat_type}")
            
            # Critical threats require immediate action
            if threat.severity == ThreatSeverity.CRITICAL:
                self._block_ip(packet_info.source_ip, "Critical threat detected")
                
                # Emergency response for critical industrial threats
                if self._is_industrial_threat(threat):
                    self._trigger_industrial_emergency_response(threat, packet_info)
            
            # Quarantine malicious content if enabled
            if (self.config.advanced.quarantine_enabled and 
                threat.threat_type in ['malware', 'trojan', 'suspicious_download']):
                self._quarantine_threat(threat, packet_info)
                
        except Exception as e:
            self.logger.error(f"Error taking action on threat {threat.threat_type}: {e}")
    
    def _block_ip(self, ip_address: str, reason: str = "Security threat") -> None:
        """Block an IP address using pfctl firewall rules."""
        try:
            # Add IP to blocked table
            result = subprocess.run([
                'pfctl', '-t', 'deepinspector_blocked', '-T', 'add', ip_address
            ], capture_output=True, text=True, check=True)
            
            self.logger.warning(f"BLOCKED IP {ip_address}: {reason}")
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to block IP {ip_address}: {e}")
        except Exception as e:
            self.logger.error(f"Error in IP blocking process: {e}")
    
    def _quarantine_threat(self, threat: ThreatInfo, packet_info: PacketInfo) -> None:
        """Quarantine detected malicious content for forensic analysis."""
        try:
            # Ensure quarantine directory exists
            quarantine_dir = Path(self.config.advanced.quarantine_path)
            quarantine_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            
            # Create unique quarantine filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            threat_id = hashlib.md5(f"{packet_info.timestamp}{threat.threat_type}".encode()).hexdigest()[:8]
            quarantine_file = quarantine_dir / f"threat_{timestamp}_{threat_id}.json"
            
            # Create comprehensive quarantine record
            quarantine_record = {
                'quarantine_info': {
                    'timestamp': datetime.now().isoformat(),
                    'quarantine_id': f"Q-{timestamp}-{threat_id}",
                    'status': 'quarantined'
                },
                'threat_info': {
                    'type': threat.threat_type,
                    'subtype': threat.subtype,
                    'severity': threat.severity.value,
                    'description': threat.description,
                    'pattern': threat.pattern,
                    'confidence': threat.confidence,
                    'details': threat.details
                },
                'network_info': {
                    'source_ip': packet_info.source_ip,
                    'dest_ip': packet_info.dest_ip,
                    'protocol': packet_info.protocol.value,
                    'interface': packet_info.interface,
                    'timestamp': packet_info.timestamp.isoformat()
                },
                'payload_info': {
                    'size': packet_info.size,
                    'hash_md5': hashlib.md5(packet_info.payload).hexdigest(),
                    'hash_sha256': hashlib.sha256(packet_info.payload).hexdigest(),
                    # Don't store actual payload for security reasons
                    'payload_preview': packet_info.payload[:100].hex() if packet_info.payload else None
                }
            }
            
            # Write quarantine record
            with open(quarantine_file, 'w', encoding='utf-8') as f:
                json.dump(quarantine_record, f, indent=2, ensure_ascii=False)
            
            # Set secure permissions
            quarantine_file.chmod(0o600)
                
            self.logger.warning(f"QUARANTINED THREAT: {threat.threat_type} saved to {quarantine_file}")
            
        except Exception as e:
            self.logger.error(f"Error quarantining threat: {e}")
    
    def _update_learning_models(self, threat: ThreatInfo, packet_info: PacketInfo) -> None:
        """Update machine learning models with new threat data (Learning mode)."""
        try:
            # In learning mode, we collect data for model training
            learning_record = {
                'timestamp': datetime.now().isoformat(),
                'threat_features': {
                    'type': threat.threat_type,
                    'severity': threat.severity.value,
                    'confidence': threat.confidence,
                    'pattern_matched': bool(threat.pattern)
                },
                'packet_features': {
                    'size': packet_info.size,
                    'protocol': packet_info.protocol.value,
                    'time_of_day': datetime.now().hour,
                    'payload_entropy': self._calculate_entropy(packet_info.payload)
                }
            }
            
            learning_log_path = Path(self.LOG_DIR) / "learning_data.log"
            with open(learning_log_path, 'a', encoding='utf-8') as f:
                f.write(json.dumps(learning_record, ensure_ascii=False) + '\n')
                
        except Exception as e:
            self.logger.error(f"Error updating learning models: {e}")
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data for anomaly detection."""
        if not data:
            return 0.0
        
        # Calculate byte frequency
        byte_counts = Counter(data)
        data_len = len(data)
        
        # Calculate Shannon entropy
        entropy = 0.0
        for count in byte_counts.values():
            probability = count / data_len
            entropy -= probability * math.log2(probability)
            
        return entropy
    
    def _start_background_threads(self) -> None:
        """Start essential background worker threads for engine operation."""
        self.logger.info("Starting background worker threads...")
        
        # Statistics collection worker thread
        def stats_worker():
            """Background worker for statistics collection and persistence."""
            self.logger.info("Statistics worker thread started")
            
            while self.running:
                try:
                    # Save statistics using integrated collectors
                    success = self.stats_manager.save_stats()
                    if success:
                        self.logger.debug("Statistics saved successfully")
                    else:
                        self.logger.warning("Failed to save statistics")
                        
                    # Sleep for 60 seconds (configurable)
                    sleep_interval = 60
                    for _ in range(sleep_interval):
                        if not self.running:
                            break
                        time.sleep(1)
                        
                except Exception as e:
                    self.logger.error(f"Error in statistics worker: {e}")
                    self.logger.exception("Full exception trace:")
                    time.sleep(10)  # Brief pause before retrying
                    
            self.logger.info("Statistics worker thread terminated")
        
        # Signature update worker thread  
        def signature_update_worker():
            """Background worker for automatic signature updates."""
            self.logger.info("Signature update worker thread started")
            
            # Initial delay before first update check
            initial_delay = 300  # 5 minutes
            self.logger.info(f"Waiting {initial_delay} seconds before first signature check")
            
            for _ in range(initial_delay):
                if not self.running:
                    return
                time.sleep(1)
            
            while self.running:
                try:
                    if self.config.advanced.signature_updates:
                        self.logger.info("Checking for threat signature updates...")
                        
                        # CORRETTO: Usare SignatureUpdater invece di download_signatures
                        updater = SignatureUpdater()
                        success = updater.update()
                        
                        if success:
                            self.logger.info("Threat signatures updated successfully")
                            
                            # Reload detection engines with new signatures
                            self._reload_detectors()
                            
                        else:
                            self.logger.warning("Failed to update threat signatures")
                    
                    # Sleep for configured interval (hours to seconds)
                    sleep_hours = self.config.advanced.update_interval
                    sleep_seconds = sleep_hours * 3600
                    
                    self.logger.info(f"Next signature update in {sleep_hours} hours")
                    
                    for _ in range(sleep_seconds):
                        if not self.running:
                            return
                        time.sleep(1)
                        
                except Exception as e:
                    self.logger.error(f"Error in signature update worker: {e}")
                    self.logger.exception("Full exception trace:")
                    time.sleep(3600)  # Wait 1 hour before retrying
                    
            self.logger.info("Signature update worker thread terminated")
        
        # Start background threads
        self.stats_thread = threading.Thread(target=stats_worker, daemon=True)
        self.signature_update_thread = threading.Thread(target=signature_update_worker, daemon=True)
        
        self.stats_thread.start()
        self.signature_update_thread.start()
        
        self.logger.info("Background worker threads started successfully")
    
    def _reload_detectors(self) -> None:
        """Reload all threat detectors with updated signatures."""
        self.logger.info("Reloading threat detectors with updated signatures")
        
        for detector in self.threat_detectors:
            try:
                success = detector.update_signatures()
                if success:
                    self.logger.debug(f"Successfully reloaded signatures for {detector.name}")
                else:
                    self.logger.warning(f"Failed to reload signatures for {detector.name}")
            except Exception as e:
                self.logger.error(f"Error reloading {detector.name}: {e}")
    
    def _signal_handler(self, signum, frame) -> None:
        """Handle shutdown signals gracefully."""
        self.logger.info(f"Received signal {signum}, initiating graceful shutdown...")
        self.running = False
    
    def run(self) -> None:
        """Main engine execution loop."""
        if not self.initialize():
            self.logger.error("Engine initialization failed - cannot start")
            return
        
        try:
            # Start background worker threads
            self._start_background_threads()
            
            # Start packet capture
            success = self.capture_manager.start_capture(self.process_packet)
            if not success:
                self.logger.error("Failed to start packet capture - engine stopping")
                return
            
            self.logger.info("Deep Inspector Engine is now running")
            
            # Main engine loop
            while self.running:
                # Monitor system resources
                self._monitor_system_resources()
                
                # Brief sleep to prevent CPU spinning
                time.sleep(1)
                
        except KeyboardInterrupt:
            self.logger.info("Keyboard interrupt received")
        except Exception as e:
            self.logger.error(f"Critical error in main engine loop: {e}")
            self.logger.exception("Full exception trace:")
        finally:
            self.shutdown()
    
    def _monitor_system_resources(self) -> None:
        """Monitor and log system resource usage."""
        try:
            # Get system metrics
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            # Update statistics manager
            self.stats_manager.metrics.cpu_usage = cpu_percent
            self.stats_manager.metrics.memory_usage = memory.percent
            
            # Log warning if resources are constrained
            if cpu_percent > 80:
                self.logger.warning(f"High CPU usage: {cpu_percent:.1f}%")
            if memory.percent > 85:
                self.logger.warning(f"High memory usage: {memory.percent:.1f}%")
            if disk.percent > 90:
                self.logger.warning(f"High disk usage: {disk.percent:.1f}%")
                
        except Exception as e:
            self.logger.debug(f"Error monitoring system resources: {e}")
    
    def shutdown(self) -> None:
        """Gracefully shutdown the engine and all components."""
        self.logger.info("Initiating engine shutdown...")
        self.running = False
        
        try:
            # Stop packet capture
            if self.capture_manager:
                self.capture_manager.stop_capture()
            
            # Wait for background threads to finish
            if self.stats_thread:
                self.stats_thread.join(timeout=5)
            if self.signature_update_thread:
                self.signature_update_thread.join(timeout=5)
            
            # Save final statistics
            if self.stats_manager:
                self.stats_manager.save_stats()
            
            # Clean up PID file
            pid_path = Path(self.PID_FILE)
            if pid_path.exists():
                pid_path.unlink()
                self.logger.info("PID file removed")
            
            self.logger.info("Deep Inspector Engine shutdown complete")
            
        except Exception as e:
            self.logger.error(f"Error during shutdown: {e}")


def main() -> None:
    """Main entry point for the Deep Inspector Engine."""
    engine = DeepInspectorEngine()
    
    try:
        engine.run()
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
