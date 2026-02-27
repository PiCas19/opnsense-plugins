#!/usr/local/bin/python3
"""
deepinspector_engine.py - Main Deep Packet Inspection (DPI) Engine

This module implements the core functionality of the DeepInspector DPI engine, designed to 
monitor and analyze network traffic for threat detection. It supports real-time packet capture, 
analysis of various protocols (e.g., HTTP, HTTPS, Modbus, DNP3, OPC UA), and logging of detected 
threats, performance metrics, and system alerts.

Author: Pierpaolo Casati
Version: 1.0.0
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
from collections import defaultdict, deque
from datetime import datetime
import socket
import subprocess
import xml.etree.ElementTree as ET

# Import OOP classes from the transformed files
from export_config import ConfigurationExporter
from get_industrial_stats import StatisticsCollector as IndustrialStatisticsCollector
from get_latency_metrics import LatencyMetricsCollector
from get_metrics import PerformanceMetricsAggregator
from get_stats import DPIStatisticsAggregator

# Fallback for download_signatures (assuming it's a function from update_signatures.py)
try:
    from update_signatures import download_signatures
except ImportError:
    def download_signatures():
        """Placeholder function for downloading threat signatures.

        Returns:
            bool: False, indicating failure to download signatures.
        """
        return False

# Network capture and analysis
try:
    import pcapy
    import dpkt
except ImportError:
    print("Error: Required packages not installed. Install pcapy and dpkt.")
    sys.exit(1)

# Configuration constants
CONFIG_FILE = "/usr/local/etc/deepinspector/config.json"
SIGNATURES_FILE = "/usr/local/etc/deepinspector/signatures.json"
OPNSENSE_CONFIG = "/conf/config.xml"
LOG_DIR = "/var/log/deepinspector"
ALERT_LOG = f"{LOG_DIR}/alerts.log"
THREAT_LOG = f"{LOG_DIR}/threats.log"
DETECTION_LOG = f"{LOG_DIR}/detections.log"
ENGINE_LOG = f"{LOG_DIR}/engine.log"
LATENCY_LOG = f"{LOG_DIR}/latency.log"
STATS_FILE = f"{LOG_DIR}/stats.json"
PID_FILE = "/var/run/deepinspector.pid"


class CaptureThread(threading.Thread):
    """Thread for capturing packets on a specific network interface."""

    def __init__(self, engine, interface):
        """Initialize the capture thread.

        Args:
            engine (DeepInspectorEngine): Reference to the main DPI engine instance.
            interface (str): Network interface to capture packets from.
        """
        super().__init__(daemon=True)
        self.engine = engine
        self.interface = interface

    def run(self):
        """Start packet capture on the specified interface."""
        self.engine.logger.info(f"Starting capture worker for interface: {self.interface}")
        try:
            max_packet_size = int(self.engine.config['general']['max_packet_size'])
            cap = pcapy.open_live(self.interface, max_packet_size, 1, 100)  # promiscuous, timeout ms
            self.engine.logger.info(f"Successfully opened capture on interface: {self.interface}")
            while self.engine.running:
                try:
                    header, packet = cap.next()
                    if packet:
                        self.engine.analyze_packet(packet, datetime.now(), self.interface)
                except pcapy.PcapError as e:
                    if "timeout" not in str(e).lower():
                        self.engine.logger.error(f"Pcap error on {self.interface}: {e}")
                        break
                except Exception as e:
                    self.engine.logger.error(f"Error processing packet on {self.interface}: {e}")
        except Exception as e:
            self.engine.logger.error(f"Failed to open capture on interface {self.interface}: {e}")
        self.engine.logger.info(f"Capture worker for {self.interface} stopped")


class StatsThread(threading.Thread):
    """Thread for periodically saving DPI engine statistics."""

    def __init__(self, engine):
        """Initialize the statistics thread.

        Args:
            engine (DeepInspectorEngine): Reference to the main DPI engine instance.
        """
        super().__init__(daemon=True)
        self.engine = engine

    def run(self):
        """Periodically save engine statistics every 60 seconds."""
        while self.engine.running:
            self.engine.save_stats()
            time.sleep(60)


class SignatureUpdateThread(threading.Thread):
    """Thread for periodically updating threat signatures."""

    def __init__(self, engine):
        """Initialize the signature update thread.

        Args:
            engine (DeepInspectorEngine): Reference to the main DPI engine instance.
        """
        super().__init__(daemon=True)
        self.engine = engine

    def run(self):
        """Periodically update threat signatures every 24 hours."""
        while self.engine.running:
            try:
                time.sleep(86400)  # 24 hours
                if self.engine.running:
                    self.engine.logger.info("Updating threat signatures...")
                    download_signatures()
                    self.engine.load_signatures()
            except Exception as e:
                self.engine.logger.error(f"Error in signature update thread: {e}")


class DeepInspectorEngine:
    """Main class for the Deep Packet Inspector Engine, managing packet analysis and threat detection."""

    def __init__(self):
        """Initialize the DPI engine with default configurations and state."""
        self.running = True
        self.config = {}
        self.signatures = {}
        self.threat_patterns = {
            'malware_signatures': [],
            'suspicious_urls': [],
            'command_injection': [],
            'sql_injection': [],
            'script_injection': [],
            'crypto_mining': [],
            'data_exfiltration': [],
            'industrial_threats': []
        }
        self.stats = {
            'packets_analyzed': 0,
            'threats_detected': 0,
            'false_positives': 0,
            'critical_alerts': 0,
            'protocols_analyzed': defaultdict(int),
            'threat_types': defaultdict(int),
            'detection_methods': defaultdict(int),
            'performance': {
                'cpu_usage': 0,
                'memory_usage': 0,
                'throughput_mbps': 0,
                'latency_avg': 0
            },
            'industrial_stats': {
                'modbus_packets': 0,
                'dnp3_packets': 0,
                'opcua_packets': 0,
                'scada_alerts': 0,
                'plc_communications': 0,
                'industrial_threats': 0,
                'avg_latency': 0
            }
        }
        self.performance_history = deque(maxlen=3600)
        self.packet_buffer = deque(maxlen=10000)
        self.latency_measurements = deque(maxlen=1000)
        self.logger = self.setup_logging()
        # Initialize collectors
        self.industrial_collector = IndustrialStatisticsCollector()
        self.latency_collector = LatencyMetricsCollector()
        self.performance_aggregator = PerformanceMetricsAggregator()
        self.dpi_aggregator = DPIStatisticsAggregator()

    def setup_logging(self):
        """Set up the logging system for the DPI engine.

        Creates necessary log files and configures logging handlers.

        Returns:
            logging.Logger: Configured logger instance.
        """
        os.makedirs(LOG_DIR, exist_ok=True)
        for log_file in [ALERT_LOG, THREAT_LOG, DETECTION_LOG, ENGINE_LOG, LATENCY_LOG]:
            if not os.path.exists(log_file):
                with open(log_file, 'w') as f:
                    pass
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(ENGINE_LOG),
                logging.StreamHandler()
            ]
        )
        return logging.getLogger(__name__)

    def get_interface_mapping(self):
        """Retrieve mapping of logical interface names to physical interfaces.

        Returns:
            dict: Mapping of logical to physical interface names.
        """
        interface_map = {}
        try:
            tree = ET.parse(OPNSENSE_CONFIG)
            root = tree.getroot()
            interfaces = root.find('interfaces')
            if interfaces is not None:
                for interface in interfaces:
                    if_name = interface.tag
                    if_element = interface.find('if')
                    if if_element is not None:
                        physical_if = if_element.text
                        interface_map[if_name] = physical_if
                        self.logger.info(f"Mapped interface {if_name} -> {physical_if}")
        except Exception as e:
            self.logger.error(f"Error parsing OPNsense config: {e}")
            try:
                result = subprocess.run(['ifconfig', '-l'], capture_output=True, text=True)
                if result.returncode == 0:
                    system_interfaces = result.stdout.strip().split()
                    common_mappings = {
                        'lan': 'em0',
                        'wan': 'em1',
                        'opt1': 'em2',
                        'opt2': 'em3'
                    }
                    for logical, physical in common_mappings.items():
                        if physical in system_interfaces:
                            interface_map[logical] = physical
                            self.logger.info(f"Fallback mapped {logical} -> {physical}")
            except Exception as e2:
                self.logger.error(f"Error getting system interfaces: {e2}")
        return interface_map

    def resolve_interfaces(self, logical_interfaces):
        """Convert logical interface names to physical interface names.

        Args:
            logical_interfaces (str or list): Logical interface names to resolve.

        Returns:
            list: List of physical interface names.
        """
        interface_map = self.get_interface_mapping()
        physical_interfaces = []
        if isinstance(logical_interfaces, str):
            logical_interfaces = [iface.strip() for iface in logical_interfaces.split(',') if iface.strip()]
        for logical_if in logical_interfaces:
            if logical_if in interface_map:
                physical_if = interface_map[logical_if]
                physical_interfaces.append(physical_if)
                self.logger.info(f"Resolved {logical_if} -> {physical_if}")
            else:
                physical_interfaces.append(logical_if)
                self.logger.warning(f"Could not resolve {logical_if}, using as-is")
        return physical_interfaces

    def load_config(self):
        """Load DPI engine configuration from file.

        Returns:
            bool: True if configuration loaded successfully, False otherwise.
        """
        try:
            exporter = ConfigurationExporter()
            exporter.export_config()
            with open(CONFIG_FILE, 'r') as f:
                self.config = json.load(f)
            self.logger.info(f"Raw configuration loaded: {json.dumps(self.config, indent=2)}")
            defaults = {
                'general': {
                    'enabled': False,
                    'mode': 'passive',
                    'interfaces': [],
                    'max_packet_size': 1500,
                    'deep_scan_ports': '80,443,21,25,53,502,4840',
                    'performance_profile': 'balanced',
                    'low_latency_mode': False,
                    'industrial_mode': False,
                    'log_level': 'info'
                },
                'protocols': {
                    'http_inspection': True,
                    'https_inspection': False,
                    'ftp_inspection': True,
                    'smtp_inspection': True,
                    'dns_inspection': True,
                    'industrial_protocols': True
                },
                'detection': {
                    'virus_signatures': True,
                    'trojan_detection': True,
                    'crypto_mining': True,
                    'data_exfiltration': True,
                    'command_injection': True,
                    'sql_injection': True,
                    'script_injection': True,
                    'zero_day_heuristics': True
                },
                'advanced': {
                    'memory_limit': 1024,
                    'thread_count': 4,
                    'analysis_timeout': 5,
                    'latency_threshold': 100
                }
            }
            for section, values in defaults.items():
                if section not in self.config:
                    self.config[section] = {}
                for key, default_value in values.items():
                    if key not in self.config[section]:
                        self.config[section][key] = default_value
            numeric_fields = {
                'general': ['max_packet_size'],
                'advanced': ['memory_limit', 'thread_count', 'analysis_timeout', 'latency_threshold']
            }
            for section, fields in numeric_fields.items():
                if section in self.config:
                    for field in fields:
                        if field in self.config[section]:
                            try:
                                self.config[section][field] = int(str(self.config[section][field]))
                            except (ValueError, TypeError):
                                self.config[section][field] = defaults[section].get(field, 0)
            boolean_fields = {
                'general': ['enabled', 'low_latency_mode', 'industrial_mode'],
                'protocols': ['http_inspection', 'https_inspection', 'ftp_inspection', 'smtp_inspection', 'dns_inspection', 'industrial_protocols'],
                'detection': ['virus_signatures', 'trojan_detection', 'crypto_mining', 'data_exfiltration', 'command_injection', 'sql_injection', 'script_injection', 'zero_day_heuristics'],
            }
            for section, fields in boolean_fields.items():
                if section in self.config:
                    for field in fields:
                        if field in self.config[section]:
                            value = self.config[section][field]
                            if isinstance(value, str):
                                self.config[section][field] = value.lower() in ['true', '1', 'yes', 'on']
                            elif isinstance(value, int):
                                self.config[section][field] = bool(value)
            self.logger.info(f"Configuration loaded: {len(self.config)} sections")
            return True
        except Exception as e:
            self.logger.error(f"Failed to load configuration: {e}")
            self.config = defaults
            return False

    def load_signatures(self):
        """Load threat detection signatures from file.

        Returns:
            bool: True if signatures loaded successfully, False otherwise.
        """
        try:
            if not os.path.exists(SIGNATURES_FILE):
                self.logger.info("Signatures file not found, downloading...")
                download_signatures()
            with open(SIGNATURES_FILE, 'r') as f:
                self.signatures = json.load(f)
            for category, patterns in self.signatures.get('patterns', {}).items():
                if category in self.threat_patterns:
                    self.threat_patterns[category] = [re.compile(pattern, re.IGNORECASE) for pattern in patterns]
            self.logger.info(f"Loaded {sum(len(patterns) for patterns in self.threat_patterns.values())} threat signatures")
            return True
        except Exception as e:
            self.logger.warning(f"Failed to load signatures: {e}")
            self.load_default_signatures()
            return False

    def load_default_signatures(self):
        """Load minimal default threat signatures."""
        self.threat_patterns['malware_signatures'] = [
            re.compile(r'X5O!P%@AP\[4\\PZX54\(P\^\)7CC\)7\}\$EICAR', re.IGNORECASE),
            re.compile(r'TVqQAAMAAAAEAAAA//8AALgAAAAA', re.IGNORECASE),
            re.compile(r'\\x4d\\x5a', re.IGNORECASE),
        ]
        self.threat_patterns['command_injection'] = [
            # Shell chaining with common recon/exploit commands
            re.compile(r'[\;\|&`][ \t]*(ls|cat|wget|curl|nc|netcat|whoami|id|uname|passwd|shadow|hostname|ifconfig|ipconfig|nmap|ping)', re.IGNORECASE),
            # Direct shell binary references
            re.compile(r'(/bin/|/usr/bin/)?(bash|sh|zsh|csh|ksh|tcsh|dash)[\s\"\'\&\;\|]', re.IGNORECASE),
            # Windows shells
            re.compile(r'(cmd\.exe|powershell|wscript|cscript)[\s/\-]', re.IGNORECASE),
            # Command substitution: $(cmd) or `cmd`
            re.compile(r'\$\([^\)]{1,100}\)|`[^`]{1,100}`', re.IGNORECASE),
            # PHP/server-side execution functions
            re.compile(r'(system|exec|popen|passthru|shell_exec|proc_open)\s*\(', re.IGNORECASE),
            # Path traversal into shell configs
            re.compile(r'\.\./\.\./\.\./etc/(passwd|shadow|hosts)', re.IGNORECASE),
            # Hex-encoded payloads with exec keywords
            re.compile(r'\\x[0-9a-f]{2}.*?(system|exec|eval)', re.IGNORECASE),
        ]
        self.threat_patterns['sql_injection'] = [
            re.compile(r'(union|select|insert|update|delete|drop|create|alter).*?(from|into|table|database)', re.IGNORECASE),
            re.compile(r'[\'\"].*?(or|and).*?[\'\"].*?=.*?[\'\"]', re.IGNORECASE),
            re.compile(r'(\'|\").*?(--|\#|\/\*)', re.IGNORECASE),
        ]
        self.threat_patterns['script_injection'] = [
            re.compile(r'<script[^>]*>.*?</script>', re.IGNORECASE | re.DOTALL),
            re.compile(r'javascript:', re.IGNORECASE),
            re.compile(r'on(load|error|click|mouseover)=', re.IGNORECASE),
        ]
        self.threat_patterns['crypto_mining'] = [
            re.compile(r'(coinhive|cryptonight|monero|mining|miner)', re.IGNORECASE),
            re.compile(r'(stratum|pool|hashrate|difficulty)', re.IGNORECASE),
        ]
        self.threat_patterns['industrial_threats'] = [
            re.compile(r'(modbus|dnp3|opcua).*?(exploit|attack|malicious)', re.IGNORECASE),
            re.compile(r'(scada|plc|hmi).*?(compromise|hijack|control)', re.IGNORECASE),
            re.compile(r'(function_code|unit_id).*?(0x[0-9a-f]+)', re.IGNORECASE),
        ]

    def log_detection(self, threat, ip, timestamp):
        """Log a detected threat to the detections log file.

        Args:
            threat (dict): Threat details including type, severity, and description.
            ip (dpkt.ip.IP): IP packet object containing source and destination IPs.
            timestamp (datetime): Timestamp of the detection.
        """
        try:
            detection = {
                'id': hashlib.md5(f"{timestamp}{ip.src}{ip.dst}{threat['type']}_detection".encode()).hexdigest(),
                'timestamp': timestamp.isoformat(),
                'source_ip': socket.inet_ntoa(ip.src),
                'destination_ip': socket.inet_ntoa(ip.dst),
                'protocol': self.get_protocol_name(ip.p),
                'threat_type': threat['type'],
                'severity': threat['severity'],
                'description': threat['description'],
                'pattern': threat.get('pattern', 'heuristic'),
                'subtype': threat.get('subtype', ''),
                'details': threat.get('details', {}),
                'detection_method': 'signature' if 'pattern' in threat else 'heuristic'
            }
            with open(DETECTION_LOG, 'a') as f:
                f.write(json.dumps(detection) + '\n')
            self.logger.debug(f"Detection logged: {threat['type']} from {socket.inet_ntoa(ip.src)}")
        except Exception as e:
            self.logger.error(f"Error logging detection: {e}")

    def log_threat(self, threat, ip, timestamp):
        """Log a threat to the threats log file.

        Args:
            threat (dict): Threat details including type, severity, and description.
            ip (dpkt.ip.IP): IP packet object containing source and destination IPs.
            timestamp (datetime): Timestamp of the threat.
        """
        try:
            threat_record = {
                'id': hashlib.md5(f"{timestamp}{ip.src}{ip.dst}{threat['type']}_threat".encode()).hexdigest(),
                'timestamp': timestamp.isoformat(),
                'source_ip': socket.inet_ntoa(ip.src),
                'destination_ip': socket.inet_ntoa(ip.dst),
                'protocol': self.get_protocol_name(ip.p),
                'threat_type': threat['type'],
                'severity': threat['severity'],
                'description': threat['description'],
                'pattern': threat.get('pattern', 'heuristic'),
                'subtype': threat.get('subtype', ''),
                'details': threat.get('details', {}),
                'action_taken': self.config['general']['mode'] == 'active',
                'blocked': False,
                'quarantined': False
            }
            with open(THREAT_LOG, 'a') as f:
                f.write(json.dumps(threat_record) + '\n')
            self.logger.debug(f"Threat logged: {threat['type']} from {socket.inet_ntoa(ip.src)}")
        except Exception as e:
            self.logger.error(f"Error logging threat: {e}")

    def log_latency(self, latency, interface, source_ip, dest_ip):
        """Log latency measurement to the latency log file.

        Args:
            latency (float): Measured latency in microseconds.
            interface (str): Network interface where the packet was captured.
            source_ip (str): Source IP address.
            dest_ip (str): Destination IP address.
        """
        try:
            latency_entry = {
                'timestamp': datetime.now().isoformat(),
                'latency': latency,
                'interface': interface,
                'source_ip': source_ip,
                'destination_ip': dest_ip,
                'threshold_exceeded': latency > self.config['advanced']['latency_threshold']
            }
            with open(LATENCY_LOG, 'a') as f:
                f.write(json.dumps(latency_entry) + '\n')
        except Exception as e:
            self.logger.error(f"Error logging latency: {e}")

    def analyze_packet(self, packet_data, timestamp, interface='unknown'):
        """Analyze a network packet for potential threats.

        Args:
            packet_data (bytes): Raw packet data.
            timestamp (datetime): Timestamp of packet capture.
            interface (str, optional): Network interface name. Defaults to 'unknown'.
        """
        start_time = time.time()
        try:
            eth = dpkt.ethernet.Ethernet(packet_data)
            if not isinstance(eth.data, dpkt.ip.IP):
                return
            ip = eth.data
            self.stats['packets_analyzed'] += 1
            protocol = self.get_protocol_name(ip.p)
            self.stats['protocols_analyzed'][protocol] += 1
            threats = []
            if ip.p == dpkt.ip.IP_PROTO_TCP:
                tcp = ip.data
                threats.extend(self.analyze_tcp_packet(ip, tcp))
                if self.config['protocols']['industrial_protocols']:
                    threats.extend(self.analyze_industrial_protocols(ip, tcp))
            elif ip.p == dpkt.ip.IP_PROTO_UDP:
                udp = ip.data
                threats.extend(self.analyze_udp_packet(ip, udp))
            if self.config['general']['industrial_mode']:
                latency = (time.time() - start_time) * 1000000  # microseconds
                self.latency_measurements.append(latency)
                self.stats['performance']['latency_avg'] = sum(self.latency_measurements) / len(self.latency_measurements)
                self.log_latency(latency, interface, socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst))
                if latency > self.config['advanced']['latency_threshold']:
                    self.create_alert('high_latency', {
                        'latency': latency,
                        'threshold': self.config['advanced']['latency_threshold'],
                        'source_ip': socket.inet_ntoa(ip.src),
                        'destination_ip': socket.inet_ntoa(ip.dst)
                    })
            for threat in threats:
                self.process_threat(threat, ip, timestamp)
        except Exception as e:
            self.logger.error(f"Error analyzing packet: {e}")

    def analyze_tcp_packet(self, ip, tcp):
        """Analyze a TCP packet for threats.

        Args:
            ip (dpkt.ip.IP): IP packet object.
            tcp (dpkt.tcp.TCP): TCP packet object.

        Returns:
            list: List of detected threats.
        """
        threats = []
        try:
            payload = tcp.data
            if not payload:
                return threats
            if tcp.dport == 80 or tcp.sport == 80:
                if self.config['protocols']['http_inspection']:
                    threats.extend(self.analyze_http_payload(payload))
            elif tcp.dport == 443 or tcp.sport == 443:
                if self.config['protocols']['https_inspection']:
                    threats.extend(self.analyze_https_payload(payload))
            elif tcp.dport == 21 or tcp.sport == 21:
                if self.config['protocols']['ftp_inspection']:
                    threats.extend(self.analyze_ftp_payload(payload))
            elif tcp.dport == 25 or tcp.sport == 25:
                if self.config['protocols']['smtp_inspection']:
                    threats.extend(self.analyze_smtp_payload(payload))
            threats.extend(self.analyze_generic_payload(payload))
        except Exception as e:
            self.logger.error(f"Error analyzing TCP packet: {e}")
        return threats

    def analyze_udp_packet(self, ip, udp):
        """Analyze a UDP packet for threats.

        Args:
            ip (dpkt.ip.IP): IP packet object.
            udp (dpkt.udp.UDP): UDP packet object.

        Returns:
            list: List of detected threats.
        """
        threats = []
        try:
            payload = udp.data
            if not payload:
                return threats
            if udp.dport == 53 or udp.sport == 53:
                if self.config['protocols']['dns_inspection']:
                    threats.extend(self.analyze_dns_payload(payload))
            threats.extend(self.analyze_generic_payload(payload))
        except Exception as e:
            self.logger.error(f"Error analyzing UDP packet: {e}")
        return threats

    def analyze_dns_payload(self, payload):
        """Analyze DNS payload for potential threats.

        Args:
            payload (bytes): DNS packet payload.

        Returns:
            list: List of detected threats.
        """
        threats = []
        try:
            if len(payload) < 12:
                return threats
            if len(payload) > 512:
                threats.append({
                    'type': 'dns_tunneling',
                    'severity': 'medium',
                    'description': 'Potential DNS tunneling detected',
                    'details': {'payload_size': len(payload)}
                })
        except Exception as e:
            self.logger.error(f"Error analyzing DNS payload: {e}")
        return threats

    def analyze_industrial_protocols(self, ip, tcp):
        """Analyze industrial protocol packets (e.g., Modbus, DNP3, OPC UA).

        Args:
            ip (dpkt.ip.IP): IP packet object.
            tcp (dpkt.tcp.TCP): TCP packet object.

        Returns:
            list: List of detected threats.
        """
        threats = []
        try:
            if tcp.dport == 502 or tcp.sport == 502:
                self.stats['industrial_stats']['modbus_packets'] += 1
                threats.extend(self.analyze_modbus_packet(tcp.data))
            elif tcp.dport == 20000 or tcp.sport == 20000:
                self.stats['industrial_stats']['dnp3_packets'] += 1
                threats.extend(self.analyze_dnp3_packet(tcp.data))
            elif tcp.dport == 4840 or tcp.sport == 4840:
                self.stats['industrial_stats']['opcua_packets'] += 1
                threats.extend(self.analyze_opcua_packet(tcp.data))
        except Exception as e:
            self.logger.error(f"Error analyzing industrial protocols: {e}")
        return threats

    def analyze_modbus_packet(self, payload):
        """Analyze Modbus protocol packet for threats.

        Args:
            payload (bytes): Modbus packet payload.

        Returns:
            list: List of detected threats.
        """
        threats = []
        try:
            if len(payload) < 8:
                return threats
            transaction_id = struct.unpack('>H', payload[0:2])[0]
            protocol_id = struct.unpack('>H', payload[2:4])[0]
            length = struct.unpack('>H', payload[4:6])[0]
            unit_id = payload[6]
            function_code = payload[7]
            dangerous_functions = [0x08, 0x11, 0x17]
            if function_code in dangerous_functions:
                threats.append({
                    'type': 'industrial_threat',
                    'subtype': 'modbus_suspicious_function',
                    'severity': 'high',
                    'description': f'Suspicious Modbus function code: {function_code:02x}',
                    'details': {
                        'function_code': function_code,
                        'unit_id': unit_id,
                        'transaction_id': transaction_id
                    }
                })
            if length > 252:
                threats.append({
                    'type': 'industrial_threat',
                    'subtype': 'modbus_oversized_packet',
                    'severity': 'medium',
                    'description': f'Oversized Modbus packet: {length} bytes',
                    'details': {'packet_size': length}
                })
        except Exception as e:
            self.logger.error(f"Error analyzing Modbus packet: {e}")
        return threats

    def analyze_dnp3_packet(self, payload):
        """Analyze DNP3 protocol packet for threats.

        Args:
            payload (bytes): DNP3 packet payload.

        Returns:
            list: List of detected threats.
        """
        threats = []
        try:
            if len(payload) < 10:
                return threats
            start_bytes = payload[0:2]
            if start_bytes != b'\x05\x64':
                return threats
            length = payload[2]
            control = payload[3]
            dest_addr = struct.unpack('<H', payload[4:6])[0]
            src_addr = struct.unpack('<H', payload[6:8])[0]
            if dest_addr == 0xFFFF or src_addr == 0xFFFF:
                threats.append({
                    'type': 'industrial_threat',
                    'subtype': 'dnp3_broadcast',
                    'severity': 'high',
                    'description': 'DNP3 broadcast address detected',
                    'details': {
                        'dest_addr': dest_addr,
                        'src_addr': src_addr
                    }
                })
        except Exception as e:
            self.logger.error(f"Error analyzing DNP3 packet: {e}")
        return threats

    def analyze_opcua_packet(self, payload):
        """Analyze OPC UA protocol packet for threats.

        Args:
            payload (bytes): OPC UA packet payload.

        Returns:
            list: List of detected threats.
        """
        threats = []
        try:
            if len(payload) < 8:
                return threats
            message_type = payload[0:4]
            message_size = struct.unpack('<I', payload[4:8])[0]
            if message_type == b'ERR\x00':
                threats.append({
                    'type': 'industrial_threat',
                    'subtype': 'opcua_error_message',
                    'severity': 'medium',
                    'description': 'OPC UA error message detected',
                    'details': {'message_type': message_type.decode('ascii', errors='ignore')}
                })
            if message_size > 65536:
                threats.append({
                    'type': 'industrial_threat',
                    'subtype': 'opcua_oversized_message',
                    'severity': 'medium',
                    'description': f'Oversized OPC UA message: {message_size} bytes',
                    'details': {'message_size': message_size}
                })
        except Exception as e:
            self.logger.error(f"Error analyzing OPC UA packet: {e}")
        return threats

    def analyze_http_payload(self, payload):
        """Analyze HTTP payload for threats.

        Performs URL decoding before pattern matching to catch percent-encoded attacks.

        Args:
            payload (bytes): HTTP packet payload.

        Returns:
            list: List of detected threats.
        """
        # analyze_generic_payload already covers injection patterns with URL decoding;
        # this method is kept for protocol-specific context tagging on port 80.
        return []

    def analyze_https_payload(self, payload):
        """Analyze HTTPS payload for threats (limited without decryption).

        Args:
            payload (bytes): HTTPS packet payload.

        Returns:
            list: List of detected threats.
        """
        threats = []
        try:
            if len(payload) < 5:
                return threats
            if payload[0] == 0x16:
                tls_version = struct.unpack('>H', payload[1:3])[0]
                if tls_version < 0x0301:
                    threats.append({
                        'type': 'tls_vulnerability',
                        'severity': 'low',
                        'description': f'Outdated TLS version: {tls_version:04x}',
                        'details': {'tls_version': tls_version}
                    })
        except Exception as e:
            self.logger.error(f"Error analyzing HTTPS payload: {e}")
        return threats

    def analyze_ftp_payload(self, payload):
        """Analyze FTP payload for threats.

        Args:
            payload (bytes): FTP packet payload.

        Returns:
            list: List of detected threats.
        """
        threats = []
        try:
            payload_str = payload.decode('utf-8', errors='ignore')
            suspicious_commands = ['SITE', 'MKD', 'RMD', 'DELE', 'RNFR', 'RNTO']
            for cmd in suspicious_commands:
                if payload_str.upper().startswith(cmd):
                    threats.append({
                        'type': 'ftp_suspicious_command',
                        'severity': 'medium',
                        'description': f'Suspicious FTP command: {cmd}',
                        'details': {'command': cmd}
                    })
        except Exception as e:
            self.logger.error(f"Error analyzing FTP payload: {e}")
        return threats

    def analyze_smtp_payload(self, payload):
        """Analyze SMTP payload for threats.

        Args:
            payload (bytes): SMTP packet payload.

        Returns:
            list: List of detected threats.
        """
        threats = []
        try:
            payload_str = payload.decode('utf-8', errors='ignore')
            if 'attachment' in payload_str.lower() and '.exe' in payload_str.lower():
                threats.append({
                    'type': 'email_malware',
                    'severity': 'high',
                    'description': 'Potential malware attachment detected',
                    'details': {'content': payload_str[:100]}
                })
        except Exception as e:
            self.logger.error(f"Error analyzing SMTP payload: {e}")
        return threats

    def analyze_generic_payload(self, payload):
        """Analyze generic payload for threats across all protocols and ports.

        Checks malware signatures, crypto-mining, command injection, SQL injection,
        and script injection on both raw and URL-decoded payload to catch encoded attacks.

        Args:
            payload (bytes): Packet payload.

        Returns:
            list: List of detected threats (deduplicated by type).
        """
        threats = []
        seen_types = set()

        def add_threat(t):
            if t['type'] not in seen_types:
                seen_types.add(t['type'])
                threats.append(t)

        try:
            payload_str = payload.decode('utf-8', errors='ignore')

            # URL-decode to catch percent-encoded attacks (e.g. %27 for ', %20 for space)
            try:
                from urllib.parse import unquote
                payload_decoded = unquote(payload_str)
            except Exception:
                payload_decoded = payload_str

            texts = [payload_str] if payload_str == payload_decoded else [payload_str, payload_decoded]

            for text in texts:
                for pattern in self.threat_patterns['malware_signatures']:
                    if pattern.search(text):
                        add_threat({
                            'type': 'malware',
                            'severity': 'critical',
                            'description': 'Malware signature detected in payload',
                            'pattern': pattern.pattern
                        })

                for pattern in self.threat_patterns['crypto_mining']:
                    if pattern.search(text):
                        add_threat({
                            'type': 'crypto_mining',
                            'severity': 'medium',
                            'description': 'Cryptocurrency mining activity detected',
                            'pattern': pattern.pattern
                        })

                for pattern in self.threat_patterns['command_injection']:
                    if pattern.search(text):
                        add_threat({
                            'type': 'command_injection',
                            'severity': 'high',
                            'description': 'Command injection attempt detected in payload',
                            'pattern': pattern.pattern
                        })

                for pattern in self.threat_patterns['sql_injection']:
                    if pattern.search(text):
                        add_threat({
                            'type': 'sql_injection',
                            'severity': 'high',
                            'description': 'SQL injection attempt detected in payload',
                            'pattern': pattern.pattern
                        })

                for pattern in self.threat_patterns['script_injection']:
                    if pattern.search(text):
                        add_threat({
                            'type': 'script_injection',
                            'severity': 'medium',
                            'description': 'Script injection attempt detected in payload',
                            'pattern': pattern.pattern
                        })

        except Exception as e:
            self.logger.error(f"Error analyzing generic payload: {e}")
        return threats

    def process_threat(self, threat, ip, timestamp):
        """Process a detected threat, logging and taking action if necessary.

        Args:
            threat (dict): Threat details including type, severity, and description.
            ip (dpkt.ip.IP): IP packet object.
            timestamp (datetime): Timestamp of the threat detection.
        """
        self.stats['threats_detected'] += 1
        self.stats['threat_types'][threat['type']] += 1
        if threat['severity'] == 'critical':
            self.stats['critical_alerts'] += 1
        self.log_detection(threat, ip, timestamp)
        self.log_threat(threat, ip, timestamp)
        alert = {
            'id': hashlib.md5(f"{timestamp}{ip.src}{ip.dst}{threat['type']}".encode()).hexdigest(),
            'timestamp': timestamp.isoformat(),
            'source_ip': socket.inet_ntoa(ip.src),
            'destination_ip': socket.inet_ntoa(ip.dst),
            'protocol': self.get_protocol_name(ip.p),
            'threat_type': threat['type'],
            'severity': threat['severity'],
            'description': threat['description'],
            'detection_method': threat.get('pattern', 'heuristic'),
            'zero_trust_triggered': self.config['general']['mode'] == 'active',
            'industrial_context': threat.get('subtype', '').startswith('modbus') or 
                                  threat.get('subtype', '').startswith('dnp3') or 
                                  threat.get('subtype', '').startswith('opcua')
        }
        if alert['industrial_context']:
            self.stats['industrial_stats']['scada_alerts'] += 1
            self.stats['industrial_stats']['industrial_threats'] += 1
            alert['industrial_protocol'] = threat.get('subtype', '').split('_')[0]
        self.log_alert(alert)
        if self.config['general']['mode'] == 'active':
            self.take_action(alert)

    def create_alert(self, alert_type, details):
        """Create a system alert for specific events.

        Args:
            alert_type (str): Type of the alert.
            details (dict): Additional details about the alert.
        """
        alert = {
            'id': hashlib.md5(f"{datetime.now()}{alert_type}{details}".encode()).hexdigest(),
            'timestamp': datetime.now().isoformat(),
            'type': alert_type,
            'severity': 'warning',
            'description': f'System alert: {alert_type}',
            'details': details
        }
        self.log_alert(alert)

    def log_alert(self, alert):
        """Log an alert to the alerts log file.

        Args:
            alert (dict): Alert details including type, severity, and description.
        """
        try:
            with open(ALERT_LOG, 'a') as f:
                f.write(json.dumps(alert) + '\n')
            self.logger.info(f"Alert: {alert.get('threat_type', alert.get('type', 'unknown'))} - {alert['description']}")
        except Exception as e:
            self.logger.error(f"Error logging alert: {e}")

    def take_action(self, alert):
        """Take action on a detected threat, such as blocking an IP address.

        Args:
            alert (dict): Alert details including source IP and severity.
        """
        try:
            if alert['severity'] == 'critical':
                self.block_ip(alert['source_ip'])
            if alert['industrial_context'] and alert['severity'] == 'critical':
                self.logger.critical(f"Critical industrial threat detected: {alert['description']}")
        except Exception as e:
            self.logger.error(f"Error taking action: {e}")

    def block_ip(self, ip_address):
        """Block an IP address using pfctl.

        Args:
            ip_address (str): IP address to block.
        """
        try:
            subprocess.run(['pfctl', '-t', 'deepinspector_blocked', '-T', 'add', ip_address], check=True, capture_output=True)
            self.logger.info(f"Blocked IP address: {ip_address}")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to block IP {ip_address}: {e}")

    def get_protocol_name(self, protocol_number):
        """Convert a protocol number to its name.

        Args:
            protocol_number (int): IP protocol number.

        Returns:
            str: Protocol name or formatted string for unknown protocols.
        """
        protocol_map = {
            1: 'ICMP',
            6: 'TCP',
            17: 'UDP',
            47: 'GRE',
            50: 'ESP',
            51: 'AH'
        }
        return protocol_map.get(protocol_number, f'Protocol-{protocol_number}')

    def save_stats(self):
        """Save engine statistics to a file.

        Preserves in-memory packet/threat counters accumulated during capture.
        Only enriches performance and industrial fields from external collectors.
        Converts defaultdict objects to plain dicts for clean JSON serialization.
        """
        try:
            # Enrich industrial stats from collector (does not overwrite capture counters)
            industrial_stats = self.industrial_collector.get_industrial_stats()
            if 'error' not in industrial_stats:
                self.stats['industrial_stats'].update(industrial_stats)

            # Enrich latency average from collector
            latency_metrics = self.latency_collector.get_latency_metrics()
            if 'error' not in latency_metrics:
                self.stats['performance']['latency_avg'] = latency_metrics.get('avg_latency', 0)

            # Enrich CPU and memory from system metrics (psutil)
            system_metrics = self.performance_aggregator.get_metrics()
            if 'error' not in system_metrics:
                self.stats['performance']['cpu_usage'] = (
                    system_metrics.get('system', {}).get('cpu', {}).get('usage_percent', 0)
                )
                self.stats['performance']['memory_usage'] = (
                    system_metrics.get('system', {}).get('memory', {}).get('virtual', {}).get('percent_used', 0)
                )

            self.stats['timestamp'] = datetime.now().isoformat()

            # Build serializable copy — convert defaultdicts to plain dicts
            stats_copy = dict(self.stats)
            stats_copy['protocols_analyzed'] = dict(self.stats['protocols_analyzed'])
            stats_copy['threat_types'] = dict(self.stats['threat_types'])
            stats_copy['detection_methods'] = dict(self.stats['detection_methods'])

            with open(STATS_FILE, 'w') as f:
                json.dump(stats_copy, f, indent=2)

        except Exception as e:
            self.logger.error(f"Error saving stats: {e}")

    def signal_handler(self, signum, frame):
        """Handle shutdown signals (SIGTERM, SIGINT).

        Args:
            signum (int): Signal number received.
            frame: Current stack frame.
        """
        self.logger.info(f"Received signal {signum}, shutting down...")
        self.running = False

    def run(self):
        """Run the DPI engine, starting packet capture and monitoring.

        Returns:
            int: Exit code (0 for success, 1 for failure).
        """
        signal.signal(signal.SIGTERM, self.signal_handler)
        signal.signal(signal.SIGINT, self.signal_handler)
        if os.geteuid() != 0:
            self.logger.error("This script must be run as root for packet capture")
            return 1
        try:
            with open(PID_FILE, 'w') as f:
                f.write(str(os.getpid()))
        except Exception as e:
            self.logger.error(f"Failed to write PID file: {e}")
            return 1
        self.logger.info("Starting Deep Packet Inspector Engine")
        if not self.load_config():
            self.logger.error("Failed to load configuration")
            return 1
        if not self.load_signatures():
            self.logger.warning("Using default signatures")
        if not self.config['general']['enabled']:
            self.logger.info("DPI engine is disabled in configuration")
            return 0
        logical_interfaces = self.config['general']['interfaces']
        if not logical_interfaces:
            self.logger.error("No interfaces configured for monitoring")
            return 1
        if isinstance(logical_interfaces, str):
            logical_interfaces = [iface.strip() for iface in logical_interfaces.split(',') if iface.strip()]
        logical_interfaces = [iface for iface in logical_interfaces if iface and len(iface) > 1]
        if not logical_interfaces:
            self.logger.error("No valid interfaces found in configuration")
            return 1
        self.logger.info(f"Logical interfaces to resolve: {logical_interfaces}")
        physical_interfaces = self.resolve_interfaces(logical_interfaces)
        if not physical_interfaces:
            self.logger.error("No valid interfaces found after resolution")
            return 1
        valid_interfaces = []
        for interface in physical_interfaces:
            try:
                result = subprocess.run(['ifconfig', interface], capture_output=True, text=True)
                if result.returncode == 0:
                    valid_interfaces.append(interface)
                    self.logger.info(f"Interface {interface} is valid and active")
                else:
                    self.logger.error(f"Interface {interface} is not available")
            except Exception as e:
                self.logger.error(f"Error checking interface {interface}: {e}")
        if not valid_interfaces:
            self.logger.error("No valid interfaces found")
            return 1
        stats_thread = StatsThread(self)
        stats_thread.start()
        signature_thread = SignatureUpdateThread(self)
        signature_thread.start()
        capture_threads = []
        for interface in valid_interfaces:
            thread = CaptureThread(self, interface)
            capture_threads.append(thread)
            thread.start()
        try:
            self.logger.info("Deep Packet Inspector Engine is running...")
            self.logger.info(f"Monitoring interfaces: {valid_interfaces}")
            self.logger.info(f"Mode: {self.config['general']['mode']}")
            self.logger.info(f"Industrial mode: {self.config['general']['industrial_mode']}")
            while self.running and any(thread.is_alive() for thread in capture_threads):
                time.sleep(1)
        except KeyboardInterrupt:
            self.logger.info("Received keyboard interrupt")
        except Exception as e:
            self.logger.error(f"Fatal error: {e}")
            return 1
        finally:
            self.running = False
            self.logger.info("Stopping all capture threads...")
            for thread in capture_threads:
                thread.join(timeout=5)
            self.save_stats()
            if os.path.exists(PID_FILE):
                os.remove(PID_FILE)
            self.logger.info("Deep Packet Inspector Engine stopped")
        return 0


if __name__ == "__main__":
    engine = DeepInspectorEngine()
    sys.exit(engine.run())