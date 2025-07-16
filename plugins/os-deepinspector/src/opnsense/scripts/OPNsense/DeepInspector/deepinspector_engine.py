#!/usr/local/bin/python3
# deepinspector_engine.py - Main DPI Engine

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
import zlib
import base64
from collections import defaultdict, deque
from datetime import datetime, timedelta
import ipaddress
import socket
import subprocess

# Network capture and analysis
try:
    import pcapy
    import dpkt
except ImportError:
    print("Error: Required packages not installed. Install pcapy and dpkt.")
    sys.exit(1)

# Configuration and logging
CONFIG_FILE = "/usr/local/etc/deepinspector/config.json"
SIGNATURES_FILE = "/usr/local/etc/deepinspector/signatures.json"
LOG_DIR = "/var/log/deepinspector"
ALERT_LOG = f"{LOG_DIR}/alerts.log"
THREAT_LOG = f"{LOG_DIR}/threats.log"
DETECTION_LOG = f"{LOG_DIR}/detections.log"
ENGINE_LOG = f"{LOG_DIR}/engine.log"
STATS_FILE = f"{LOG_DIR}/stats.json"
PID_FILE = "/var/run/deepinspector.pid"

# Global state
running = True
config = {}
signatures = {}
stats = {
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
        'scada_alerts': 0
    }
}

# Threat detection engines
threat_patterns = {
    'malware_signatures': [],
    'suspicious_urls': [],
    'command_injection': [],
    'sql_injection': [],
    'script_injection': [],
    'crypto_mining': [],
    'data_exfiltration': [],
    'industrial_threats': []
}

# Performance monitoring
performance_history = deque(maxlen=3600)
packet_buffer = deque(maxlen=10000)
latency_measurements = deque(maxlen=1000)

def setup_logging():
    """Initialize logging system"""
    os.makedirs(LOG_DIR, exist_ok=True)
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(ENGINE_LOG),
            logging.StreamHandler()
        ]
    )
    
    return logging.getLogger(__name__)

def load_config():
    """Load DPI engine configuration"""
    global config
    try:
        with open(CONFIG_FILE, 'r') as f:
            config = json.load(f)
            
        # Set defaults for missing values
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
        
        # Merge defaults with loaded config
        for section, values in defaults.items():
            if section not in config:
                config[section] = {}
            for key, default_value in values.items():
                if key not in config[section]:
                    config[section][key] = default_value
                    
        logger.info(f"Configuration loaded: {len(config)} sections")
        return True
        
    except Exception as e:
        logger.error(f"Failed to load configuration: {e}")
        config = defaults
        return False

def load_signatures():
    """Load threat detection signatures"""
    global signatures, threat_patterns
    
    try:
        with open(SIGNATURES_FILE, 'r') as f:
            signatures = json.load(f)
            
        # Compile threat patterns for faster matching
        for category, patterns in signatures.get('patterns', {}).items():
            if category in threat_patterns:
                threat_patterns[category] = [re.compile(pattern, re.IGNORECASE) for pattern in patterns]
                
        logger.info(f"Loaded {sum(len(patterns) for patterns in threat_patterns.values())} threat signatures")
        return True
        
    except Exception as e:
        logger.warning(f"Failed to load signatures: {e}")
        load_default_signatures()
        return False

def load_default_signatures():
    """Load minimal default threat signatures"""
    global threat_patterns
    
    # Basic malware patterns
    threat_patterns['malware_signatures'] = [
        re.compile(r'X5O!P%@AP\[4\\PZX54\(P\^\)7CC\)7\}\$EICAR', re.IGNORECASE),
        re.compile(r'TVqQAAMAAAAEAAAA//8AALgAAAAA', re.IGNORECASE),
        re.compile(r'\\x4d\\x5a', re.IGNORECASE),
    ]
    
    # Command injection patterns
    threat_patterns['command_injection'] = [
        re.compile(r'[\;\|&`\$\(\)].*?(ls|cat|wget|curl|nc|netcat)', re.IGNORECASE),
        re.compile(r'(cmd\.exe|powershell|bash|sh).*?[\;\|&]', re.IGNORECASE),
        re.compile(r'\\x[0-9a-f]{2}.*?(system|exec|eval)', re.IGNORECASE),
    ]
    
    # Industrial protocol threat patterns
    threat_patterns['industrial_threats'] = [
        re.compile(r'(modbus|dnp3|opcua).*?(exploit|attack|malicious)', re.IGNORECASE),
        re.compile(r'(scada|plc|hmi).*?(compromise|hijack|control)', re.IGNORECASE),
        re.compile(r'(function_code|unit_id).*?(0x[0-9a-f]+)', re.IGNORECASE),
    ]

def analyze_packet(packet_data, timestamp):
    """Analyze individual packet for threats"""
    global stats
    
    start_time = time.time()
    
    try:
        # Parse packet
        eth = dpkt.ethernet.Ethernet(packet_data)
        if not isinstance(eth.data, dpkt.ip.IP):
            return
            
        ip = eth.data
        stats['packets_analyzed'] += 1
        
        # Protocol analysis
        protocol = get_protocol_name(ip.p)
        stats['protocols_analyzed'][protocol] += 1
        
        # Deep packet inspection based on protocol
        threats = []
        
        if ip.p == dpkt.ip.IP_PROTO_TCP:
            tcp = ip.data
            threats.extend(analyze_tcp_packet(ip, tcp))
            
            # Industrial protocol detection
            if config['protocols']['industrial_protocols']:
                threats.extend(analyze_industrial_protocols(ip, tcp))
                
        elif ip.p == dpkt.ip.IP_PROTO_UDP:
            udp = ip.data
            threats.extend(analyze_udp_packet(ip, udp))
            
        # Record latency for industrial environments
        if config['general']['industrial_mode']:
            latency = (time.time() - start_time) * 1000000  # microseconds
            latency_measurements.append(latency)
            stats['performance']['latency_avg'] = sum(latency_measurements) / len(latency_measurements)
            
            # Alert if latency exceeds threshold
            if latency > config['advanced']['latency_threshold']:
                create_alert('high_latency', {
                    'latency': latency,
                    'threshold': config['advanced']['latency_threshold'],
                    'source_ip': socket.inet_ntoa(ip.src),
                    'destination_ip': socket.inet_ntoa(ip.dst)
                })
        
        # Process detected threats
        for threat in threats:
            process_threat(threat, ip, timestamp)
            
    except Exception as e:
        logger.error(f"Error analyzing packet: {e}")

def analyze_tcp_packet(ip, tcp):
    """Analyze TCP packet for threats"""
    threats = []
    
    try:
        payload = tcp.data
        if not payload:
            return threats
            
        # HTTP/HTTPS analysis
        if tcp.dport == 80 or tcp.sport == 80:
            if config['protocols']['http_inspection']:
                threats.extend(analyze_http_payload(payload))
                
        elif tcp.dport == 443 or tcp.sport == 443:
            if config['protocols']['https_inspection']:
                threats.extend(analyze_https_payload(payload))
                
        # FTP analysis
        elif tcp.dport == 21 or tcp.sport == 21:
            if config['protocols']['ftp_inspection']:
                threats.extend(analyze_ftp_payload(payload))
                
        # SMTP analysis
        elif tcp.dport == 25 or tcp.sport == 25:
            if config['protocols']['smtp_inspection']:
                threats.extend(analyze_smtp_payload(payload))
                
        # Generic payload analysis
        threats.extend(analyze_generic_payload(payload))
        
    except Exception as e:
        logger.error(f"Error analyzing TCP packet: {e}")
        
    return threats

def analyze_industrial_protocols(ip, tcp):
    """Analyze industrial protocol packets"""
    threats = []
    
    try:
        # Modbus (port 502)
        if tcp.dport == 502 or tcp.sport == 502:
            stats['industrial_stats']['modbus_packets'] += 1
            threats.extend(analyze_modbus_packet(tcp.data))
            
        # DNP3 (port 20000)
        elif tcp.dport == 20000 or tcp.sport == 20000:
            stats['industrial_stats']['dnp3_packets'] += 1
            threats.extend(analyze_dnp3_packet(tcp.data))
            
        # OPC UA (port 4840)
        elif tcp.dport == 4840 or tcp.sport == 4840:
            stats['industrial_stats']['opcua_packets'] += 1
            threats.extend(analyze_opcua_packet(tcp.data))
            
    except Exception as e:
        logger.error(f"Error analyzing industrial protocols: {e}")
        
    return threats

def analyze_modbus_packet(payload):
    """Analyze Modbus protocol packet"""
    threats = []
    
    try:
        if len(payload) < 8:
            return threats
            
        # Basic Modbus frame analysis
        transaction_id = struct.unpack('>H', payload[0:2])[0]
        protocol_id = struct.unpack('>H', payload[2:4])[0]
        length = struct.unpack('>H', payload[4:6])[0]
        unit_id = payload[6]
        function_code = payload[7]
        
        # Check for suspicious function codes
        dangerous_functions = [0x08, 0x11, 0x17]  # Diagnostics, Report Server ID, etc.
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
            
        # Check for anomalous packet sizes
        if length > 252:  # Modbus max PDU size
            threats.append({
                'type': 'industrial_threat',
                'subtype': 'modbus_oversized_packet',
                'severity': 'medium',
                'description': f'Oversized Modbus packet: {length} bytes',
                'details': {'packet_size': length}
            })
            
    except Exception as e:
        logger.error(f"Error analyzing Modbus packet: {e}")
        
    return threats

def analyze_dnp3_packet(payload):
    """Analyze DNP3 protocol packet"""
    threats = []
    
    try:
        if len(payload) < 10:
            return threats
            
        # DNP3 header analysis
        start_bytes = payload[0:2]
        if start_bytes != b'\x05\x64':
            return threats
            
        length = payload[2]
        control = payload[3]
        dest_addr = struct.unpack('<H', payload[4:6])[0]
        src_addr = struct.unpack('<H', payload[6:8])[0]
        
        # Check for broadcast addresses (potential attacks)
        if dest_addr == 0xFFFF or src_addr == 0xFFFF:
            threats.append({
                'type': 'industrial_threat',
                'subtype': 'dnp3_broadcast_attack',
                'severity': 'high',
                'description': 'DNP3 broadcast address detected',
                'details': {
                    'dest_addr': dest_addr,
                    'src_addr': src_addr
                }
            })
            
    except Exception as e:
        logger.error(f"Error analyzing DNP3 packet: {e}")
        
    return threats

def analyze_opcua_packet(payload):
    """Analyze OPC UA protocol packet"""
    threats = []
    
    try:
        if len(payload) < 8:
            return threats
            
        # Basic OPC UA message analysis
        message_type = payload[0:4]
        message_size = struct.unpack('<I', payload[4:8])[0]
        
        # Check for suspicious message types
        if message_type == b'ERR\x00':
            threats.append({
                'type': 'industrial_threat',
                'subtype': 'opcua_error_message',
                'severity': 'medium',
                'description': 'OPC UA error message detected',
                'details': {'message_type': message_type.decode('ascii', errors='ignore')}
            })
            
        # Check for oversized messages
        if message_size > 65536:  # Reasonable limit
            threats.append({
                'type': 'industrial_threat',
                'subtype': 'opcua_oversized_message',
                'severity': 'medium',
                'description': f'Oversized OPC UA message: {message_size} bytes',
                'details': {'message_size': message_size}
            })
            
    except Exception as e:
        logger.error(f"Error analyzing OPC UA packet: {e}")
        
    return threats

def analyze_http_payload(payload):
    """Analyze HTTP payload for threats"""
    threats = []
    
    try:
        payload_str = payload.decode('utf-8', errors='ignore')
        
        # Check against threat patterns
        for pattern in threat_patterns['command_injection']:
            if pattern.search(payload_str):
                threats.append({
                    'type': 'command_injection',
                    'severity': 'high',
                    'description': 'Command injection attempt detected in HTTP',
                    'pattern': pattern.pattern
                })
                
        for pattern in threat_patterns['sql_injection']:
            if pattern.search(payload_str):
                threats.append({
                    'type': 'sql_injection',
                    'severity': 'high',
                    'description': 'SQL injection attempt detected in HTTP',
                    'pattern': pattern.pattern
                })
                
        for pattern in threat_patterns['script_injection']:
            if pattern.search(payload_str):
                threats.append({
                    'type': 'script_injection',
                    'severity': 'medium',
                    'description': 'Script injection attempt detected in HTTP',
                    'pattern': pattern.pattern
                })
                
    except Exception as e:
        logger.error(f"Error analyzing HTTP payload: {e}")
        
    return threats

def analyze_generic_payload(payload):
    """Analyze generic payload for malware signatures"""
    threats = []
    
    try:
        # Convert to string for pattern matching
        payload_str = payload.decode('utf-8', errors='ignore')
        
        # Check malware signatures
        for pattern in threat_patterns['malware_signatures']:
            if pattern.search(payload_str):
                threats.append({
                    'type': 'malware',
                    'severity': 'critical',
                    'description': 'Malware signature detected',
                    'pattern': pattern.pattern
                })
                
        # Check crypto mining patterns
        for pattern in threat_patterns['crypto_mining']:
            if pattern.search(payload_str):
                threats.append({
                    'type': 'crypto_mining',
                    'severity': 'medium',
                    'description': 'Cryptocurrency mining activity detected',
                    'pattern': pattern.pattern
                })
                
    except Exception as e:
        logger.error(f"Error analyzing generic payload: {e}")
        
    return threats

def process_threat(threat, ip, timestamp):
    """Process detected threat"""
    global stats
    
    stats['threats_detected'] += 1
    stats['threat_types'][threat['type']] += 1
    
    if threat['severity'] == 'critical':
        stats['critical_alerts'] += 1
        
    # Create alert record
    alert = {
        'id': hashlib.md5(f"{timestamp}{ip.src}{ip.dst}{threat['type']}".encode()).hexdigest(),
        'timestamp': timestamp.isoformat(),
        'source_ip': socket.inet_ntoa(ip.src),
        'destination_ip': socket.inet_ntoa(ip.dst),
        'protocol': get_protocol_name(ip.p),
        'threat_type': threat['type'],
        'severity': threat['severity'],
        'description': threat['description'],
        'detection_method': threat.get('pattern', 'heuristic'),
        'zero_trust_triggered': config['general']['mode'] == 'active',
        'industrial_context': threat.get('subtype', '').startswith('modbus') or 
                            threat.get('subtype', '').startswith('dnp3') or 
                            threat.get('subtype', '').startswith('opcua')
    }
    
    # Add industrial-specific fields
    if alert['industrial_context']:
        stats['industrial_stats']['scada_alerts'] += 1
        alert['industrial_protocol'] = threat.get('subtype', '').split('_')[0]
        
    # Log alert
    log_alert(alert)
    
    # Take action based on mode
    if config['general']['mode'] == 'active':
        take_action(alert)

def log_alert(alert):
    """Log alert to file"""
    try:
        with open(ALERT_LOG, 'a') as f:
            f.write(json.dumps(alert) + '\n')
            
        logger.info(f"Alert: {alert['threat_type']} from {alert['source_ip']} - {alert['description']}")
        
    except Exception as e:
        logger.error(f"Error logging alert: {e}")

def take_action(alert):
    """Take action on detected threat"""
    try:
        # Block IP if critical threat
        if alert['severity'] == 'critical':
            block_ip(alert['source_ip'])
            
        # Emergency shutdown for critical industrial threats
        if alert['industrial_context'] and alert['severity'] == 'critical':
            logger.critical(f"Critical industrial threat detected: {alert['description']}")
            # Could trigger emergency protocols here
            
    except Exception as e:
        logger.error(f"Error taking action: {e}")

def block_ip(ip_address):
    """Block IP address using pfctl"""
    try:
        subprocess.run(['pfctl', '-t', 'deepinspector_blocked', '-T', 'add', ip_address], 
                      check=True, capture_output=True)
        logger.info(f"Blocked IP address: {ip_address}")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to block IP {ip_address}: {e}")

def get_protocol_name(protocol_number):
    """Get protocol name from number"""
    protocol_map = {
        1: 'ICMP',
        6: 'TCP',
        17: 'UDP',
        47: 'GRE',
        50: 'ESP',
        51: 'AH'
    }
    return protocol_map.get(protocol_number, f'Protocol-{protocol_number}')

def save_stats():
    """Save statistics to file"""
    try:
        stats['timestamp'] = datetime.now().isoformat()
        with open(STATS_FILE, 'w') as f:
            json.dump(stats, f, indent=2, default=str)
    except Exception as e:
        logger.error(f"Error saving stats: {e}")

def signal_handler(signum, frame):
    """Handle shutdown signals"""
    global running
    logger.info(f"Received signal {signum}, shutting down...")
    running = False

def main():
    """Main DPI engine loop"""
    global logger, running
    
    # Setup
    logger = setup_logging()
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    
    # Save PID
    with open(PID_FILE, 'w') as f:
        f.write(str(os.getpid()))
    
    logger.info("Starting Deep Packet Inspector Engine")
    
    # Load configuration and signatures
    if not load_config():
        logger.error("Failed to load configuration")
        return 1
        
    if not load_signatures():
        logger.warning("Using default signatures")
        
    # Check if enabled
    if not config['general']['enabled']:
        logger.info("DPI engine is disabled in configuration")
        return 0
        
    # Start packet capture
    interfaces = config['general']['interfaces']
    if not interfaces:
        logger.error("No interfaces configured for monitoring")
        return 1
        
    logger.info(f"Starting packet capture on interfaces: {interfaces}")
    
    # Statistics thread
    stats_thread = threading.Thread(target=lambda: [save_stats(), time.sleep(60)] and None)
    stats_thread.daemon = True
    stats_thread.start()
    
    # Main packet processing loop
    try:
        for interface in interfaces:
            try:
                cap = pcapy.open_live(interface, 
                                    config['general']['max_packet_size'], 
                                    1,  # promiscuous mode
                                    100)  # timeout
                
                logger.info(f"Capturing on interface: {interface}")
                
                while running:
                    header, packet = cap.next()
                    if packet:
                        analyze_packet(packet, datetime.now())
                        
            except Exception as e:
                logger.error(f"Error capturing on interface {interface}: {e}")
                continue
                
    except KeyboardInterrupt:
        logger.info("Received keyboard interrupt")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        return 1
    finally:
        # Cleanup
        save_stats()
        if os.path.exists(PID_FILE):
            os.remove(PID_FILE)
        logger.info("Deep Packet Inspector Engine stopped")
        
    return 0

if __name__ == "__main__":
    sys.exit(main())