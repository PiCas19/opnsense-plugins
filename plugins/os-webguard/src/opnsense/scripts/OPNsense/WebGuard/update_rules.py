#!/usr/local/bin/python3.11

"""
WebGuard Rules Update Script
Copyright (C) 2024 OPNsense WebGuard Plugin
All rights reserved.
"""

import os
import json
import time
from datetime import datetime

WAF_RULES_FILE = "/usr/local/etc/webguard/waf_rules.json"
ATTACK_PATTERNS_FILE = "/usr/local/etc/webguard/attack_patterns.json"

def download_rules():
    """Download and update WAF rules"""
    try:
        print("Updating WebGuard rules...")
        
        # For now, we'll create updated local rules
        # In production, this would download from a threat intelligence feed
        
        # Update WAF rules - PATTERN CORRETTI PER JSON
        updated_waf_rules = {
            "version": "1.0",
            "updated": datetime.now().isoformat(),
            "rules": [
                {
                    "id": 1,
                    "name": "SQL Injection - UNION SELECT",
                    "type": "sql_injection",
                    "pattern": "union\\\\s+select",
                    "enabled": True,
                    "score": 50,
                    "description": "Detects UNION SELECT SQL injection attempts"
                },
                {
                    "id": 2,
                    "name": "SQL Injection - OR 1=1",
                    "type": "sql_injection",
                    "pattern": "or\\\\s+1\\\\s*=\\\\s*1",
                    "enabled": True,
                    "score": 45,
                    "description": "Detects classic OR 1=1 SQL injection"
                },
                {
                    "id": 3,
                    "name": "SQL Injection - DROP TABLE",
                    "type": "sql_injection",
                    "pattern": "drop\\\\s+table",
                    "enabled": True,
                    "score": 60,
                    "description": "Detects DROP TABLE SQL injection"
                },
                {
                    "id": 4,
                    "name": "XSS - Script Tag",
                    "type": "xss",
                    "pattern": "<script[^>]*>.*?</script>",
                    "enabled": True,
                    "score": 40,
                    "description": "Detects script tag XSS attempts"
                },
                {
                    "id": 5,
                    "name": "XSS - JavaScript Protocol",
                    "type": "xss",
                    "pattern": "javascript:",
                    "enabled": True,
                    "score": 35,
                    "description": "Detects javascript: protocol XSS"
                },
                {
                    "id": 6,
                    "name": "XSS - Event Handlers",
                    "type": "xss",
                    "pattern": "on(load|error|click|mouseover)\\\\s*=",
                    "enabled": True,
                    "score": 38,
                    "description": "Detects event handler XSS"
                },
                {
                    "id": 7,
                    "name": "Command Injection - Basic",
                    "type": "command_injection",
                    "pattern": "[\\\\;\\\\|&`\\\\$\\\\(\\\\)].*?(ls|cat|wget|curl|nc)",
                    "enabled": True,
                    "score": 60,
                    "description": "Detects basic command injection attempts"
                },
                {
                    "id": 8,
                    "name": "Command Injection - Windows",
                    "type": "command_injection",
                    "pattern": "(cmd\\\\.exe|powershell).*?[\\\\;\\\\|&]",
                    "enabled": True,
                    "score": 55,
                    "description": "Detects Windows command injection"
                },
                {
                    "id": 9,
                    "name": "Path Traversal - Unix",
                    "type": "lfi",
                    "pattern": "\\\\.\\\\.\\\\/.*?\\\\.\\\\.\\\\/.*?\\\\.\\\\.\\\\/",
                    "enabled": True,
                    "score": 45,
                    "description": "Detects Unix path traversal"
                },
                {
                    "id": 10,
                    "name": "Path Traversal - Windows",
                    "type": "lfi",
                    "pattern": "\\\\.\\\\.*?\\\\.\\\\.*?\\\\.\\\\",
                    "enabled": True,
                    "score": 45,
                    "description": "Detects Windows path traversal"
                },
                {
                    "id": 11,
                    "name": "Remote File Inclusion",
                    "type": "rfi",
                    "pattern": "https?:\\\\/\\\\/[^\\\\/\\\\s]+\\\\.",
                    "enabled": True,
                    "score": 40,
                    "description": "Detects remote file inclusion"
                },
                {
                    "id": 12,
                    "name": "CSRF Token Bypass",
                    "type": "csrf",
                    "pattern": "csrf_token\\\\s*=\\\\s*['\"]?\\\\s*['\"]?",
                    "enabled": True,
                    "score": 30,
                    "description": "Detects CSRF token bypass attempts"
                }
            ]
        }
        
        # Update attack patterns
        updated_attack_patterns = {
            "version": "1.1",
            "updated": datetime.now().isoformat(),
            "patterns": {
                "malware_signatures": [
                    "X5O!P%@AP\\\\[4\\\\\\\\PZX54\\\\(P\\\\^\\\\)7CC\\\\)7\\\\}\\\\$EICAR",
                    "TVqQAAMAAAAEAAAA//8AALgAAAAA",
                    "\\\\x4d\\\\x5a",
                    "PK\\\\x03\\\\x04",
                    "Rar!\\\\x1a\\\\x07\\\\x00"
                ],
                "crypto_mining": [
                    "coinhive",
                    "cryptonight",
                    "monero",
                    "stratum",
                    "mining",
                    "miner",
                    "hashrate",
                    "difficulty"
                ],
                "suspicious_urls": [
                    "bit\\\\.ly",
                    "tinyurl\\\\.com",
                    "t\\\\.co",
                    "goo\\\\.gl",
                    "ow\\\\.ly"
                ],
                "data_exfiltration": [
                    "base64",
                    "data:image",
                    "data:text",
                    "btoa\\\\(",
                    "atob\\\\(",
                    "eval\\\\("
                ],
                "command_injection": [
                    "system\\\\(",
                    "exec\\\\(",
                    "shell_exec\\\\(",
                    "passthru\\\\(",
                    "popen\\\\(",
                    "proc_open\\\\("
                ],
                "script_injection": [
                    "<iframe",
                    "<object",
                    "<embed",
                    "<applet",
                    "vbscript:",
                    "data:text\\\\/html"
                ]
            }
        }
        
        # Save updated rules
        os.makedirs(os.path.dirname(WAF_RULES_FILE), exist_ok=True)
        
        with open(WAF_RULES_FILE, 'w') as f:
            json.dump(updated_waf_rules, f, indent=2)
        
        with open(ATTACK_PATTERNS_FILE, 'w') as f:
            json.dump(updated_attack_patterns, f, indent=2)
        
        print(f"Rules updated successfully")
        print(f"WAF rules: {len(updated_waf_rules['rules'])} rules")
        print(f"Attack patterns: {sum(len(patterns) for patterns in updated_attack_patterns['patterns'].values())} patterns")
        
        return True
        
    except Exception as e:
        print(f"Error updating rules: {e}")
        return False

def check_rules_age():
    """Check if rules need updating"""
    try:
        if not os.path.exists(WAF_RULES_FILE):
            return True
        
        # Check file modification time
        file_age = time.time() - os.path.getmtime(WAF_RULES_FILE)
        
        # Update if older than 24 hours
        return file_age > 86400
        
    except Exception:
        return True

if __name__ == "__main__":
    if check_rules_age():
        download_rules()
    else:
        print("Rules are up to date")