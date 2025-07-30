#!/usr/bin/env python3
# quick_test.py - Test native API

import requests

class QuickOPNsenseTest:
    def __init__(self):
        self.host = "192.168.216.1"
        self.api_key = "your_api_key"
        self.api_secret = "your_api_secret"
        self.base_url = f"http://{self.host}/api"
        self.auth = (self.api_key, self.api_secret)
    
    def test_connection(self):
        """Test basic connectivity"""
        try:
            response = requests.get(
                f"{self.base_url}/core/system/status",
                auth=self.auth, verify=False, timeout=10
            )
            return response.status_code == 200
        except:
            return False
    
    def get_rules_count(self):
        """Get active rules count"""
        response = requests.get(
            f"{self.base_url}/firewall/filter/get",
            auth=self.auth, verify=False
        )
        data = response.json()
        active_rules = [r for r in data.get("rows", []) if r.get("enabled") == "1"]
        return len(active_rules)
    
    def emergency_block_ip(self, ip, reason="TEST BLOCK"):
        """Emergency IP block"""
        rule_data = {
            "rule": {
                "enabled": "1",
                "interface": "wan",
                "action": "block",
                "source_net": ip,
                "description": f"EMERGENCY: {reason}"
            }
        }
        
        # Add rule
        response = requests.post(
            f"{self.base_url}/firewall/filter/addRule",
            json=rule_data, auth=self.auth, verify=False
        )
        
        if response.json().get("result") == "saved":
            # Apply changes
            apply_response = requests.post(
                f"{self.base_url}/firewall/filter/apply",
                auth=self.auth, verify=False
            )
            return {
                "blocked": True,
                "rule_uuid": response.json().get("uuid"),
                "applied": apply_response.json().get("status") == "ok"
            }
        return {"blocked": False}

# Quick test
if __name__ == "__main__":
    test = QuickOPNsenseTest()
    
    print("QUICK OPNSENSE API TEST")
    print(f"Connection: {'SUCCESS' if test.test_connection() else 'FAILED'}")
    print(f"Active Rules: {test.get_rules_count()}")
    
    # Test emergency block
    result = test.emergency_block_ip("1.2.3.4", "Quick Test")
    print(f"Emergency Block: {'SUCCESS' if result['blocked'] else 'FAILED'}")
    
    print("Phase 1 Complete!")