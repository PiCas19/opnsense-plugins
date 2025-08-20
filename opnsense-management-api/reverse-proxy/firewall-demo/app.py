#!/usr/bin/env python3
"""
Demo application for managing OPNsense Firewall rules.
Simulates SIEM calls to enable/disable security rules.
"""

from flask import Flask, render_template, request, jsonify
import requests
import os
import logging
from datetime import datetime
import urllib3
from requests.auth import HTTPBasicAuth

# Disable SSL warnings for the demo (test environment only)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'demo-secret-key-change-me')

# Logging configuration
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# OPNsense configuration from environment variables
OPNSENSE_CONFIG = {
    'host': os.environ.get('OPNSENSE_HOST', '192.168.216.1'),
    'port': os.environ.get('OPNSENSE_PORT', '443'),
    'api_key': os.environ.get('OPNSENSE_API_KEY', ''),
    'api_secret': os.environ.get('OPNSENSE_API_SECRET', ''),
    'verify_ssl': False  # For demo/test
}

class OPNsenseAPI:
    """OPNsense API client"""
    
    def __init__(self, config):
        self.base_url = f"https://{config['host']}:{config['port']}"
        self.auth = HTTPBasicAuth(config['api_key'], config['api_secret'])
        self.verify_ssl = config['verify_ssl']
        self.session = requests.Session()
        self.session.auth = self.auth
        self.session.verify = self.verify_ssl
    
    def test_connection(self):
        """Test connectivity to the OPNsense API"""
        try:
            response = self.session.get(f"{self.base_url}/api/core/firmware/status")
            return response.status_code == 200
        except Exception as e:
            logger.error(f"OPNsense connection error: {e}")
            return False
    
    def get_firewall_rules(self):
        """Get firewall rule list"""
        try:
            response = self.session.get(f"{self.base_url}/api/firewall/filter/searchRule")
            if response.status_code == 200:
                return response.json()
            return None
        except Exception as e:
            logger.error(f"Error retrieving rules: {e}")
            return None
    
    def toggle_rule(self, rule_uuid, enabled=True):
        """Enable/disable a firewall rule"""
        try:
            # First fetch the current rule
            response = self.session.get(f"{self.base_url}/api/firewall/filter/getRule/{rule_uuid}")
            if response.status_code != 200:
                return False, "Rule not found"
            
            rule_data = response.json()
            rule_data['rule']['enabled'] = '1' if enabled else '0'
            
            # Update the rule
            response = self.session.post(
                f"{self.base_url}/api/firewall/filter/setRule/{rule_uuid}",
                data=rule_data
            )
            
            if response.status_code == 200:
                # Apply changes
                apply_response = self.session.post(f"{self.base_url}/api/firewall/filter/apply")
                return apply_response.status_code == 200, "Rule updated successfully"
            
            return False, "Rule update error"
            
        except Exception as e:
            logger.error(f"Rule toggle error: {e}")
            return False, str(e)

# Initialize OPNsense client
opnsense_client = OPNsenseAPI(OPNSENSE_CONFIG)

# Demo rule simulation (if the API is unavailable)
DEMO_RULES = [
    {
        "uuid": "demo-rule-1",
        "description": "Block Malicious IPs",
        "action": "block",
        "enabled": True,
        "source": "192.168.100.0/24",
        "destination": "any",
        "created": "2024-01-15 10:30:00"
    },
    {
        "uuid": "demo-rule-2", 
        "description": "Allow Management Access",
        "action": "pass",
        "enabled": True,
        "source": "192.168.1.0/24",
        "destination": "192.168.216.1",
        "created": "2024-01-15 11:00:00"
    },
    {
        "uuid": "demo-rule-3",
        "description": "Block Suspicious Port Scans",
        "action": "block", 
        "enabled": False,
        "source": "any",
        "destination": "192.168.216.0/24",
        "created": "2024-01-15 12:15:00"
    },
    {
        "uuid": "demo-rule-4",
        "description": "Block Brute Force Attacks",
        "action": "block", 
        "enabled": False,
        "source": "any",
        "destination": "192.168.216.1",
        "created": "2024-01-15 13:00:00"
    }
]

@app.route('/')
def index():
    """Main dashboard"""
    # Test OPNsense connection
    opnsense_status = opnsense_client.test_connection()
    
    # Get rules (real or demo)
    if opnsense_status:
        rules_data = opnsense_client.get_firewall_rules()
        rules = rules_data.get('rows', []) if rules_data else DEMO_RULES
    else:
        rules = DEMO_RULES
    
    return render_template('index.html', 
                         rules=rules, 
                         opnsense_status=opnsense_status,
                         opnsense_host=OPNSENSE_CONFIG['host'])

@app.route('/api/rules')
def api_get_rules():
    """API: Get rule list"""
    try:
        if opnsense_client.test_connection():
            rules_data = opnsense_client.get_firewall_rules()
            rules = rules_data.get('rows', []) if rules_data else DEMO_RULES
        else:
            rules = DEMO_RULES
        
        return jsonify({
            'success': True,
            'rules': rules,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/rules/<rule_id>/toggle', methods=['POST'])
def api_toggle_rule(rule_id):
    """API: Enable/disable rule (SIEM call simulation)"""
    try:
        enabled = request.json.get('enabled', True)
        reason = request.json.get('reason', 'Manual toggle')
        
        logger.info(f"SIEM Request: Toggle rule {rule_id} to {'enabled' if enabled else 'disabled'}, reason: {reason}")
        
        # Try real API first
        if opnsense_client.test_connection():
            success, message = opnsense_client.toggle_rule(rule_id, enabled)
        else:
            # Demo simulation
            success = True
            message = f"Demo: Rule {rule_id} {'enabled' if enabled else 'disabled'}"
            
            # Update local demo rule
            for rule in DEMO_RULES:
                if rule['uuid'] == rule_id:
                    rule['enabled'] = enabled
                    break
        
        if success:
            return jsonify({
                'success': True,
                'message': message,
                'rule_id': rule_id,
                'enabled': enabled,
                'timestamp': datetime.now().isoformat()
            })
        else:
            return jsonify({
                'success': False,
                'error': message
            }), 400
            
    except Exception as e:
        logger.error(f"Rule toggle error: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/siem/incident', methods=['POST'])
def api_siem_incident():
    """API: Simulate a SIEM incident that triggers rules"""
    try:
        incident_data = request.json
        incident_type = incident_data.get('type', 'unknown')
        severity = incident_data.get('severity', 'medium')
        source_ip = incident_data.get('source_ip', 'unknown')
        
        logger.info(f"SIEM Incident: {incident_type}, severity: {severity}, source: {source_ip}")
        
        # Automatic response logic based on incident type
        response_actions = []
        
        if incident_type == 'malicious_ip':
            # Enable rule to block malicious IPs
            for rule in DEMO_RULES:
                if 'malicious' in rule['description'].lower():
                    rule['enabled'] = True
                    response_actions.append(f"Enabled rule: {rule['description']}")
                    
        elif incident_type == 'port_scan':
            # Enable anti port-scan rule
            for rule in DEMO_RULES:
                if 'port scan' in rule['description'].lower():
                    rule['enabled'] = True
                    response_actions.append(f"Enabled rule: {rule['description']}")
                    
        elif incident_type == 'brute_force':
            # Enable anti brute-force rule
            for rule in DEMO_RULES:
                if 'brute force' in rule['description'].lower():
                    rule['enabled'] = True
                    response_actions.append(f"Enabled rule: {rule['description']}")
        
        return jsonify({
            'success': True,
            'incident_id': f"INC-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            'actions_taken': response_actions,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"SIEM incident handling error: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/status')
def api_status():
    """API: System status"""
    opnsense_status = opnsense_client.test_connection()
    
    return jsonify({
        'service': 'OPNsense Firewall Demo',
        'status': 'healthy',
        'opnsense_connected': opnsense_status,
        'opnsense_host': OPNSENSE_CONFIG['host'],
        'timestamp': datetime.now().isoformat()
    })

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)