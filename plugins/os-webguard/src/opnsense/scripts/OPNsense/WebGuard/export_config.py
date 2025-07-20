#!/usr/local/bin/python3.11
# export_config.py - Export OPNsense configuration to WebGuard engine format
import os
import json
import xml.etree.ElementTree as ET

CONFIG_FILE = "/usr/local/etc/webguard/config.json"
OPNSENSE_CONFIG = "/conf/config.xml"

def export_config():
    """Export OPNsense WebGuard configuration to JSON format"""
    try:
        if not os.path.exists(OPNSENSE_CONFIG):
            print("OPNsense config file not found")
            return False
            
        tree = ET.parse(OPNSENSE_CONFIG)
        root = tree.getroot()
        
        # Find WebGuard configuration
        webguard_node = root.find(".//OPNsense/WebGuard")
        if webguard_node is None:
            print("WebGuard configuration not found")
            return False
            
        config = {
            'general': {},
            'waf': {},
            'behavioral': {},
            'covert_channels': {},
            'response': {},
            'whitelist': {}
        }
        
        # Extract general settings
        general = webguard_node.find("general")
        if general is not None:
            for child in general:
                value = child.text or ""
                # Convert boolean strings
                if value in ['0', '1']:
                    value = value == '1'
                elif value.isdigit():
                    value = int(value)
                config['general'][child.tag] = value
        
        # Extract WAF settings
        waf = webguard_node.find("waf")
        if waf is not None:
            for child in waf:
                value = child.text or ""
                if value in ['0', '1']:
                    value = value == '1'
                config['waf'][child.tag] = value
        
        # Extract behavioral settings
        behavioral = webguard_node.find("behavioral")
        if behavioral is not None:
            for child in behavioral:
                value = child.text or ""
                if value in ['0', '1']:
                    value = value == '1'
                config['behavioral'][child.tag] = value
        
        # Extract covert channels settings
        covert_channels = webguard_node.find("covert_channels")
        if covert_channels is not None:
            for child in covert_channels:
                value = child.text or ""
                if value in ['0', '1']:
                    value = value == '1'
                config['covert_channels'][child.tag] = value
        
        # Extract response settings
        response = webguard_node.find("response")
        if response is not None:
            for child in response:
                value = child.text or ""
                if value in ['0', '1']:
                    value = value == '1'
                config['response'][child.tag] = value
        
        # Extract whitelist settings
        whitelist = webguard_node.find("whitelist")
        if whitelist is not None:
            for child in whitelist:
                value = child.text or ""
                if value in ['0', '1']:
                    value = value == '1'
                config['whitelist'][child.tag] = value
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
        
        # Write configuration
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=2)
            
        print(f"Configuration exported to {CONFIG_FILE}")
        return True
        
    except Exception as e:
        print(f"Error exporting configuration: {e}")
        return False

if __name__ == "__main__":
    export_config()