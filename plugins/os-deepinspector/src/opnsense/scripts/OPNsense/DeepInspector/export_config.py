#!/usr/local/bin/python3
# export_config.py - Export OPNsense configuration to DPI engine format

import os
import json
import xml.etree.ElementTree as ET

CONFIG_FILE = "/usr/local/etc/deepinspector/config.json"
OPNSENSE_CONFIG = "/conf/config.xml"

def export_config():
    """Export OPNsense DPI configuration to JSON format"""
    try:
        if not os.path.exists(OPNSENSE_CONFIG):
            print("OPNsense config file not found")
            return False
            
        tree = ET.parse(OPNSENSE_CONFIG)
        root = tree.getroot()
        
        # Find DeepInspector configuration
        dpi_node = root.find(".//OPNsense/DeepInspector")
        if dpi_node is None:
            print("DeepInspector configuration not found")
            return False
            
        config = {
            'general': {},
            'protocols': {},
            'detection': {},
            'advanced': {}
        }
        
        # Extract general settings
        general = dpi_node.find("general")
        if general is not None:
            for child in general:
                value = child.text or ""
                # Convert boolean strings
                if value in ['0', '1']:
                    value = value == '1'
                config['general'][child.tag] = value
                
        # Extract protocol settings
        protocols = dpi_node.find("protocols")
        if protocols is not None:
            for child in protocols:
                value = child.text or ""
                if value in ['0', '1']:
                    value = value == '1'
                config['protocols'][child.tag] = value
                
        # Extract detection settings
        detection = dpi_node.find("detection")
        if detection is not None:
            for child in detection:
                value = child.text or ""
                if value in ['0', '1']:
                    value = value == '1'
                config['detection'][child.tag] = value
                
        # Extract advanced settings
        advanced = dpi_node.find("advanced")
        if advanced is not None:
            for child in advanced:
                value = child.text or ""
                if value in ['0', '1']:
                    value = value == '1'
                elif value.isdigit():
                    value = int(value)
                config['advanced'][child.tag] = value
                
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