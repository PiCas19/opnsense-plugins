#!/usr/local/bin/python3

"""
WebGuard Configuration Export Script
Copyright (C) 2024 OPNsense WebGuard Plugin
All rights reserved.
"""

import sys
import json
import os
from datetime import datetime

CONFIG_FILE = '/usr/local/etc/webguard/config.json'

def export_config(config_data=None):
    """Export WebGuard configuration to JSON format"""
    try:
        if config_data:
            # Configuration data provided as argument (from API)
            config = json.loads(config_data) if isinstance(config_data, str) else config_data
        else:
            # Read from existing config file
            if not os.path.exists(CONFIG_FILE):
                print("ERROR: Configuration file not found")
                return False
            
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
        
        # Write configuration to file
        os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
        
        # Add metadata
        config['_metadata'] = {
            'exported_at': datetime.now().isoformat(),
            'version': '1.0.0',
            'source': 'webguard_export'
        }
        
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=2)
        
        print("OK: Configuration exported successfully")
        return True
        
    except Exception as e:
        print(f"ERROR: Failed to export configuration: {e}")
        return False

def main():
    if len(sys.argv) > 1:
        # Configuration data provided as command line argument
        config_data = sys.argv[1]
        export_config(config_data)
    else:
        # Export existing configuration
        export_config()

if __name__ == '__main__':
    main()