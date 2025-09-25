#!/usr/local/bin/python3
"""
DeepInspector OPNsense Configuration Exporter - Enhanced Version
----------------------------------------------------------------
Reads the OPNsense system configuration (config.xml), parses
all DeepInspector plugin settings, and exports them to a JSON
file for the DPI engine.

Features:
- Robust defaults integrated in export process
- Full support for <general>, <protocols>, <detection>, <advanced>
- Boolean and integer normalization with fallback
- Handles missing fields gracefully with smart defaults
- Creates output directories automatically
- Auto-detects network interfaces
- Creates default configuration if OPNsense config missing
- Intelligent merge of XML config with defaults

Author: Pierpaolo Casati
Version: 3.0 (Enhanced with integrated defaults)
"""

import json
import xml.etree.ElementTree as ET
import subprocess
import os
from pathlib import Path
from typing import Dict, Any, Optional, List


class ConfigExporter:
    """
    Exports DeepInspector configuration from OPNsense config.xml
    to a JSON file for the DPI engine, with robust defaults and fallback.
    """

    def __init__(self,
                 source_xml: str = "/conf/config.xml",
                 target_json: str = "/usr/local/etc/deepinspector/config.json"):
        """
        Initialize the exporter.

        Args:
            source_xml: Path to the OPNsense XML configuration file.
            target_json: Path to the output JSON configuration file.
        """
        self.source_path = Path(source_xml)
        self.target_path = Path(target_json)

    def _get_comprehensive_defaults(self) -> Dict[str, Dict[str, Any]]:
        """
        Define comprehensive default configuration.
        
        Returns:
            Complete default configuration dictionary
        """
        interfaces = self._detect_network_interfaces()
        
        return {
            "general": {
                "enabled": False,
                "mode": "passive",
                "interfaces": interfaces,
                "trusted_networks": [
                    "192.168.1.0/24",
                    "192.168.0.0/24", 
                    "10.0.0.0/8",
                    "172.16.0.0/12"
                ],
                "max_packet_size": 1500,
                "deep_scan_ports": "80,443,21,25,53,502,4840,20000",
                "ssl_inspection": False,
                "archive_extraction": False,
                "malware_detection": True,
                "anomaly_detection": False,
                "performance_profile": "balanced",
                "low_latency_mode": False,
                "industrial_mode": False,
                "log_level": "info"
            },
            "protocols": {
                "http_inspection": True,
                "https_inspection": False,
                "ftp_inspection": True,
                "smtp_inspection": True,
                "dns_inspection": True,
                "industrial_protocols": True,
                "p2p_detection": False,
                "voip_inspection": False,
                "custom_protocols": ""
            },
            "detection": {
                "virus_signatures": True,
                "trojan_detection": True,
                "crypto_mining": True,
                "data_exfiltration": True,
                "command_injection": True,
                "sql_injection": True,
                "script_injection": True,
                "suspicious_downloads": False,
                "phishing_detection": False,
                "botnet_detection": False,
                "steganography_detection": False,
                "zero_day_heuristics": True
            },
            "advanced": {
                "signature_updates": True,
                "update_interval": 24,
                "threat_intelligence_feeds": "",
                "custom_signatures": "",
                "quarantine_enabled": False,
                "quarantine_path": "/var/quarantine/deepinspector",
                "memory_limit": 1024,
                "thread_count": 4,
                "packet_buffer_size": 10000,
                "analysis_timeout": 5,
                "bypass_trusted_networks": True,
                "industrial_optimization": False,
                "scada_protocols": True,
                "plc_protocols": True,
                "latency_threshold": 100
            }
        }

    def _convert_value(self, value: Optional[str]) -> Any:
        """
        Convert XML string values to Python types.

        Args:
            value: XML text value

        Returns:
            Converted Python object (bool for "0"/"1", int for digits, str otherwise)
        """
        if value is None:
            return ""
        val = value.strip()
        if val in ("0", "1"):
            return val == "1"
        if val.isdigit():
            return int(val)
        return val

    def _extract_section(self, parent: ET.Element, section_name: str) -> Dict[str, Any]:
        """
        Extract key-value pairs from a given XML section.

        Args:
            parent: Parent XML node containing the section
            section_name: Name of the child node to extract

        Returns:
            Dictionary of settings for that section
        """
        section_data: Dict[str, Any] = {}
        node = parent.find(section_name)
        if node is not None:
            for child in node:
                section_data[child.tag] = self._convert_value(child.text)
        return section_data

    def _detect_network_interfaces(self) -> List[str]:
        """
        Detect available network interfaces on the system.
        
        Returns:
            List of available network interface names
        """
        try:
            result = subprocess.run(['ifconfig', '-l'], 
                                  capture_output=True, text=True, check=True)
            interfaces = result.stdout.strip().split()
            
            # Filter out loopback and other non-physical interfaces
            physical_interfaces = []
            for iface in interfaces:
                if not iface.startswith(('lo', 'pflog', 'pfsync', 'enc')):
                    physical_interfaces.append(iface)
            
            print(f"Detected network interfaces: {', '.join(physical_interfaces)}")
            return physical_interfaces[:3] if physical_interfaces else ["em0", "em1"]
            
        except Exception as e:
            print(f"Could not detect network interfaces: {e}")
            return ["em0", "em1"]  # FreeBSD default fallback

    def _load_xml_config(self) -> Optional[Dict[str, Dict[str, Any]]]:
        """
        Load configuration from OPNsense XML file.
        
        Returns:
            Configuration dictionary or None if not found/invalid
        """
        if not self.source_path.exists():
            print(f"OPNsense config file not found: {self.source_path}")
            return None
            
        try:
            tree = ET.parse(self.source_path)
            root = tree.getroot()
            
            # Locate the DeepInspector node
            dpi_node = root.find(".//OPNsense/DeepInspector")
            if dpi_node is None:
                print("DeepInspector configuration not found in OPNsense config.xml")
                return None
                
            # Build configuration dictionary from XML
            xml_config = {
                "general": self._extract_section(dpi_node, "general"),
                "protocols": self._extract_section(dpi_node, "protocols"),
                "detection": self._extract_section(dpi_node, "detection"),
                "advanced": self._extract_section(dpi_node, "advanced"),
            }
            
            print(f"Found DeepInspector configuration in {self.source_path}")
            return xml_config
            
        except Exception as e:
            print(f"Error parsing OPNsense config: {e}")
            return None

    def _merge_with_defaults(self, xml_config: Dict[str, Dict[str, Any]], 
                            defaults: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """
        Merge XML configuration with defaults, ensuring all required fields exist.
        
        Args:
            xml_config: Configuration loaded from OPNsense XML
            defaults: Default configuration values
            
        Returns:
            Merged configuration dictionary
        """
        merged = {}
        
        for section_name, default_section in defaults.items():
            merged[section_name] = {}
            xml_section = xml_config.get(section_name, {})
            
            for key, default_value in default_section.items():
                if key in xml_section and xml_section[key] is not None and xml_section[key] != "":
                    # Use value from XML
                    merged[section_name][key] = xml_section[key]
                else:
                    # Use default value
                    merged[section_name][key] = default_value
                    
        print("Configuration merged: XML values used where available, defaults filled gaps")
        return merged

    def _apply_type_conversions(self, config: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """
        Apply robust type conversions to configuration values.
        
        Args:
            config: Configuration to process
            
        Returns:
            Configuration with proper type conversions
        """
        # Force convert numeric fields to integers
        numeric_fields = {
            'general': ['max_packet_size'],
            'advanced': ['memory_limit', 'thread_count', 'analysis_timeout', 
                        'latency_threshold', 'update_interval', 'packet_buffer_size']
        }
        
        for section, fields in numeric_fields.items():
            if section in config:
                for field in fields:
                    if field in config[section]:
                        try:
                            original_value = config[section][field]
                            config[section][field] = int(str(original_value))
                            print(f"Converted {section}.{field}: {original_value} -> {config[section][field]} (int)")
                        except (ValueError, TypeError) as e:
                            print(f"Warning: Failed to convert {section}.{field} to int: {e}")
                            # Apply sensible defaults based on field
                            fallback_values = {
                                'max_packet_size': 1500,
                                'thread_count': 4,
                                'memory_limit': 1024,
                                'analysis_timeout': 5,
                                'latency_threshold': 100,
                                'update_interval': 24,
                                'packet_buffer_size': 10000
                            }
                            config[section][field] = fallback_values.get(field, 0)
                            print(f"Applied fallback for {section}.{field}: {config[section][field]}")
        
        # Force convert boolean fields
        boolean_fields = {
            'general': ['enabled', 'low_latency_mode', 'industrial_mode', 'ssl_inspection', 
                       'archive_extraction', 'malware_detection', 'anomaly_detection'],
            'protocols': ['http_inspection', 'https_inspection', 'ftp_inspection', 
                         'smtp_inspection', 'dns_inspection', 'industrial_protocols', 
                         'p2p_detection', 'voip_inspection'],
            'detection': ['virus_signatures', 'trojan_detection', 'crypto_mining', 
                         'data_exfiltration', 'command_injection', 'sql_injection', 
                         'script_injection', 'suspicious_downloads', 'phishing_detection', 
                         'botnet_detection', 'steganography_detection', 'zero_day_heuristics'],
            'advanced': ['signature_updates', 'quarantine_enabled', 'bypass_trusted_networks', 
                        'industrial_optimization', 'scada_protocols', 'plc_protocols']
        }
        
        for section, fields in boolean_fields.items():
            if section in config:
                for field in fields:
                    if field in config[section]:
                        value = config[section][field]
                        original_value = value
                        
                        if isinstance(value, str):
                            config[section][field] = value.lower() in ['true', '1', 'yes', 'on', 'enabled']
                        elif isinstance(value, int):
                            config[section][field] = bool(value)
                        # else already boolean, leave as is
                        
                        if config[section][field] != original_value:
                            print(f"Converted {section}.{field}: {original_value} -> {config[section][field]} (bool)")
        
        return config

    def _normalize_list_fields(self, config: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """
        Normalize fields that should be lists (interfaces, trusted_networks).
        
        Args:
            config: Configuration to normalize
            
        Returns:
            Configuration with normalized list fields
        """
        # Handle interfaces - ensure it's always a list
        if 'interfaces' in config.get('general', {}):
            interfaces = config['general']['interfaces']
            if isinstance(interfaces, str):
                if ',' in interfaces:
                    config['general']['interfaces'] = [iface.strip() for iface in interfaces.split(',') if iface.strip()]
                else:
                    config['general']['interfaces'] = [interfaces.strip()] if interfaces.strip() else []
            elif not isinstance(interfaces, list):
                config['general']['interfaces'] = self._detect_network_interfaces()
            print(f"Normalized interfaces: {config['general']['interfaces']}")
        
        # Handle trusted networks - ensure it's always a list  
        if 'trusted_networks' in config.get('general', {}):
            networks = config['general']['trusted_networks']
            if isinstance(networks, str):
                if ',' in networks:
                    config['general']['trusted_networks'] = [net.strip() for net in networks.split(',') if net.strip()]
                else:
                    config['general']['trusted_networks'] = [networks.strip()] if networks.strip() else []
            elif not isinstance(networks, list):
                config['general']['trusted_networks'] = [
                    "192.168.1.0/24", "192.168.0.0/24", "10.0.0.0/8", "172.16.0.0/12"
                ]
            print(f"Normalized trusted networks: {config['general']['trusted_networks']}")
        
        return config

    def _create_supporting_files(self) -> None:
        """Create necessary log directories and signature files."""
        self._create_log_directories()
        self._create_signatures_directory()

    def _create_log_directories(self) -> None:
        """Create necessary log directories and files."""
        log_dir = Path("/var/log/deepinspector")
        log_dir.mkdir(parents=True, exist_ok=True)
        
        # Create log files if they don't exist
        log_files = [
            "engine.log", "threats.log", "alerts.log",
            "detections.log", "latency.log", "stats.log"
        ]
        
        for log_file in log_files:
            log_path = log_dir / log_file
            if not log_path.exists():
                log_path.touch()
                os.chmod(log_path, 0o644)
        
        os.chmod(log_dir, 0o755)
        print(f"Log directories created: {log_dir}")

    def _create_signatures_directory(self) -> None:
        """Create signatures directory with basic signature file."""
        sig_dir = Path("/usr/local/etc/deepinspector")
        sig_dir.mkdir(parents=True, exist_ok=True)
        
        # Create basic signatures file
        signatures_file = sig_dir / "signatures.json"
        if not signatures_file.exists():
            basic_signatures = {
                "version": "1.0",
                "last_updated": "2025-09-25",
                "signatures": {
                    "malware": [
                        {
                            "name": "EICAR Test String",
                            "pattern": "X5O!P%@AP\\[4\\\\PZX54\\(P\\^\\)7CC\\)7\\}\\$EICAR",
                            "severity": "critical"
                        }
                    ],
                    "sql_injection": [
                        {
                            "name": "Basic SQL Injection",
                            "pattern": "(union|select|insert|update|delete|drop).*?(from|into|table)",
                            "severity": "high"
                        }
                    ],
                    "command_injection": [
                        {
                            "name": "Command Execution",
                            "pattern": "(cmd\\.exe|powershell|bash|sh).*?[;&|]",
                            "severity": "high"
                        }
                    ]
                }
            }
            
            with open(signatures_file, 'w') as f:
                json.dump(basic_signatures, f, indent=2)
            
            os.chmod(signatures_file, 0o644)
            print(f"Basic signatures file created: {signatures_file}")

    def _save_config_to_file(self, config: Dict[str, Dict[str, Any]]) -> None:
        """
        Save configuration to JSON file with proper permissions.
        
        Args:
            config: Configuration to save
        """
        # Write configuration to JSON
        with self.target_path.open("w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)
        
        # Set proper permissions
        os.chmod(self.target_path, 0o644)
        print(f"Configuration saved to {self.target_path}")

    def _print_config_summary(self, config: Dict[str, Dict[str, Any]], config_source: str) -> None:
        """
        Print a comprehensive summary of the exported configuration.
        
        Args:
            config: Configuration to summarize
            config_source: Source of the configuration (XML, default, etc.)
        """
        print("\n" + "=" * 60)
        print("DEEPINSPECTOR CONFIGURATION SUMMARY")
        print("=" * 60)
        print(f"Configuration source: {config_source}")
        
        general = config.get("general", {})
        print(f"Status: {'ENABLED' if general.get('enabled', False) else 'DISABLED'}")
        print(f"Mode: {general.get('mode', 'passive')}")
        print(f"Performance Profile: {general.get('performance_profile', 'balanced')}")
        print(f"Industrial Mode: {'YES' if general.get('industrial_mode', False) else 'NO'}")
        print(f"Low Latency Mode: {'YES' if general.get('low_latency_mode', False) else 'NO'}")
        
        interfaces = general.get("interfaces", [])
        print(f"Monitoring Interfaces ({len(interfaces)}): {', '.join(interfaces) if interfaces else 'None'}")
        
        trusted = general.get("trusted_networks", [])
        if trusted:
            display_networks = trusted[:3]
            if len(trusted) > 3:
                display_networks.append(f"... and {len(trusted) - 3} more")
            print(f"Trusted Networks ({len(trusted)}): {', '.join(display_networks)}")
        
        # Count enabled features
        detection = config.get("detection", {})
        enabled_detections = sum(1 for v in detection.values() if v is True)
        print(f"Detection Engines: {enabled_detections}/{len(detection)} enabled")
        
        protocols = config.get("protocols", {})
        enabled_protocols = sum(1 for v in protocols.values() if v is True)
        print(f"Protocol Analyzers: {enabled_protocols}/{len(protocols)} enabled")
        
        advanced = config.get("advanced", {})
        print(f"Thread Count: {advanced.get('thread_count', 4)}")
        print(f"Memory Limit: {advanced.get('memory_limit', 1024)} MB")
        print(f"Signature Updates: {'Enabled' if advanced.get('signature_updates', False) else 'Disabled'}")
        
        print("=" * 60)
        
        if not general.get('enabled', False):
            print("WARNING: DeepInspector is DISABLED")
            print("Enable it in OPNsense: Services -> Deep Packet Inspector -> Settings")
        else:
            print("DeepInspector is configured and ready to start")

    def export(self) -> bool:
        """
        Main export method with integrated defaults and robust processing.
        
        Returns:
            True if successful, False otherwise
        """
        try:
            # Step 1: Ensure destination directory exists
            self.target_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Step 2: Get comprehensive defaults
            defaults = self._get_comprehensive_defaults()
            
            # Step 3: Try to load from XML
            xml_config = self._load_xml_config()
            
            # Step 4: Determine configuration source and merge appropriately
            if xml_config is not None:
                # Merge XML with defaults
                config = self._merge_with_defaults(xml_config, defaults)
                config_source = "OPNsense XML merged with defaults"
                
                # Warn if disabled
                if not config["general"].get("enabled", False):
                    print("WARNING: DeepInspector is disabled in OPNsense config")
                    print("Enable it in Services -> Deep Packet Inspector -> Settings")
            else:
                # Use pure defaults
                print("Using default configuration...")
                config = defaults
                config_source = "Default configuration"
            
            # Step 5: Apply type conversions and normalization
            config = self._apply_type_conversions(config)
            config = self._normalize_list_fields(config)
            
            # Step 6: Save to file
            self._save_config_to_file(config)
            
            # Step 7: Create supporting files
            self._create_supporting_files()
            
            # Step 8: Show summary
            self._print_config_summary(config, config_source)
            
            return True

        except Exception as exc:
            print(f"Error exporting configuration: {exc}")
            import traceback
            traceback.print_exc()
            return False


def main() -> None:
    """
    CLI entry point.
    Creates a ConfigExporter instance and runs the export.
    """
    print("DeepInspector Configuration Exporter v3.0")
    print("Enhanced with Integrated Defaults")
    print("=" * 50)
    
    # Check if running as root (recommended for interface detection)
    if os.geteuid() != 0:
        print("WARNING: Not running as root - interface detection may be limited")
        print("For best results, run as: sudo python3 export_config.py")
    
    exporter = ConfigExporter()
    success = exporter.export()
    
    if success:
        print("\nConfiguration export completed successfully!")
        print("You can now start the DeepInspector engine:")
        print("  sudo python3 /usr/local/opnsense/scripts/OPNsense/DeepInspector/deepinspector_engine.py")
        print("\nOr test the configuration first:")
        print("  sudo python3 /usr/local/opnsense/scripts/OPNsense/DeepInspector/deepinspector_engine.py --debug")
    else:
        print("\nConfiguration export failed!")
        raise SystemExit(1)


if __name__ == "__main__":
    main()