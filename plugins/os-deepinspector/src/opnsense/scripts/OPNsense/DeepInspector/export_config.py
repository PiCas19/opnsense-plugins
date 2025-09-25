#!/usr/local/bin/python3
"""
DeepInspector OPNsense Configuration Exporter - Enhanced Version
----------------------------------------------------------------
Reads the OPNsense system configuration (config.xml), parses
all DeepInspector plugin settings, and exports them to a JSON
file for the DPI engine.

If no configuration is found, creates a sensible default configuration.

Features:
- Full support for <general>, <protocols>, <detection>, <advanced>
- Boolean and integer normalization
- Handles missing fields gracefully
- Creates output directories automatically
- Auto-detects network interfaces
- Creates default configuration if OPNsense config missing
- Ready for cron or automation tasks

Author: Pierpaolo Casati
Version: 2.0
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
    to a JSON file for the DPI engine, with fallback default creation.
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

    def _convert_value(self, value: Optional[str]) -> Any:
        """
        Convert XML string values to Python types.

        - '0' or '1' → bool
        - Numeric strings → int
        - Otherwise → str

        Args:
            value: XML text value

        Returns:
            Converted Python object
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
            return physical_interfaces[:2] if physical_interfaces else ["em0", "em1"]
            
        except Exception as e:
            print(f"Could not detect network interfaces: {e}")
            return ["em0", "em1"]  # FreeBSD default fallback

    def _create_default_config(self) -> Dict[str, Dict[str, Any]]:
        """
        Create a sensible default configuration when OPNsense config is missing.
        
        Returns:
            Default configuration dictionary
        """
        interfaces = self._detect_network_interfaces()
        
        default_config = {
            "general": {
                "enabled": True,
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
                "thread_count": 2,
                "packet_buffer_size": 10000,
                "analysis_timeout": 5,
                "bypass_trusted_networks": True,
                "industrial_optimization": False,
                "scada_protocols": True,
                "plc_protocols": True,
                "latency_threshold": 100
            }
        }
        
        print("Created default DeepInspector configuration")
        print(f"Monitoring interfaces: {', '.join(interfaces)}")
        return default_config

    def _create_log_directories(self) -> None:
        """Create necessary log directories and files."""
        log_dir = Path("/var/log/deepinspector")
        log_dir.mkdir(parents=True, exist_ok=True)
        
        # Create log files if they don't exist
        log_files = [
            "engine.log",
            "threats.log", 
            "alerts.log",
            "detections.log",
            "latency.log",
            "stats.log"
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

    def export(self) -> bool:
        """
        Perform the export operation.
        First tries to read from OPNsense config, falls back to default config.

        Returns:
            True if successful, False otherwise
        """
        config = None
        config_source = "unknown"
        
        try:
            # Ensure destination directory exists
            self.target_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Try to read from OPNsense configuration first
            if self.source_path.exists():
                try:
                    tree = ET.parse(self.source_path)
                    root = tree.getroot()
                    
                    # Locate the DeepInspector node
                    dpi_node = root.find(".//OPNsense/DeepInspector")
                    if dpi_node is not None:
                        # Build configuration dictionary from XML
                        config = {
                            "general": self._extract_section(dpi_node, "general"),
                            "protocols": self._extract_section(dpi_node, "protocols"),
                            "detection": self._extract_section(dpi_node, "detection"),
                            "advanced": self._extract_section(dpi_node, "advanced"),
                        }
                        
                        # Ensure enabled is set to True if found in config
                        if not config["general"].get("enabled", False):
                            print("WARNING: DeepInspector is disabled in OPNsense config")
                            print("Enable it in Services -> Deep Packet Inspector -> Settings")
                            # Still export the config but warn user
                        
                        config_source = "OPNsense XML"
                        print(f"Found DeepInspector configuration in {self.source_path}")
                    else:
                        print("DeepInspector configuration not found in OPNsense config.xml")
                        config = None
                        
                except Exception as e:
                    print(f"Error parsing OPNsense config: {e}")
                    config = None
            else:
                print(f"OPNsense config file not found: {self.source_path}")
            
            # Fall back to default configuration if needed
            if config is None:
                print("Creating default configuration...")
                config = self._create_default_config()
                config_source = "default"
            
            # Write configuration to JSON
            with self.target_path.open("w", encoding="utf-8") as f:
                json.dump(config, f, indent=2)
            
            # Set proper permissions
            os.chmod(self.target_path, 0o644)
            
            # Create supporting directories and files
            self._create_log_directories()
            self._create_signatures_directory()
            
            print(f"DeepInspector configuration exported to {self.target_path}")
            print(f"Configuration source: {config_source}")
            
            # Show configuration summary
            self._print_config_summary(config)
            
            return True

        except Exception as exc:
            print(f"Error exporting configuration: {exc}")
            return False

    def _print_config_summary(self, config: Dict[str, Dict[str, Any]]) -> None:
        """Print a summary of the exported configuration."""
        print("\n" + "=" * 50)
        print("DEEPINSPECTOR CONFIGURATION SUMMARY")
        print("=" * 50)
        
        general = config.get("general", {})
        print(f"Status: {'ENABLED' if general.get('enabled', False) else 'DISABLED'}")
        print(f"Mode: {general.get('mode', 'passive')}")
        print(f"Performance Profile: {general.get('performance_profile', 'balanced')}")
        print(f"Industrial Mode: {'YES' if general.get('industrial_mode', False) else 'NO'}")
        
        interfaces = general.get("interfaces", [])
        if isinstance(interfaces, str):
            interfaces = [iface.strip() for iface in interfaces.split(',')]
        print(f"Monitoring Interfaces: {', '.join(interfaces) if interfaces else 'None'}")
        
        trusted = general.get("trusted_networks", [])
        if isinstance(trusted, str):
            trusted = [net.strip() for net in trusted.split(',')]
        if trusted:
            print(f"Trusted Networks: {', '.join(trusted[:3])}{'...' if len(trusted) > 3 else ''}")
        
        # Count enabled detections
        detection = config.get("detection", {})
        enabled_detections = sum(1 for v in detection.values() if v is True)
        print(f"Enabled Detections: {enabled_detections}/{len(detection)}")
        
        # Count enabled protocols  
        protocols = config.get("protocols", {})
        enabled_protocols = sum(1 for v in protocols.values() if v is True)
        print(f"Enabled Protocols: {enabled_protocols}/{len(protocols)}")
        
        advanced = config.get("advanced", {})
        print(f"Thread Count: {advanced.get('thread_count', 2)}")
        print(f"Signature Updates: {'YES' if advanced.get('signature_updates', False) else 'NO'}")
        
        print("=" * 50)
        
        if not general.get('enabled', False):
            print("WARNING: DeepInspector is DISABLED")
            print("   Enable it in OPNsense: Services -> Deep Packet Inspector -> Settings")
        else:
            print("DeepInspector is ready to start")


def main() -> None:
    """
    CLI entry point.
    Creates a ConfigExporter instance and runs the export.
    """
    print("DeepInspector Configuration Exporter v2.0")
    print("==========================================")
    
    # Check if running as root (recommended for interface detection)
    if os.geteuid() != 0:
        print("WARNING: Not running as root - interface detection may be limited")
        print("For best results, run as: sudo python3 export_config.py")
    
    exporter = ConfigExporter()
    success = exporter.export()
    
    if success:
        print("\nConfiguration export completed successfully!")
        print("You can now start the DeepInspector engine:")
        print("sudo python3 /usr/local/opnsense/scripts/OPNsense/DeepInspector/deepinspector_engine.py")
    else:
        print("\nConfiguration export failed!")
        raise SystemExit(1)


if __name__ == "__main__":
    main()