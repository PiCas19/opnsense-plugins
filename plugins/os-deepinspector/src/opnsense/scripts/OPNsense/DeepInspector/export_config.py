#!/usr/local/bin/python3
"""
DeepInspector OPNsense Configuration Exporter - Object-Oriented Version
-----------------------------------------------------------------------
Reads the OPNsense system configuration (config.xml), parses
all DeepInspector plugin settings, and exports them to a JSON
file for the DPI engine using a robust object-oriented architecture.
Author: Pierpaolo Casati
Version: 1.0.0
"""
import os
import json
import xml.etree.ElementTree as ET
from typing import Dict, Any, Optional
from abc import ABC, abstractmethod


class ConfigurationError(Exception):
    """Custom exception for configuration-related errors"""
    pass


class ConfigurationParser(ABC):
    """Abstract base class for configuration parsers"""
    
    @abstractmethod
    def parse(self, node: ET.Element) -> Dict[str, Any]:
        """Parse configuration node and return dictionary"""
        pass


class GeneralConfigParser(ConfigurationParser):
    """Parser for general configuration settings"""
    
    def parse(self, node: ET.Element) -> Dict[str, Any]:
        """Parse general settings node"""
        config = {}
        if node is not None:
            for child in node:
                value = child.text or ""
                # Convert boolean strings
                if value in ['0', '1']:
                    value = value == '1'
                config[child.tag] = value
        return config


class ProtocolConfigParser(ConfigurationParser):
    """Parser for protocol configuration settings"""
    
    def parse(self, node: ET.Element) -> Dict[str, Any]:
        """Parse protocol settings node"""
        config = {}
        if node is not None:
            for child in node:
                value = child.text or ""
                if value in ['0', '1']:
                    value = value == '1'
                config[child.tag] = value
        return config


class DetectionConfigParser(ConfigurationParser):
    """Parser for detection configuration settings"""
    
    def parse(self, node: ET.Element) -> Dict[str, Any]:
        """Parse detection settings node"""
        config = {}
        if node is not None:
            for child in node:
                value = child.text or ""
                if value in ['0', '1']:
                    value = value == '1'
                config[child.tag] = value
        return config


class AdvancedConfigParser(ConfigurationParser):
    """Parser for advanced configuration settings"""
    
    def parse(self, node: ET.Element) -> Dict[str, Any]:
        """Parse advanced settings node"""
        config = {}
        if node is not None:
            for child in node:
                value = child.text or ""
                if value in ['0', '1']:
                    value = value == '1'
                elif value.isdigit():
                    value = int(value)
                config[child.tag] = value
        return config


class ConfigurationExporter:
    """Main configuration exporter class"""
    
    def __init__(self, config_file: str = "/usr/local/etc/deepinspector/config.json",
                 opnsense_config: str = "/conf/config.xml"):
        """
        Initialize the configuration exporter
        
        Args:
            config_file: Path to output configuration file
            opnsense_config: Path to OPNsense configuration file
        """
        self.config_file = config_file
        self.opnsense_config = opnsense_config
        
        # Initialize parsers
        self.parsers = {
            'general': GeneralConfigParser(),
            'protocols': ProtocolConfigParser(),
            'detection': DetectionConfigParser(),
            'advanced': AdvancedConfigParser()
        }
    
    def _validate_files(self) -> None:
        """Validate that required files exist"""
        if not os.path.exists(self.opnsense_config):
            raise ConfigurationError(f"OPNsense config file not found: {self.opnsense_config}")
    
    def _load_xml_config(self) -> ET.Element:
        """Load and parse the OPNsense XML configuration"""
        try:
            tree = ET.parse(self.opnsense_config)
            root = tree.getroot()
            
            # Find DeepInspector configuration
            dpi_node = root.find(".//OPNsense/DeepInspector")
            if dpi_node is None:
                raise ConfigurationError("DeepInspector configuration not found in config.xml")
            
            return dpi_node
        except ET.ParseError as e:
            raise ConfigurationError(f"Error parsing XML configuration: {e}")
    
    def _parse_configuration(self, dpi_node: ET.Element) -> Dict[str, Any]:
        """Parse the configuration using registered parsers"""
        config = {}
        
        for section_name, parser in self.parsers.items():
            section_node = dpi_node.find(section_name)
            config[section_name] = parser.parse(section_node)
        
        return config
    
    def _ensure_output_directory(self) -> None:
        """Ensure the output directory exists"""
        output_dir = os.path.dirname(self.config_file)
        if output_dir:  # Only create if directory path is not empty
            os.makedirs(output_dir, exist_ok=True)
    
    def _write_configuration(self, config: Dict[str, Any]) -> None:
        """Write configuration to JSON file"""
        try:
            self._ensure_output_directory()
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=2)
        except IOError as e:
            raise ConfigurationError(f"Error writing configuration file: {e}")
    
    def export_config(self) -> bool:
        """
        Export OPNsense DPI configuration to JSON format
        
        Returns:
            bool: True if export successful, False otherwise
        """
        try:
            # Validate prerequisites
            self._validate_files()
            
            # Load and parse XML configuration
            dpi_node = self._load_xml_config()
            
            # Parse configuration sections
            config = self._parse_configuration(dpi_node)
            
            # Write configuration to file
            self._write_configuration(config)
            
            print(f"Configuration exported successfully to {self.config_file}")
            return True
            
        except ConfigurationError as e:
            print(f"Configuration error: {e}")
            return False
        except Exception as e:
            print(f"Unexpected error exporting configuration: {e}")
            return False
    
    def get_configuration_summary(self) -> Optional[Dict[str, Any]]:
        """
        Get a summary of the current configuration without exporting
        
        Returns:
            Dict with configuration summary or None if error
        """
        try:
            self._validate_files()
            dpi_node = self._load_xml_config()
            config = self._parse_configuration(dpi_node)
            
            # Create summary
            summary = {
                'sections': list(config.keys()),
                'general_enabled': config.get('general', {}).get('enabled', False),
                'protocols_count': len([k for k, v in config.get('protocols', {}).items() if v is True]),
                'detection_count': len([k for k, v in config.get('detection', {}).items() if v is True]),
                'advanced_settings': len(config.get('advanced', {}))
            }
            
            return summary
            
        except (ConfigurationError, Exception) as e:
            print(f"Error getting configuration summary: {e}")
            return None
    
    def add_parser(self, section_name: str, parser: ConfigurationParser) -> None:
        """
        Add a custom parser for a new configuration section
        
        Args:
            section_name: Name of the configuration section
            parser: Parser instance implementing ConfigurationParser
        """
        self.parsers[section_name] = parser
    
    def remove_parser(self, section_name: str) -> bool:
        """
        Remove a parser for a configuration section
        
        Args:
            section_name: Name of the section to remove
            
        Returns:
            bool: True if removed, False if section didn't exist
        """
        return self.parsers.pop(section_name, None) is not None


def main():
    """Main function to run the configuration export"""
    exporter = ConfigurationExporter()
    
    # Show configuration summary before export
    summary = exporter.get_configuration_summary()
    if summary:
        print("Configuration Summary:")
        print(f"  - Sections: {', '.join(summary['sections'])}")
        print(f"  - DPI Enabled: {summary['general_enabled']}")
        print(f"  - Active Protocols: {summary['protocols_count']}")
        print(f"  - Active Detection Engines: {summary['detection_count']}")
        print(f"  - Advanced Settings: {summary['advanced_settings']}")
        print()
    
    # Export configuration
    success = exporter.export_config()
    exit(0 if success else 1)


if __name__ == "__main__":
    main()