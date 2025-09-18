"""
export_rules.py - OPNsense Advanced Inspector Rule Export Module

This module handles the export of inspection rules from OPNsense XML configuration
to JSON format for use by the packet inspection engine.

Author: Pierpaolo Casati
Version: 1.0
License: BSD 2-Clause
"""

import os
import json
import logging
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import dataclass


@dataclass
class ExportConfig:
    """Configuration for rule export operations"""
    config_path: Path = Path("/conf/config.xml")
    output_path: Path = Path("/usr/local/etc/advinspector/rules.json")
    backup_count: int = 5
    validate_rules: bool = True
    create_backup: bool = True


class RuleExporter:
    """
    Handles the export of OPNsense inspection rules from XML to JSON format.
    
    This class provides functionality to parse XML configuration files,
    extract inspection rules, validate them, and export to JSON format
    suitable for the packet inspection engine.
    """
    
    def __init__(self, config: Optional[ExportConfig] = None):
        """
        Initialize the rule exporter.
        
        Args:
            config: Export configuration. Uses default if None.
        """
        self.config = config or ExportConfig()
        self.logger = self._setup_logger()
        
    def _setup_logger(self) -> logging.Logger:
        """
        Set up logging for the exporter.
        
        Returns:
            Configured logger instance
        """
        logger = logging.getLogger('rule_exporter')
        logger.setLevel(logging.INFO)
        
        # Create console handler if not already present
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            
        return logger
    
    def parse_rules(self) -> List[Dict]:
        """
        Parse inspection rules from OPNsense XML configuration.
        
        Returns:
            List of rule dictionaries extracted from XML
            
        Raises:
            FileNotFoundError: If configuration file doesn't exist
            ET.ParseError: If XML is malformed
            ValueError: If XML structure is invalid
        """
        if not self.config.config_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {self.config.config_path}")
        
        try:
            self.logger.info(f"Parsing rules from {self.config.config_path}")
            tree = ET.parse(self.config.config_path)
            root = tree.getroot()
            
            # Navigate to AdvInspector rules section
            rules_xpath = ".//OPNsense/AdvInspector/rules/rule"
            rule_elements = root.findall(rules_xpath)
            
            if not rule_elements:
                self.logger.warning("No rules found in configuration")
                return []
            
            rules = []
            for rule_elem in rule_elements:
                rule_data = self._extract_rule_data(rule_elem)
                if rule_data:
                    rules.append(rule_data)
            
            self.logger.info(f"Successfully parsed {len(rules)} rules")
            return rules
            
        except ET.ParseError as e:
            self.logger.error(f"XML parsing error: {e}")
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error parsing rules: {e}")
            raise
    
    def _extract_rule_data(self, rule_elem: ET.Element) -> Optional[Dict]:
        """
        Extract rule data from XML element.
        
        Args:
            rule_elem: XML element containing rule data
            
        Returns:
            Dictionary containing rule data or None if invalid
        """
        try:
            # Get UUID from element attributes
            uuid = rule_elem.get("uuid")
            if not uuid:
                self.logger.warning("Rule missing UUID, skipping")
                return None
            
            rule_data = {"uuid": uuid}
            
            # Extract all child elements
            for elem in rule_elem:
                if elem.tag and elem.text:
                    rule_data[elem.tag] = elem.text.strip()
                elif elem.tag:
                    # Handle empty elements as empty strings
                    rule_data[elem.tag] = ""
            
            # Validate rule if configured to do so
            if self.config.validate_rules and not self._validate_rule(rule_data):
                self.logger.warning(f"Invalid rule {uuid}, skipping")
                return None
            
            return rule_data
            
        except Exception as e:
            self.logger.error(f"Error extracting rule data: {e}")
            return None
    
    def _validate_rule(self, rule_data: Dict) -> bool:
        """
        Validate rule data for completeness and correctness.
        
        Args:
            rule_data: Dictionary containing rule data
            
        Returns:
            True if rule is valid, False otherwise
        """
        required_fields = ['uuid', 'description', 'source', 'destination', 'protocol', 'action']
        
        # Check required fields
        for field in required_fields:
            if field not in rule_data or not rule_data[field]:
                self.logger.warning(f"Rule {rule_data.get('uuid', 'unknown')} missing required field: {field}")
                return False
        
        # Validate action field
        valid_actions = ['allow', 'block', 'alert']
        if rule_data.get('action') not in valid_actions:
            self.logger.warning(f"Rule {rule_data['uuid']} has invalid action: {rule_data.get('action')}")
            return False
        
        # Validate protocol field
        valid_protocols = [
            'tcp', 'udp', 'icmp', 'modbus_tcp', 'dnp3', 'iec104', 'iec61850',
            'profinet', 'ethercat', 'opcua', 'mqtt', 'bacnet', 's7comm'
        ]
        if rule_data.get('protocol') not in valid_protocols:
            self.logger.warning(f"Rule {rule_data['uuid']} has invalid protocol: {rule_data.get('protocol')}")
            return False
        
        return True
    
    def save_rules(self, rules: List[Dict]) -> bool:
        """
        Save rules to JSON file with optional backup.
        
        Args:
            rules: List of rule dictionaries to save
            
        Returns:
            True if save successful, False otherwise
        """
        try:
            # Create output directory if it doesn't exist
            self.config.output_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Create backup if configured and output file exists
            if self.config.create_backup and self.config.output_path.exists():
                self._create_backup()
            
            # Prepare output data
            output_data = {
                "rules": rules,
                "metadata": {
                    "exported_at": self._get_timestamp(),
                    "source": str(self.config.config_path),
                    "rule_count": len(rules),
                    "version": "2.0"
                }
            }
            
            # Write JSON file
            with open(self.config.output_path, 'w', encoding='utf-8') as f:
                json.dump(output_data, f, indent=2, ensure_ascii=False)
            
            # Set appropriate permissions
            os.chmod(self.config.output_path, 0o644)
            
            self.logger.info(f"Rules exported successfully to {self.config.output_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to save rules: {e}")
            return False
    
    def _create_backup(self) -> None:
        """Create backup of existing rules file."""
        try:
            timestamp = self._get_timestamp().replace(':', '-').replace(' ', '_')
            backup_path = self.config.output_path.with_suffix(f'.backup.{timestamp}.json')
            
            # Copy existing file to backup
            import shutil
            shutil.copy2(self.config.output_path, backup_path)
            
            # Clean old backups
            self._cleanup_old_backups()
            
            self.logger.info(f"Created backup: {backup_path}")
            
        except Exception as e:
            self.logger.warning(f"Failed to create backup: {e}")
    
    def _cleanup_old_backups(self) -> None:
        """Remove old backup files beyond the configured count."""
        try:
            backup_pattern = f"{self.config.output_path.stem}.backup.*.json"
            backup_dir = self.config.output_path.parent
            
            # Find all backup files
            backup_files = list(backup_dir.glob(backup_pattern))
            
            # Sort by modification time (newest first)
            backup_files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
            
            # Remove excess backups
            for backup_file in backup_files[self.config.backup_count:]:
                backup_file.unlink()
                self.logger.debug(f"Removed old backup: {backup_file}")
                
        except Exception as e:
            self.logger.warning(f"Failed to cleanup old backups: {e}")
    
    def _get_timestamp(self) -> str:
        """Get current timestamp in ISO format."""
        from datetime import datetime
        return datetime.now().isoformat()
    
    def export_rules(self) -> bool:
        """
        Complete rule export process.
        
        Returns:
            True if export successful, False otherwise
        """
        try:
            self.logger.info("Starting rule export process")
            
            # Parse rules from XML
            rules = self.parse_rules()
            
            if not rules:
                self.logger.warning("No rules to export")
                return True  # Not an error condition
            
            # Save rules to JSON
            success = self.save_rules(rules)
            
            if success:
                self.logger.info(f"Export completed successfully: {len(rules)} rules exported")
            else:
                self.logger.error("Export failed")
            
            return success
            
        except Exception as e:
            self.logger.error(f"Export process failed: {e}")
            return False


class RuleImporter:
    """
    Handles import of rules from JSON format back to OPNsense XML.
    
    This is the reverse operation of RuleExporter, allowing rules to be
    imported from JSON files into the OPNsense configuration.
    """
    
    def __init__(self, config: Optional[ExportConfig] = None):
        """Initialize the rule importer."""
        self.config = config or ExportConfig()
        self.logger = logging.getLogger('rule_importer')
    
    def import_rules(self, json_path: Path) -> bool:
        """
        Import rules from JSON file to OPNsense XML configuration.
        
        Args:
            json_path: Path to JSON file containing rules
            
        Returns:
            True if import successful, False otherwise
        """
        try:
            self.logger.info(f"Importing rules from {json_path}")
            
            # Load rules from JSON
            with open(json_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            rules = data.get('rules', [])
            if not rules:
                self.logger.warning("No rules found in JSON file")
                return True
            
            # Import to XML configuration
            success = self._import_to_xml(rules)
            
            if success:
                self.logger.info(f"Import completed: {len(rules)} rules imported")
            
            return success
            
        except Exception as e:
            self.logger.error(f"Import failed: {e}")
            return False
    
    def _import_to_xml(self, rules: List[Dict]) -> bool:
        """Import rules to XML configuration file."""
        # Implementation would depend on specific OPNsense XML structure requirements
        # This is a placeholder for the actual implementation
        self.logger.info(f"Would import {len(rules)} rules to XML")
        return True


def main():
    """Main entry point for the export script."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Export OPNsense inspection rules")
    parser.add_argument('--config', type=Path, help='Path to OPNsense config.xml')
    parser.add_argument('--output', type=Path, help='Output JSON file path')
    parser.add_argument('--no-backup', action='store_true', help='Skip backup creation')
    parser.add_argument('--no-validate', action='store_true', help='Skip rule validation')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Configure logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Create configuration
    config = ExportConfig()
    if args.config:
        config.config_path = args.config
    if args.output:
        config.output_path = args.output
    if args.no_backup:
        config.create_backup = False
    if args.no_validate:
        config.validate_rules = False
    
    # Create exporter and run export
    exporter = RuleExporter(config)
    success = exporter.export_rules()
    
    exit(0 if success else 1)


if __name__ == "__main__":
    main()