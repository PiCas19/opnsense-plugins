#!/usr/local/bin/python3

"""
Rule Parser Module for Advanced Network Inspector

Handles parsing and conversion of XML-based security rules to JSON format
for use by the network inspection engine. Provides validation, error handling,
and extensible rule processing capabilities.

Author: System Administrator
Version: 1.0
"""

import json
import xml.etree.ElementTree as ET
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime


class RuleParseError(Exception):
    """Custom exception for rule parsing errors."""
    pass


class RuleValidationError(Exception):
    """Custom exception for rule validation errors."""
    pass


@dataclass
class SecurityRule:
    """
    Represents a single security rule with validation and serialization capabilities.
    """
    uuid: str
    name: str = ""
    description: str = ""
    source: str = ""
    destination: str = ""
    port: str = ""
    protocol: str = ""
    action: str = "alert"
    enabled: bool = True
    priority: int = 1000
    category: str = "general"
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self) -> None:
        """Validate rule data after initialization."""
        self._validate()
    
    def _validate(self) -> None:
        """
        Validate rule data for consistency and completeness.
        
        Raises:
            RuleValidationError: If rule data is invalid
        """
        if not self.uuid:
            raise RuleValidationError("Rule UUID is required")
        
        if not self.uuid.strip():
            raise RuleValidationError("Rule UUID cannot be empty")
        
        # Validate action
        valid_actions = ["allow", "block", "alert", "drop", "reject"]
        if self.action.lower() not in valid_actions:
            raise RuleValidationError(f"Invalid action '{self.action}'. Must be one of: {valid_actions}")
        
        # Validate protocol if specified
        if self.protocol:
            valid_protocols = ["tcp", "udp", "icmp", "any", "*"]
            if self.protocol.lower() not in valid_protocols:
                # Allow numeric protocol numbers
                try:
                    proto_num = int(self.protocol)
                    if proto_num < 0 or proto_num > 255:
                        raise RuleValidationError(f"Protocol number must be 0-255, got {proto_num}")
                except ValueError:
                    raise RuleValidationError(f"Invalid protocol '{self.protocol}'")
        
        # Validate port if specified
        if self.port and self.port not in ["any", "*", ""]:
            self._validate_port_specification(self.port)
    
    def _validate_port_specification(self, port_spec: str) -> None:
        """
        Validate port specification (single port, range, or list).
        
        Args:
            port_spec: Port specification string
            
        Raises:
            RuleValidationError: If port specification is invalid
        """
        # Handle port ranges (e.g., "80-8080")
        if "-" in port_spec:
            try:
                start, end = port_spec.split("-", 1)
                start_port = int(start.strip())
                end_port = int(end.strip())
                if start_port < 1 or start_port > 65535 or end_port < 1 or end_port > 65535:
                    raise RuleValidationError(f"Port numbers must be 1-65535")
                if start_port > end_port:
                    raise RuleValidationError(f"Invalid port range: {start_port}-{end_port}")
            except ValueError:
                raise RuleValidationError(f"Invalid port range format: {port_spec}")
        
        # Handle port lists (e.g., "80,443,8080")
        elif "," in port_spec:
            for port in port_spec.split(","):
                port = port.strip()
                try:
                    port_num = int(port)
                    if port_num < 1 or port_num > 65535:
                        raise RuleValidationError(f"Port number must be 1-65535, got {port_num}")
                except ValueError:
                    raise RuleValidationError(f"Invalid port number: {port}")
        
        # Handle single port
        else:
            try:
                port_num = int(port_spec)
                if port_num < 1 or port_num > 65535:
                    raise RuleValidationError(f"Port number must be 1-65535, got {port_num}")
            except ValueError:
                raise RuleValidationError(f"Invalid port number: {port_spec}")
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert rule to dictionary format for JSON serialization.
        
        Returns:
            Dictionary representation of the rule
        """
        return {
            "uuid": self.uuid,
            "name": self.name,
            "description": self.description,
            "source": self.source,
            "destination": self.destination,
            "port": self.port,
            "protocol": self.protocol.lower() if self.protocol else "",
            "action": self.action.lower(),
            "enabled": self.enabled,
            "priority": self.priority,
            "category": self.category,
            "metadata": self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SecurityRule':
        """
        Create SecurityRule instance from dictionary data.
        
        Args:
            data: Dictionary containing rule data
            
        Returns:
            SecurityRule instance
        """
        # Extract known fields with defaults
        rule_data = {
            "uuid": data.get("uuid", ""),
            "name": data.get("name", ""),
            "description": data.get("description", ""),
            "source": data.get("source", ""),
            "destination": data.get("destination", ""),
            "port": data.get("port", ""),
            "protocol": data.get("protocol", ""),
            "action": data.get("action", "alert"),
            "enabled": data.get("enabled", True),
            "priority": int(data.get("priority", 1000)),
            "category": data.get("category", "general")
        }
        
        # Store additional fields in metadata
        metadata = {}
        for key, value in data.items():
            if key not in rule_data:
                metadata[key] = value
        
        rule_data["metadata"] = metadata
        
        return cls(**rule_data)


class RuleParser(ABC):
    """Abstract base class for rule parsers."""
    
    @abstractmethod
    def parse_rules(self, source_path: Path) -> List[SecurityRule]:
        """
        Parse rules from source file.
        
        Args:
            source_path: Path to source file
            
        Returns:
            List of parsed SecurityRule objects
        """
        pass


class XMLRuleParser(RuleParser):
    """
    XML-based rule parser for pfSense-style configuration files.
    """
    
    def __init__(self, rule_xpath: str = ".//AdvInspector/rules/rule"):
        """
        Initialize XML rule parser.
        
        Args:
            rule_xpath: XPath expression to locate rule elements
        """
        self.rule_xpath = rule_xpath
    
    def parse_rules(self, source_path: Path) -> List[SecurityRule]:
        """
        Parse security rules from XML configuration file.
        
        Args:
            source_path: Path to XML configuration file
            
        Returns:
            List of parsed SecurityRule objects
            
        Raises:
            RuleParseError: If XML parsing fails
            RuleValidationError: If rule validation fails
        """
        if not source_path.exists():
            raise RuleParseError(f"Configuration file not found: {source_path}")
        
        try:
            tree = ET.parse(source_path)
            root = tree.getroot()
        except ET.ParseError as e:
            raise RuleParseError(f"XML parsing failed: {e}")
        except Exception as e:
            raise RuleParseError(f"Failed to read configuration file: {e}")
        
        rules = []
        rule_elements = root.findall(self.rule_xpath)
        
        if not rule_elements:
            logging.warning(f"No rules found using XPath: {self.rule_xpath}")
            return rules
        
        for rule_element in rule_elements:
            try:
                rule = self._parse_rule_element(rule_element)
                rules.append(rule)
            except (RuleValidationError, RuleParseError) as e:
                # Log error and continue with next rule
                rule_id = rule_element.get("uuid", "unknown")
                logging.error(f"Failed to parse rule {rule_id}: {e}")
                continue
        
        return rules
    
    def _parse_rule_element(self, rule_element: ET.Element) -> SecurityRule:
        """
        Parse a single rule element from XML.
        
        Args:
            rule_element: XML element containing rule data
            
        Returns:
            Parsed SecurityRule object
            
        Raises:
            RuleValidationError: If rule data is invalid
        """
        # Extract UUID from attribute
        uuid = rule_element.get("uuid")
        if not uuid:
            raise RuleValidationError("Rule missing required UUID attribute")
        
        # Extract all child elements as rule data
        rule_data = {"uuid": uuid}
        
        for child in rule_element:
            # Handle boolean values
            if child.tag in ["enabled"]:
                rule_data[child.tag] = child.text and child.text.lower() in ["true", "1", "yes", "on"]
            
            # Handle integer values
            elif child.tag in ["priority"]:
                try:
                    rule_data[child.tag] = int(child.text or "1000")
                except ValueError:
                    rule_data[child.tag] = 1000
            
            # Handle text values
            else:
                rule_data[child.tag] = (child.text or "").strip()
        
        return SecurityRule.from_dict(rule_data)


class RuleExporter(ABC):
    """Abstract base class for rule exporters."""
    
    @abstractmethod
    def export_rules(self, rules: List[SecurityRule], output_path: Path) -> bool:
        """
        Export rules to output file.
        
        Args:
            rules: List of SecurityRule objects to export
            output_path: Path to output file
            
        Returns:
            True if export was successful, False otherwise
        """
        pass


class JSONRuleExporter(RuleExporter):
    """
    JSON-based rule exporter for network inspection engine.
    """
    
    def __init__(self, indent: int = 2, sort_keys: bool = True):
        """
        Initialize JSON rule exporter.
        
        Args:
            indent: JSON indentation level
            sort_keys: Whether to sort JSON keys
        """
        self.indent = indent
        self.sort_keys = sort_keys
    
    def export_rules(self, rules: List[SecurityRule], output_path: Path) -> bool:
        """
        Export rules to JSON format file.
        
        Args:
            rules: List of SecurityRule objects to export
            output_path: Path to output JSON file
            
        Returns:
            True if export was successful, False otherwise
        """
        try:
            # Ensure output directory exists
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Prepare export data
            export_data = {
                "metadata": {
                    "exported_at": datetime.utcnow().isoformat() + "Z",
                    "rule_count": len(rules),
                    "format_version": "2.0"
                },
                "rules": [rule.to_dict() for rule in rules]
            }
            
            # Write JSON file
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(export_data, f, indent=self.indent, 
                         sort_keys=self.sort_keys, ensure_ascii=False)
            
            return True
            
        except Exception as e:
            logging.error(f"Failed to export rules to {output_path}: {e}")
            return False


class RuleManager:
    """
    Main rule management system orchestrating parsing and exporting operations.
    """
    
    def __init__(self, 
                 parser: RuleParser,
                 exporter: RuleExporter,
                 config_path: str = "/conf/config.xml",
                 output_path: str = "/usr/local/etc/advinspector/rules.json"):
        """
        Initialize rule manager.
        
        Args:
            parser: Rule parser implementation
            exporter: Rule exporter implementation
            config_path: Path to source configuration file
            output_path: Path to output rules file
        """
        self.parser = parser
        self.exporter = exporter
        self.config_path = Path(config_path)
        self.output_path = Path(output_path)
        self.rules: List[SecurityRule] = []
    
    def load_rules(self) -> int:
        """
        Load and parse rules from configuration file.
        
        Returns:
            Number of rules successfully loaded
            
        Raises:
            RuleParseError: If loading fails critically
        """
        try:
            self.rules = self.parser.parse_rules(self.config_path)
            logging.info(f"Loaded {len(self.rules)} rules from {self.config_path}")
            return len(self.rules)
            
        except Exception as e:
            logging.error(f"Failed to load rules: {e}")
            raise RuleParseError(f"Rule loading failed: {e}")
    
    def export_rules(self) -> bool:
        """
        Export loaded rules to output format.
        
        Returns:
            True if export was successful, False otherwise
        """
        if not self.rules:
            logging.warning("No rules loaded to export")
            return False
        
        success = self.exporter.export_rules(self.rules, self.output_path)
        if success:
            logging.info(f"Exported {len(self.rules)} rules to {self.output_path}")
        
        return success
    
    def validate_rules(self) -> Dict[str, Any]:
        """
        Validate all loaded rules and return validation report.
        
        Returns:
            Validation report with statistics and errors
        """
        report = {
            "total_rules": len(self.rules),
            "valid_rules": 0,
            "invalid_rules": 0,
            "validation_errors": [],
            "rule_categories": {},
            "rule_actions": {}
        }
        
        for rule in self.rules:
            try:
                rule._validate()
                report["valid_rules"] += 1
                
                # Collect statistics
                category = rule.category or "unknown"
                action = rule.action or "unknown"
                
                report["rule_categories"][category] = report["rule_categories"].get(category, 0) + 1
                report["rule_actions"][action] = report["rule_actions"].get(action, 0) + 1
                
            except RuleValidationError as e:
                report["invalid_rules"] += 1
                report["validation_errors"].append({
                    "rule_uuid": rule.uuid,
                    "rule_name": rule.name,
                    "error": str(e)
                })
        
        return report
    
    def get_rules(self) -> List[SecurityRule]:
        """Get list of loaded rules."""
        return self.rules.copy()
    
    def get_rule_by_uuid(self, uuid: str) -> Optional[SecurityRule]:
        """
        Get rule by UUID.
        
        Args:
            uuid: Rule UUID to search for
            
        Returns:
            SecurityRule if found, None otherwise
        """
        for rule in self.rules:
            if rule.uuid == uuid:
                return rule
        return None


def create_rule_manager(config_path: str = "/conf/config.xml",
                       output_path: str = "/usr/local/etc/advinspector/rules.json") -> RuleManager:
    """
    Factory function to create a standard rule manager with XML->JSON conversion.
    
    Args:
        config_path: Path to XML configuration file
        output_path: Path to JSON output file
        
    Returns:
        Configured RuleManager instance
    """
    parser = XMLRuleParser()
    exporter = JSONRuleExporter()
    return RuleManager(parser, exporter, config_path, output_path)


# Backward compatibility functions
def parse_rules() -> List[Dict[str, Any]]:
    """
    Parse rules using legacy interface for backward compatibility.
    
    Returns:
        List of rule dictionaries
    """
    manager = create_rule_manager()
    try:
        manager.load_rules()
        return [rule.to_dict() for rule in manager.get_rules()]
    except Exception as e:
        logging.error(f"Failed to parse rules: {e}")
        return []


def save_json(data: List[Dict[str, Any]], 
              output_path: str = "/usr/local/etc/advinspector/rules.json") -> None:
    """
    Save rules data as JSON for backward compatibility.
    
    Args:
        data: List of rule dictionaries
        output_path: Path to output file
    """
    try:
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump({"rules": data}, f, indent=2)
    except Exception as e:
        logging.error(f"Failed to save rules JSON: {e}")


if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(level=logging.INFO, 
                       format='%(asctime)s - %(levelname)s - %(message)s')
    
    try:
        # Create and use rule manager
        manager = create_rule_manager()
        rule_count = manager.load_rules()
        
        # Validate rules
        validation_report = manager.validate_rules()
        if validation_report["invalid_rules"] > 0:
            logging.warning(f"Found {validation_report['invalid_rules']} invalid rules")
            for error in validation_report["validation_errors"][:5]:  # Show first 5 errors
                logging.warning(f"Rule {error['rule_uuid']}: {error['error']}")
        
        # Export rules
        if manager.export_rules():
            print(f"[✓] Exported {rule_count} rules to {manager.output_path}")
            print(f"[✓] Valid rules: {validation_report['valid_rules']}")
            if validation_report["invalid_rules"] > 0:
                print(f"[⚠] Invalid rules: {validation_report['invalid_rules']}")
        else:
            print("[✗] Failed to export rules")
            
    except Exception as e:
        print(f"[✗] Error: {e}")
        logging.error(f"Rule processing failed: {e}")