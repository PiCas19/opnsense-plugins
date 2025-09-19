#!/usr/bin/env python3
"""
rule_engine.py - OPNsense Advanced Inspector Rule Engine

This module provides the core rule evaluation engine for packet inspection.
It handles loading rules from JSON configuration and evaluating packets
against those rules to determine appropriate actions.

Author: Pierpaolo Casati
Version: 2.0
License: BSD 2-Clause
"""

import json
import ipaddress
import os
import logging
from typing import List, Dict, Optional, Any, Union
from dataclasses import dataclass
from pathlib import Path


@dataclass
class RuleMatch:
    """Represents a rule match result."""
    matched: bool
    rule_id: Optional[str] = None
    action: str = "allow"
    description: str = ""
    confidence: float = 1.0


class RuleEngine:
    """
    Core rule evaluation engine for packet inspection.
    
    This class handles loading inspection rules from JSON configuration
    and evaluating incoming packets against those rules to determine
    the appropriate security action to take.
    """
    
    def __init__(self, rules_file: str = "/usr/local/etc/advinspector/rules.json"):
        """
        Initialize the rule engine.
        
        Args:
            rules_file: Path to the JSON file containing inspection rules
        """
        self.rules_file = Path(rules_file)
        self.logger = self._setup_logger()
        self._rules_cache: Optional[List[Dict[str, Any]]] = None
        self._last_load_time: float = 0.0
        
    def _setup_logger(self) -> logging.Logger:
        """
        Set up logging for the rule engine.
        
        Returns:
            Configured logger instance
        """
        logger = logging.getLogger('rule_engine')
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            logger.setLevel(logging.WARNING)  # Default to WARNING to reduce noise
        return logger
    
    def load_rules(self, force_reload: bool = False) -> List[Dict[str, Any]]:
        """
        Load inspection rules from JSON file with caching.
        
        Args:
            force_reload: If True, force reload from disk even if cached
            
        Returns:
            List of rule dictionaries
        """
        try:
            # Check if we need to reload
            if not force_reload and self._rules_cache is not None:
                if self.rules_file.exists():
                    current_mtime = self.rules_file.stat().st_mtime
                    if current_mtime <= self._last_load_time:
                        return self._rules_cache
            
            # Load rules from file
            if not self.rules_file.exists():
                self.logger.warning(f"Rules file not found: {self.rules_file}")
                return []
                
            with open(self.rules_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                
            rules = data.get("rules", [])
            
            # Filter enabled rules and validate
            enabled_rules = []
            for rule in rules:
                if self._validate_rule(rule):
                    if str(rule.get("enabled", "1")) == "1":
                        enabled_rules.append(rule)
                else:
                    self.logger.warning(f"Invalid rule skipped: {rule.get('uuid', 'unknown')}")
            
            # Update cache
            self._rules_cache = enabled_rules
            self._last_load_time = self.rules_file.stat().st_mtime if self.rules_file.exists() else 0.0
            
            self.logger.info(f"Loaded {len(enabled_rules)} enabled rules from {len(rules)} total")
            return enabled_rules
            
        except json.JSONDecodeError as e:
            self.logger.error(f"JSON decode error in rules file: {e}")
            return []
        except Exception as e:
            self.logger.error(f"Error loading rules: {e}")
            return []
    
    def _validate_rule(self, rule: Dict[str, Any]) -> bool:
        """
        Validate rule structure and content.
        
        Args:
            rule: Rule dictionary to validate
            
        Returns:
            True if rule is valid, False otherwise
        """
        if not isinstance(rule, dict):
            return False
            
        required_fields = ['source', 'destination', 'protocol', 'action']
        
        # Check required fields
        for field in required_fields:
            if field not in rule or not rule[field]:
                return False
        
        # Validate action
        valid_actions = ['allow', 'block', 'alert']
        if rule.get('action') not in valid_actions:
            return False
            
        # Validate protocol
        valid_protocols = [
            'tcp', 'udp', 'icmp', 'modbus_tcp', 'dnp3', 'iec104', 'iec61850',
            'profinet', 'ethercat', 'opcua', 'mqtt', 'bacnet', 's7comm'
        ]
        if rule.get('protocol') not in valid_protocols:
            return False
            
        return True
    
    def ip_match(self, rule_ip: str, packet_ip: str) -> bool:
        """
        Check if packet IP matches rule IP/network.
        
        Args:
            rule_ip: IP address or network in CIDR format from rule
            packet_ip: IP address from packet
            
        Returns:
            True if IP matches, False otherwise
        """
        try:
            # Handle empty or wildcard IPs
            if not rule_ip or rule_ip in ['any', '*', '0.0.0.0/0']:
                return True
                
            packet_addr = ipaddress.ip_address(packet_ip)
            rule_network = ipaddress.ip_network(rule_ip, strict=False)
            return packet_addr in rule_network
        except (ValueError, ipaddress.AddressValueError) as e:
            self.logger.debug(f"IP match error for {rule_ip} vs {packet_ip}: {e}")
            return False
    
    def port_match(self, rule_ports: str, packet_port: Union[int, str]) -> bool:
        """
        Check if packet port matches rule port specification.
        
        Args:
            rule_ports: Port specification from rule (e.g., "80", "80,443", "1000-2000")
            packet_port: Port number from packet
            
        Returns:
            True if port matches, False otherwise
        """
        # Handle empty rule_ports or wildcards
        if not rule_ports or rule_ports in ['any', '*']:
            return True
            
        try:
            packet_port_int = int(packet_port)
            
            for port_spec in str(rule_ports).split(','):
                port_spec = port_spec.strip()
                
                if '-' in port_spec:
                    # Port range
                    try:
                        start, end = map(int, port_spec.split('-', 1))
                        if start <= packet_port_int <= end:
                            return True
                    except ValueError:
                        self.logger.debug(f"Invalid port range: {port_spec}")
                        continue
                else:
                    # Single port
                    try:
                        if int(port_spec) == packet_port_int:
                            return True
                    except ValueError:
                        self.logger.debug(f"Invalid port number: {port_spec}")
                        continue
                        
        except (ValueError, TypeError) as e:
            self.logger.debug(f"Port match error for {rule_ports} vs {packet_port}: {e}")
            
        return False
    
    def evaluate_packet(self, packet: Dict[str, Any]) -> RuleMatch:
        """
        Evaluate a packet against all loaded rules.
        
        Args:
            packet: Dictionary containing packet information with keys:
                   'src', 'dst', 'port', 'protocol', etc.
                   
        Returns:
            RuleMatch object indicating if a rule matched and what action to take
        """
        rules = self.load_rules()
        
        if not rules:
            return RuleMatch(matched=False, action="allow")
        
        # Extract packet information with defaults
        packet_src = packet.get("src", "")
        packet_dst = packet.get("dst", "")
        packet_port = packet.get("port", 0)
        packet_protocol = str(packet.get("protocol", "")).lower()
        
        # Evaluate each rule
        for rule in rules:
            try:
                rule_src = str(rule.get("source", ""))
                rule_dst = str(rule.get("destination", ""))
                rule_port = str(rule.get("port", ""))
                rule_protocol = str(rule.get("protocol", "")).lower()
                
                # Check all matching criteria
                if (self.ip_match(rule_src, packet_src) and
                    self.ip_match(rule_dst, packet_dst) and
                    self.port_match(rule_port, packet_port) and
                    rule_protocol == packet_protocol):
                    
                    action = rule.get("action", "allow")
                    rule_id = rule.get("uuid", "unknown")
                    description = rule.get("description", "")
                    
                    self.logger.debug(
                        f"Rule {rule_id} matched: {packet_src}:{packet_port} -> "
                        f"{packet_dst} ({packet_protocol}) = {action}"
                    )
                    
                    return RuleMatch(
                        matched=True,
                        rule_id=rule_id,
                        action=action,
                        description=description
                    )
                    
            except Exception as e:
                self.logger.error(f"Error evaluating rule {rule.get('uuid', 'unknown')}: {e}")
                continue
        
        # No rules matched
        return RuleMatch(matched=False, action="allow")
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get engine statistics.
        
        Returns:
            Dictionary containing engine statistics
        """
        rules = self.load_rules()
        
        stats: Dict[str, Any] = {
            "total_rules": len(rules),
            "rules_by_action": {},
            "rules_by_protocol": {},
            "last_reload": self._last_load_time,
            "rules_file": str(self.rules_file)
        }
        
        # Count rules by action and protocol
        for rule in rules:
            action = rule.get("action", "unknown")
            protocol = rule.get("protocol", "unknown")
            
            stats["rules_by_action"][action] = stats["rules_by_action"].get(action, 0) + 1
            stats["rules_by_protocol"][protocol] = stats["rules_by_protocol"].get(protocol, 0) + 1
        
        return stats


# Legacy functions for backward compatibility
def load_rules() -> List[Dict[str, Any]]:
    """Legacy function - use RuleEngine.load_rules() instead."""
    engine = RuleEngine()
    return engine.load_rules()


def ip_match(rule_ip: str, pkt_ip: str) -> bool:
    """Legacy function - use RuleEngine.ip_match() instead."""
    engine = RuleEngine()
    return engine.ip_match(rule_ip, pkt_ip)


def port_match(rule_ports: str, pkt_port: Union[int, str]) -> bool:
    """Legacy function - use RuleEngine.port_match() instead."""
    engine = RuleEngine()
    return engine.port_match(rule_ports, pkt_port)


def evaluate_packet(packet: Dict[str, Any]) -> str:
    """Legacy function - use RuleEngine.evaluate_packet() instead."""
    engine = RuleEngine()
    result = engine.evaluate_packet(packet)
    return result.action  # Return only action for backward compatibility


if __name__ == "__main__":
    # Basic test functionality
    engine = RuleEngine()
    stats = engine.get_statistics()
    print(f"Rule engine initialized with {stats['total_rules']} rules")