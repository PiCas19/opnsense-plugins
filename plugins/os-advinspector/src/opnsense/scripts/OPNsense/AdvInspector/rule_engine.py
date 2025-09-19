#!/usr/local/bin/python3

"""
Rule Engine Module for Advanced Network Inspector

High-performance rule evaluation engine with advanced matching capabilities,
caching, and comprehensive logging. Supports complex rule conditions including
IP networks, port ranges, protocol matching, and rule priorities.

Author: System Administrator
Version: 1.0
"""

import json
import ipaddress
import logging
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Any, Union, Set, Tuple
from enum import Enum
from functools import lru_cache


class RuleAction(Enum):
    """Enumeration of possible rule actions."""
    ALLOW = "allow"
    BLOCK = "block"
    ALERT = "alert"
    DROP = "drop"
    REJECT = "reject"


class MatchResult(Enum):
    """Enumeration of match results."""
    MATCH = "match"
    NO_MATCH = "no_match"
    ERROR = "error"


@dataclass
class RuleMatchContext:
    """Context information for rule matching operations."""
    rule_uuid: str
    rule_name: str
    match_time: float
    packet_info: Dict[str, Any]
    matched_conditions: List[str]


class RuleMatcher(ABC):
    """Abstract base class for rule condition matchers."""
    
    @abstractmethod
    def matches(self, rule_value: str, packet_value: Any) -> MatchResult:
        """
        Check if rule condition matches packet data.
        
        Args:
            rule_value: Value from rule definition
            packet_value: Value from packet data
            
        Returns:
            MatchResult indicating match status
        """
        pass


class IPMatcher(RuleMatcher):
    """
    IP address and network matcher with CIDR support.
    Supports single IPs, CIDR networks, and wildcard matching.
    """
    
    def __init__(self):
        """Initialize IP matcher with caching for performance."""
        self._network_cache = {}
        self._cache_lock = threading.Lock()
    
    @lru_cache(maxsize=1000)
    def _parse_network(self, network_spec: str) -> Optional[ipaddress.IPv4Network]:
        """
        Parse network specification with caching.
        
        Args:
            network_spec: Network specification (IP, CIDR, or wildcard)
            
        Returns:
            IPv4Network object or None if invalid
        """
        if not network_spec or network_spec.lower() in ("any", "*", ""):
            return None
        
        try:
            # Handle single IP addresses
            if "/" not in network_spec:
                # Convert single IP to /32 network
                return ipaddress.IPv4Network(f"{network_spec}/32", strict=False)
            else:
                # Handle CIDR notation
                return ipaddress.IPv4Network(network_spec, strict=False)
        except (ipaddress.AddressValueError, ValueError):
            logging.warning(f"Invalid network specification: {network_spec}")
            return None
    
    def matches(self, rule_value: str, packet_value: Any) -> MatchResult:
        """
        Check if packet IP matches rule network specification.
        
        Args:
            rule_value: Network specification from rule
            packet_value: IP address from packet
            
        Returns:
            MatchResult indicating match status
        """
        if not rule_value or rule_value.lower() in ("any", "*"):
            return MatchResult.MATCH
        
        try:
            packet_ip = ipaddress.ip_address(str(packet_value))
            rule_network = self._parse_network(rule_value)
            
            if rule_network is None:
                return MatchResult.MATCH  # Wildcard match
            
            return MatchResult.MATCH if packet_ip in rule_network else MatchResult.NO_MATCH
            
        except (ipaddress.AddressValueError, ValueError) as e:
            logging.debug(f"IP match error: {e}")
            return MatchResult.ERROR


class PortMatcher(RuleMatcher):
    """
    Port matcher supporting single ports, ranges, and comma-separated lists.
    Examples: "80", "80-8080", "80,443,8080", "1000-2000,8080"
    """
    
    @lru_cache(maxsize=500)
    def _parse_port_specification(self, port_spec: str) -> Set[Tuple[int, int]]:
        """
        Parse port specification into set of (start, end) ranges.
        
        Args:
            port_spec: Port specification string
            
        Returns:
            Set of (start_port, end_port) tuples
        """
        if not port_spec or port_spec.lower() in ("any", "*", ""):
            return {(1, 65535)}  # Match all ports
        
        port_ranges = set()
        
        try:
            for part in port_spec.split(','):
                part = part.strip()
                
                if '-' in part:
                    # Handle port range (e.g., "80-8080")
                    start_str, end_str = part.split('-', 1)
                    start_port = int(start_str.strip())
                    end_port = int(end_str.strip())
                    
                    # Validate port range
                    if 1 <= start_port <= 65535 and 1 <= end_port <= 65535 and start_port <= end_port:
                        port_ranges.add((start_port, end_port))
                    else:
                        logging.warning(f"Invalid port range: {part}")
                else:
                    # Handle single port
                    port = int(part)
                    if 1 <= port <= 65535:
                        port_ranges.add((port, port))
                    else:
                        logging.warning(f"Invalid port number: {port}")
        
        except ValueError as e:
            logging.warning(f"Port specification parsing error: {e}")
        
        return port_ranges
    
    def matches(self, rule_value: str, packet_value: Any) -> MatchResult:
        """
        Check if packet port matches rule port specification.
        
        Args:
            rule_value: Port specification from rule
            packet_value: Port number from packet
            
        Returns:
            MatchResult indicating match status
        """
        if not rule_value or rule_value.lower() in ("any", "*"):
            return MatchResult.MATCH
        
        try:
            packet_port = int(packet_value)
            if not (1 <= packet_port <= 65535):
                return MatchResult.ERROR
            
            port_ranges = self._parse_port_specification(rule_value)
            
            # Check if packet port falls within any specified range
            for start_port, end_port in port_ranges:
                if start_port <= packet_port <= end_port:
                    return MatchResult.MATCH
            
            return MatchResult.NO_MATCH
            
        except (ValueError, TypeError) as e:
            logging.debug(f"Port match error: {e}")
            return MatchResult.ERROR


class ProtocolMatcher(RuleMatcher):
    """
    Protocol matcher supporting both named protocols and numeric values.
    Supports: tcp, udp, icmp, any, *, and numeric protocol numbers (0-255).
    """
    
    # Protocol name to number mapping
    PROTOCOL_MAP = {
        "tcp": 6,
        "udp": 17,
        "icmp": 1,
        "igmp": 2,
        "ipv4": 4,
        "ipv6": 41,
        "gre": 47,
        "esp": 50,
        "ah": 51
    }
    
    def matches(self, rule_value: str, packet_value: Any) -> MatchResult:
        """
        Check if packet protocol matches rule protocol specification.
        
        Args:
            rule_value: Protocol specification from rule
            packet_value: Protocol from packet (name or number)
            
        Returns:
            MatchResult indicating match status
        """
        if not rule_value or rule_value.lower() in ("any", "*", ""):
            return MatchResult.MATCH
        
        try:
            # Normalize rule and packet values
            rule_protocol = rule_value.lower().strip()
            packet_protocol = str(packet_value).lower().strip()
            
            # Direct string match first
            if rule_protocol == packet_protocol:
                return MatchResult.MATCH
            
            # Convert to protocol numbers for comparison
            rule_proto_num = self._get_protocol_number(rule_protocol)
            packet_proto_num = self._get_protocol_number(packet_protocol)
            
            if rule_proto_num is not None and packet_proto_num is not None:
                return MatchResult.MATCH if rule_proto_num == packet_proto_num else MatchResult.NO_MATCH
            
            return MatchResult.NO_MATCH
            
        except Exception as e:
            logging.debug(f"Protocol match error: {e}")
            return MatchResult.ERROR
    
    def _get_protocol_number(self, protocol: str) -> Optional[int]:
        """
        Get numeric protocol number from name or number string.
        
        Args:
            protocol: Protocol name or number
            
        Returns:
            Protocol number or None if invalid
        """
        # Check if it's a known protocol name
        if protocol in self.PROTOCOL_MAP:
            return self.PROTOCOL_MAP[protocol]
        
        # Try to parse as numeric protocol number
        try:
            proto_num = int(protocol)
            if 0 <= proto_num <= 255:
                return proto_num
        except ValueError:
            pass
        
        return None


class SecurityRule:
    """
    Enhanced security rule with comprehensive matching capabilities.
    """
    
    def __init__(self, rule_data: Dict[str, Any]):
        """
        Initialize security rule from dictionary data.
        
        Args:
            rule_data: Rule configuration dictionary
        """
        self.uuid = rule_data.get("uuid", "")
        self.name = rule_data.get("name", "")
        self.description = rule_data.get("description", "")
        self.source = rule_data.get("source", "")
        self.destination = rule_data.get("destination", "")
        self.port = rule_data.get("port", "")
        self.protocol = rule_data.get("protocol", "")
        self.action = rule_data.get("action", "allow")
        self.enabled = self._parse_boolean(rule_data.get("enabled", True))
        self.priority = int(rule_data.get("priority", 1000))
        self.category = rule_data.get("category", "general")
        self.metadata = rule_data.get("metadata", {})
        
        # Initialize matchers
        self._ip_matcher = IPMatcher()
        self._port_matcher = PortMatcher()
        self._protocol_matcher = ProtocolMatcher()
    
    def _parse_boolean(self, value: Any) -> bool:
        """
        Parse various boolean representations.
        
        Args:
            value: Value to parse as boolean
            
        Returns:
            Boolean value
        """
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.lower() in ("true", "1", "yes", "on", "enabled")
        if isinstance(value, int):
            return value != 0
        return bool(value)
    
    def matches_packet(self, packet: Dict[str, Any]) -> Tuple[bool, RuleMatchContext]:
        """
        Check if this rule matches the given packet.
        
        Args:
            packet: Packet data dictionary
            
        Returns:
            Tuple of (matches, context) where matches is boolean and context contains match details
        """
        start_time = time.time()
        matched_conditions = []
        
        # Check source IP
        if self.source:
            src_match = self._ip_matcher.matches(self.source, packet.get("src", ""))
            if src_match == MatchResult.NO_MATCH:
                context = RuleMatchContext(
                    rule_uuid=self.uuid,
                    rule_name=self.name,
                    match_time=time.time() - start_time,
                    packet_info=packet,
                    matched_conditions=matched_conditions
                )
                return False, context
            elif src_match == MatchResult.MATCH:
                matched_conditions.append(f"source_ip:{self.source}")
        
        # Check destination IP
        if self.destination:
            dst_match = self._ip_matcher.matches(self.destination, packet.get("dst", ""))
            if dst_match == MatchResult.NO_MATCH:
                context = RuleMatchContext(
                    rule_uuid=self.uuid,
                    rule_name=self.name,
                    match_time=time.time() - start_time,
                    packet_info=packet,
                    matched_conditions=matched_conditions
                )
                return False, context
            elif dst_match == MatchResult.MATCH:
                matched_conditions.append(f"destination_ip:{self.destination}")
        
        # Check port
        if self.port:
            port_match = self._port_matcher.matches(self.port, packet.get("port", 0))
            if port_match == MatchResult.NO_MATCH:
                context = RuleMatchContext(
                    rule_uuid=self.uuid,
                    rule_name=self.name,
                    match_time=time.time() - start_time,
                    packet_info=packet,
                    matched_conditions=matched_conditions
                )
                return False, context
            elif port_match == MatchResult.MATCH:
                matched_conditions.append(f"port:{self.port}")
        
        # Check protocol
        if self.protocol:
            proto_match = self._protocol_matcher.matches(self.protocol, packet.get("protocol", ""))
            if proto_match == MatchResult.NO_MATCH:
                context = RuleMatchContext(
                    rule_uuid=self.uuid,
                    rule_name=self.name,
                    match_time=time.time() - start_time,
                    packet_info=packet,
                    matched_conditions=matched_conditions
                )
                return False, context
            elif proto_match == MatchResult.MATCH:
                matched_conditions.append(f"protocol:{self.protocol}")
        
        # All conditions matched
        context = RuleMatchContext(
            rule_uuid=self.uuid,
            rule_name=self.name,
            match_time=time.time() - start_time,
            packet_info=packet,
            matched_conditions=matched_conditions
        )
        return True, context
    
    def get_action(self) -> RuleAction:
        """
        Get rule action as enum.
        
        Returns:
            RuleAction enum value
        """
        try:
            return RuleAction(self.action.lower())
        except ValueError:
            logging.warning(f"Unknown rule action '{self.action}', defaulting to ALLOW")
            return RuleAction.ALLOW


class RuleLoader:
    """
    Rule loader with caching and automatic reloading capabilities.
    """
    
    def __init__(self, rules_file: str = "/usr/local/etc/advinspector/rules.json"):
        """
        Initialize rule loader.
        
        Args:
            rules_file: Path to rules JSON file
        """
        self.rules_file = Path(rules_file)
        self._rules_cache: List[SecurityRule] = []
        self._last_modified: Optional[float] = None
        self._cache_lock = threading.Lock()
        self.load_errors = 0
    
    def load_rules(self, force_reload: bool = False) -> List[SecurityRule]:
        """
        Load rules from file with automatic caching and reload detection.
        
        Args:
            force_reload: Force reload even if file hasn't changed
            
        Returns:
            List of loaded SecurityRule objects
        """
        with self._cache_lock:
            # Check if reload is needed
            if not force_reload and self._rules_cache and self._is_cache_valid():
                return self._rules_cache.copy()
            
            return self._load_rules_from_file()
    
    def _is_cache_valid(self) -> bool:
        """Check if cached rules are still valid."""
        try:
            if not self.rules_file.exists():
                return len(self._rules_cache) == 0
            
            current_mtime = self.rules_file.stat().st_mtime
            return self._last_modified == current_mtime
        except OSError:
            return False
    
    def _load_rules_from_file(self) -> List[SecurityRule]:
        """Load rules from JSON file."""
        rules = []
        
        try:
            if not self.rules_file.exists():
                logging.warning(f"Rules file not found: {self.rules_file}")
                self._rules_cache = []
                return []
            
            with open(self.rules_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            # Extract rules from JSON structure
            rules_data = data.get("rules", []) if isinstance(data, dict) else data
            
            # Create SecurityRule objects
            for rule_data in rules_data:
                try:
                    rule = SecurityRule(rule_data)
                    if rule.enabled:  # Only load enabled rules
                        rules.append(rule)
                except Exception as e:
                    self.load_errors += 1
                    logging.error(f"Failed to load rule {rule_data.get('uuid', 'unknown')}: {e}")
            
            # Update cache
            self._rules_cache = rules
            self._last_modified = self.rules_file.stat().st_mtime
            
            logging.info(f"Loaded {len(rules)} enabled rules from {self.rules_file}")
            
        except json.JSONDecodeError as e:
            logging.error(f"Invalid JSON in rules file {self.rules_file}: {e}")
            self.load_errors += 1
        except Exception as e:
            logging.error(f"Failed to load rules from {self.rules_file}: {e}")
            self.load_errors += 1
        
        return rules
    
    def get_load_errors(self) -> int:
        """Get count of rule loading errors."""
        return self.load_errors


class RuleEngine:
    """
    High-performance rule evaluation engine with comprehensive matching and logging.
    """
    
    def __init__(self, rules_file: str = "/usr/local/etc/advinspector/rules.json"):
        """
        Initialize rule engine.
        
        Args:
            rules_file: Path to rules JSON file
        """
        self.rule_loader = RuleLoader(rules_file)
        self.evaluation_stats = {
            "total_evaluations": 0,
            "rule_matches": 0,
            "evaluation_errors": 0,
            "average_evaluation_time": 0.0
        }
        self._stats_lock = threading.Lock()
    
    def evaluate_packet(self, packet: Dict[str, Any]) -> str:
        """
        Evaluate packet against all loaded rules and return action.
        
        Args:
            packet: Packet data dictionary
            
        Returns:
            Action string ("allow", "block", "alert", etc.)
        """
        start_time = time.time()
        
        try:
            # Load current rules (with caching)
            rules = self.rule_loader.load_rules()
            
            # Sort rules by priority (lower number = higher priority)
            sorted_rules = sorted(rules, key=lambda r: r.priority)
            
            # Evaluate rules in priority order
            for rule in sorted_rules:
                matches, context = rule.matches_packet(packet)
                
                if matches:
                    action = rule.get_action().value
                    
                    # Update statistics
                    self._update_stats(start_time, True)
                    
                    # Log match details
                    logging.debug(f"Rule {rule.uuid} matched packet: {context.matched_conditions}")
                    
                    return action
            
            # No rules matched
            self._update_stats(start_time, False)
            return RuleAction.ALLOW.value
            
        except Exception as e:
            logging.error(f"Rule evaluation error: {e}")
            self._update_stats(start_time, False, error=True)
            return RuleAction.ALLOW.value  # Fail open
    
    def _update_stats(self, start_time: float, matched: bool, error: bool = False) -> None:
        """Update evaluation statistics."""
        evaluation_time = time.time() - start_time
        
        with self._stats_lock:
            self.evaluation_stats["total_evaluations"] += 1
            
            if matched:
                self.evaluation_stats["rule_matches"] += 1
            
            if error:
                self.evaluation_stats["evaluation_errors"] += 1
            
            # Update average evaluation time
            total_evals = self.evaluation_stats["total_evaluations"]
            current_avg = self.evaluation_stats["average_evaluation_time"]
            self.evaluation_stats["average_evaluation_time"] = (
                (current_avg * (total_evals - 1) + evaluation_time) / total_evals
            )
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get engine statistics."""
        with self._stats_lock:
            stats = self.evaluation_stats.copy()
        
        # Add rule loader statistics
        stats["load_errors"] = self.rule_loader.get_load_errors()
        stats["rules_loaded"] = len(self.rule_loader.load_rules())
        
        return stats
    
    def reload_rules(self) -> int:
        """
        Force reload of rules from file.
        
        Returns:
            Number of rules loaded
        """
        rules = self.rule_loader.load_rules(force_reload=True)
        return len(rules)


# Global rule engine instance
_rule_engine = RuleEngine()


def evaluate_packet(packet: Dict[str, Any]) -> str:
    """
    Evaluate packet against security rules (backward compatibility function).
    
    Args:
        packet: Packet data dictionary
        
    Returns:
        Action string ("allow", "block", "alert", etc.)
    """
    return _rule_engine.evaluate_packet(packet)


def load_rules() -> List[Dict[str, Any]]:
    """
    Load rules in legacy format for backward compatibility.
    
    Returns:
        List of rule dictionaries
    """
    try:
        rules = _rule_engine.rule_loader.load_rules()
        return [
            {
                "uuid": rule.uuid,
                "name": rule.name,
                "source": rule.source,
                "destination": rule.destination,
                "port": rule.port,
                "protocol": rule.protocol,
                "action": rule.action,
                "enabled": "1" if rule.enabled else "0",
                "priority": rule.priority
            }
            for rule in rules
        ]
    except Exception as e:
        logging.error(f"Failed to load rules: {e}")
        return []


def get_rule_engine() -> RuleEngine:
    """
    Get the global rule engine instance.
    
    Returns:
        RuleEngine instance
    """
    return _rule_engine


def reload_rules() -> int:
    """
    Reload rules from file.
    
    Returns:
        Number of rules loaded
    """
    return _rule_engine.reload_rules()


# Legacy compatibility functions
def ip_match(rule_ip: str, pkt_ip: str) -> bool:
    """Legacy IP matching function for backward compatibility."""
    matcher = IPMatcher()
    result = matcher.matches(rule_ip, pkt_ip)
    return result == MatchResult.MATCH


def port_match(rule_ports: str, pkt_port: Union[str, int]) -> bool:
    """Legacy port matching function for backward compatibility."""
    matcher = PortMatcher()
    result = matcher.matches(rule_ports, pkt_port)
    return result == MatchResult.MATCH


if __name__ == "__main__":
    # Module loaded directly - use as import only
    print("RuleEngine module - use as import only")
    import sys
    sys.exit(1)