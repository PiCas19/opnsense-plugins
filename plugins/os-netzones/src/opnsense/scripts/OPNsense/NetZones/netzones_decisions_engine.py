#!/usr/local/bin/python3

# netzones_decision_engine.py - Network Zones Decision Engine for OPNsense
#
# This script evaluates network traffic policies between zones based on protocol and port,
# logging decisions and providing statistics for dashboard integration. It aligns with
# OPNsense's XML-based policy model and integrates with the settings_loader module.
#
# Author:  Pierpaolo Casati
# Version: 1.0.0
#

import json
import os
import sys
from settings_loader import get_policy_between_zones, get_zone_config

# Constants for default action and log file location
DEFAULT_ACTION = "block"  # Default action if no policy or zone configuration is found
LOG_FILE = "/var/log/netzones_decisions.log"  # Path to store decision logs

def check_port_match(port_rule, port):
    """
    Check if a port matches a given port rule as defined in the XML policy model.

    Args:
        port_rule (str): Port rule from policy (e.g., single port "80", range "1000-2000", or list "80,443")
        port (int or str): Port number to check against the rule

    Returns:
        bool: True if the port matches the rule, False otherwise
    """
    if not port_rule:
        return True  # No port restriction, allow all ports
    
    try:
        port = int(port)  # Convert port to integer for comparison
        port_rule = str(port_rule).strip()  # Ensure port_rule is a string and remove whitespace
        
        if '-' in port_rule:
            # Handle port range (e.g., "1000-2000")
            start, end = map(int, port_rule.split('-', 1))
            return start <= port <= end
        elif ',' in port_rule:
            # Handle port list (e.g., "80,443,8080")
            ports = [int(p.strip()) for p in port_rule.split(',')]
            return port in ports
        else:
            # Handle single port
            return int(port_rule) == port
    except (ValueError, TypeError) as e:
        # Log error if port or rule format is invalid
        return False

def check_protocol_match(policy_protocol, requested_protocol):
    """
    Check if a requested protocol matches the policy protocol, with support for aliases.

    Args:
        policy_protocol (str): Protocol defined in the policy (e.g., "tcp", "udp", "http")
        requested_protocol (str): Protocol of the incoming packet (e.g., "tcp", "http")

    Returns:
        bool: True if protocols match (including aliases), False otherwise
    """
    if not policy_protocol:
        return True  # No protocol restriction, allow all protocols
    
    policy_protocol = policy_protocol.lower().strip()  # Normalize policy protocol
    requested_protocol = requested_protocol.lower().strip()  # Normalize requested protocol
    
    # Direct protocol match
    if policy_protocol == requested_protocol:
        return True
    
    # Handle special "any" protocol
    if policy_protocol == "any":
        return True
    
    # Define common protocol aliases for normalization
    protocol_aliases = {
        'http': 'tcp',
        'https': 'tcp', 
        'ssh': 'tcp',
        'ftp': 'tcp',
        'dns': 'udp',
        'dhcp': 'udp'
    }
    
    # Normalize protocols using aliases
    normalized_policy = protocol_aliases.get(policy_protocol, policy_protocol)
    normalized_requested = protocol_aliases.get(requested_protocol, requested_protocol)
    
    return normalized_policy == normalized_requested

def evaluate_policy(source_zone, destination_zone, protocol, port):
    """
    Evaluate whether communication between two zones is allowed based on policy rules.

    This function checks zone configurations and policies to determine if traffic
    should be allowed or blocked, logging the decision.

    Args:
        source_zone (str): Source zone identifier (e.g., "LAN")
        destination_zone (str): Destination zone identifier (e.g., "DMZ")
        protocol (str): Protocol of the traffic (e.g., "tcp", "udp")
        port (int or str): Port number of the traffic

    Returns:
        str: Action to take ("pass" or "block")
    """
    # Retrieve zone configurations
    src_config = get_zone_config(source_zone)
    dst_config = get_zone_config(destination_zone)
    
    # Block if either zone is missing or disabled
    if not src_config or not dst_config:
        log_decision(source_zone, destination_zone, protocol, port, "block", 
                    "Zone not found or disabled")
        return "block"
    
    # Retrieve policies between source and destination zones
    policies = get_policy_between_zones(source_zone, destination_zone)
    
    for policy in policies:
        # Check if protocol matches
        if not check_protocol_match(policy.get("protocol", ""), protocol):
            continue
        
        # Check source port if specified
        source_port_rule = policy.get("source_port", "")
        if source_port_rule and not check_port_match(source_port_rule, port):
            continue
        
        # Check destination port if specified
        dest_port_rule = policy.get("destination_port", "")
        if dest_port_rule and not check_port_match(dest_port_rule, port):
            continue
        
        # Policy matches, apply its action
        action = policy.get("action", "block")
        
        # Log decision if policy specifies logging
        if policy.get("log_traffic", True):
            log_decision(source_zone, destination_zone, protocol, port, action, 
                        f"Policy '{policy.get('name', 'unnamed')}' matched")
        
        return action
    
    # No specific policy found, apply default zone actions
    src_default = src_config.get("default_action", "pass")
    dst_default = dst_config.get("default_action", "pass")
    
    # Block if either zone has a default action of "block" or "reject"
    if src_default in ["block", "reject"] or dst_default in ["block", "reject"]:
        log_decision(source_zone, destination_zone, protocol, port, "block", 
                    "Zone default action blocks traffic")
        return "block"
    
    # Allow if both zones have default action "pass"
    if src_default == "pass" and dst_default == "pass":
        log_decision(source_zone, destination_zone, protocol, port, "pass", 
                    "Zone default action allows traffic")
        return "pass"
    
    # Fallback to default block action for safety
    log_decision(source_zone, destination_zone, protocol, port, "block", 
                "Default block for unknown action")
    return "block"

def log_decision(source_zone, destination_zone, protocol, port, decision, reason, extra_data=None):
    """
    Log policy decisions to a file for analysis and debugging.

    Args:
        source_zone (str): Source zone identifier
        destination_zone (str): Destination zone identifier
        protocol (str): Protocol of the traffic
        port (int or str): Port number of the traffic
        decision (str): Decision taken ("pass" or "block")
        reason (str): Reason for the decision
        extra_data (dict, optional): Additional data to include in the log

    Returns:
        None
    """
    import time
    
    # Create log entry with relevant details
    entry = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source_zone": source_zone,
        "destination_zone": destination_zone,
        "protocol": protocol,
        "port": port,
        "decision": decision,
        "reason": reason,
        "processing_time_ms": 0.1  # Placeholder for processing time
    }
    
    # Include extra data if provided
    if extra_data:
        entry["extra"] = extra_data
    
    try:
        # Append log entry to the log file
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as e:
        # Log error to stderr if logging fails
        print(f"[ERROR] Failed to log decision: {e}", file=sys.stderr)

def evaluate_packet(packet):
    """
    Evaluate a packet for compatibility with existing inspector systems.

    This function maps packet IPs to zones and evaluates the policy for the traffic.

    Args:
        packet (dict): Packet data with 'src', 'dst', 'port', and 'protocol' fields

    Returns:
        str: Action to take ("pass" or "block")
    """
    from settings_loader import get_zone_by_ip
    
    # Extract packet details with defaults
    src_ip = packet.get("src", "")
    dst_ip = packet.get("dst", "")
    port = packet.get("port", 0)
    protocol = packet.get("protocol", "tcp")
    
    # Map IPs to zones
    src_zone = get_zone_by_ip(src_ip)
    dst_zone = get_zone_by_ip(dst_ip)
    
    # Evaluate policy for the zones, protocol, and port
    return evaluate_policy(src_zone, dst_zone, protocol, port)

def get_policy_stats():
    """
    Retrieve statistics from logged decisions for dashboard display.

    Reads the log file and aggregates decision counts by action, protocol, and zone pair.

    Returns:
        dict: Statistics including total decisions, decisions by action, protocol, zone pairs, and recent decisions
    """
    import time
    from collections import defaultdict
    
    # Return empty stats if log file doesn't exist
    if not os.path.exists(LOG_FILE):
        return {}
    
    stats = {
        "total_decisions": 0,
        "decisions_by_action": defaultdict(int),
        "decisions_by_protocol": defaultdict(int),
        "decisions_by_zone_pair": defaultdict(int),
        "recent_decisions": []
    }
    
    try:
        # Read log file
        with open(LOG_FILE, "r") as f:
            lines = f.readlines()
        
        # Process last 1000 lines for performance
        for line in lines[-1000:]:
            try:
                entry = json.loads(line.strip())
                stats["total_decisions"] += 1
                
                # Aggregate decisions by action
                action = entry.get("decision", "unknown")
                stats["decisions_by_action"][action] += 1
                
                # Aggregate decisions by protocol
                protocol = entry.get("protocol", "unknown")
                stats["decisions_by_protocol"][protocol] += 1
                
                # Aggregate decisions by zone pair
                src_zone = entry.get("source_zone", "UNKNOWN")
                dst_zone = entry.get("destination_zone", "UNKNOWN")
                stats["decisions_by_zone_pair"][f"{src_zone}->{dst_zone}"] += 1
                
                # Store up to 10 recent decisions
                if len(stats["recent_decisions"]) < 10:
                    stats["recent_decisions"].append(entry)
                
            except json.JSONDecodeError:
                continue
        
        # Reverse recent decisions to show newest first
        stats["recent_decisions"].reverse()
        
    except Exception as e:
        # Log error to stderr if stats retrieval fails
        print(f"[ERROR] Failed to read policy stats: {e}", file=sys.stderr)
    
    return dict(stats)

if __name__ == "__main__":
    # Command-line interface for policy evaluation and testing
    if len(sys.argv) == 2:
        # JSON input mode for compatibility with external systems
        try:
            data = json.loads(sys.argv[1])
            result = evaluate_policy(
                data.get("source_zone", ""),
                data.get("destination_zone", ""),
                data.get("protocol", ""),
                data.get("port", 0)
            )
            print(result)
        except json.JSONDecodeError:
            print("Invalid JSON input.", file=sys.stderr)
            sys.exit(1)
    else:
        # Test mode for debugging and validation
        print("=== NetZones Decision Engine Test ===")
        
        # Define test cases for policy evaluation
        test_cases = [
            ("LAN", "DMZ", "tcp", 502),
            ("LAN", "GUEST", "tcp", 80),
            ("DMZ", "WAN", "tcp", 443),
            ("UNKNOWN", "LAN", "tcp", 22)
        ]
        
        # Run test cases and print results
        for src, dst, proto, port in test_cases:
            result = evaluate_policy(src, dst, proto, port)
            print(f"{src} -> {dst} ({proto}:{port}): {result}")
        
        # Display policy statistics
        stats = get_policy_stats()
        print(f"\nPolicy Stats: {stats.get('total_decisions', 0)} total decisions")
        print(f"Actions: {dict(stats.get('decisions_by_action', {}))}")