#!/usr/local/bin/python3

# settings_loader.py - Configuration Loader for NetZones in OPNsense
#
# This script loads and parses configuration data from OPNsense's XML configuration
# file for the NetZones module, providing zone and policy information for policy
# evaluation and dashboard display. It supports caching for performance and ensures
# compatibility with the OPNsense XML model for zones and inter-zone policies.
#
# Author: Pierpaolo Casati
# Version: 1.0.0
#

import xml.etree.ElementTree as ET
import ipaddress
import json
import time

# Configuration constants
CONFIG_PATH = "/conf/config.xml"  # Path to OPNsense configuration file
CACHE_FILE = "/tmp/netzones_cache.json"  # Path to store cached configuration
CACHE_TIMEOUT = 30  # Cache validity duration in seconds

# Global cache variables
_cache = None  # Cached configuration data
_cache_time = 0  # Timestamp of last cache update

def get_zones():
    """
    Retrieve all zone configurations from OPNsense/NetZones/zone in the XML configuration.

    Returns:
        list: List of XML elements representing zones, or empty list on error
    """
    try:
        tree = ET.parse(CONFIG_PATH)  # Parse the OPNsense configuration XML
        root = tree.getroot()
        # Navigate to OPNsense/NetZones/zone path as per XML model
        return root.findall(".//OPNsense/NetZones/zone")
    except Exception as e:
        # Log error to stderr if XML parsing fails
        print(f"[ERROR] get_zones: {e}", file=sys.stderr)
        return []

def get_inter_zone_policies():
    """
    Retrieve all inter-zone policies from OPNsense/NetZones/inter_zone_policy in the XML configuration.

    Returns:
        list: List of XML elements representing inter-zone policies, or empty list on error
    """
    try:
        tree = ET.parse(CONFIG_PATH)  # Parse the OPNsense configuration XML
        root = tree.getroot()
        # Navigate to OPNsense/NetZones/inter_zone_policy path as per XML model
        return root.findall(".//OPNsense/NetZones/inter_zone_policy")
    except Exception as e:
        # Log error to stderr if XML parsing fails
        print(f"[ERROR] get_inter_zone_policies: {e}", file=sys.stderr)
        return []

def load_enabled():
    """
    Check if at least one zone is enabled in the configuration.

    Returns:
        bool: True if at least one zone is enabled, False otherwise
    """
    for zone in get_zones():
        if zone.findtext("enabled", "0") == "1":
            return True
    return False

def load_verbosity():
    """
    Retrieve the logging verbosity level (placeholder for future configurability).

    Returns:
        str: Current verbosity level ("normal")
    """
    return "normal"

def load_inspection_mode():
    """
    Retrieve the inspection mode for compatibility with the inspector system.

    Returns:
        str: Current inspection mode ("stateful")
    """
    return "stateful"

def load_ips_mode():
    """
    Check if IPS mode is enabled for compatibility with the inspector system.

    Returns:
        bool: True if IPS mode is enabled, False otherwise
    """
    return True

def load_promiscuous_mode():
    """
    Check if promiscuous mode is enabled for network interfaces.

    Returns:
        bool: False (promiscuous mode is disabled by default)
    """
    return False

def load_home_networks():
    """
    Retrieve a list of home/internal networks from enabled zones.

    Returns:
        list: List of subnet strings for enabled zones
    """
    networks = set()
    for zone in get_zones():
        if zone.findtext("enabled", "0") == "1":
            subnets = zone.findtext("subnets", "")  # Extract subnets field
            for subnet in subnets.split(","):
                subnet = subnet.strip()
                if subnet:
                    networks.add(subnet)
    return list(networks)

def load_interfaces():
    """
    Retrieve all configured network interfaces from enabled zones.

    Returns:
        list: List of interface names, defaulting to ["lan", "wan", "dmz"] if none specified
    """
    interfaces = set()
    for zone in get_zones():
        if zone.findtext("enabled", "0") == "1":
            interface_list = zone.findtext("interface", "")  # Extract interface field
            for iface in interface_list.split(","):
                iface = iface.strip()
                if iface:
                    interfaces.add(iface.lower())  # Normalize to lowercase
    
    # Default to standard interfaces if none are specified
    if not interfaces:
        interfaces = {"lan", "wan", "dmz"}
    
    return list(interfaces)

def load_zone_subnet_map():
    """
    Create a mapping of subnets to zone names for IP-to-zone resolution.

    Returns:
        dict: Mapping of subnet strings to zone names
    """
    subnet_map = {}
    for zone in get_zones():
        if zone.findtext("enabled", "0") == "1":
            name = zone.findtext("name")  # Extract zone name
            subnets = zone.findtext("subnets", "")  # Extract subnets field
            for subnet in subnets.split(","):
                subnet = subnet.strip()
                if subnet and name:
                    subnet_map[subnet] = name
    return subnet_map

def get_zone_by_ip(ip):
    """
    Resolve an IP address to its corresponding zone name.

    Args:
        ip (str): IP address to resolve

    Returns:
        str: Zone name if found, "UNKNOWN" otherwise
    """
    zone_map = load_zone_subnet_map()
    try:
        ip_obj = ipaddress.ip_address(ip)  # Parse IP address
    except ValueError:
        return "UNKNOWN"
    
    for subnet, zone in zone_map.items():
        try:
            if ip_obj in ipaddress.ip_network(subnet, strict=False):  # Check if IP is in subnet
                return zone
        except ValueError:
            continue
    
    return "UNKNOWN"

def get_zone_config(zone_name):
    """
    Retrieve the full configuration for a specific zone, aligned with the XML model.

    Args:
        zone_name (str): Name of the zone to retrieve configuration for

    Returns:
        dict: Zone configuration dictionary, or None if not found or disabled
    """
    for zone in get_zones():
        if zone.findtext("name") == zone_name and zone.findtext("enabled", "0") == "1":
            return {
                "name": zone.findtext("name", ""),
                "description": zone.findtext("description", ""),
                "enabled": zone.findtext("enabled", "0") == "1",
                "subnets": [s.strip() for s in zone.findtext("subnets", "").split(",") if s.strip()],
                "interface": [i.strip() for i in zone.findtext("interface", "").split(",") if i.strip()],
                "default_action": zone.findtext("default_action", "pass"),  # Default action per XML model
                "log_traffic": zone.findtext("log_traffic", "0") == "1",
                "priority": int(zone.findtext("priority", "100") or 100),
            }
    return None

def get_policy_between_zones(source_zone, destination_zone):
    """
    Retrieve policies between two zones, sorted by priority, aligned with the XML model.

    Args:
        source_zone (str): Source zone name
        destination_zone (str): Destination zone name

    Returns:
        list: List of policy dictionaries, sorted by priority
    """
    policies = []
    for policy in get_inter_zone_policies():
        if (policy.findtext("enabled", "0") == "1" and
            policy.findtext("source_zone") == source_zone and
            policy.findtext("destination_zone") == destination_zone):
            
            policies.append({
                "name": policy.findtext("name", ""),
                "description": policy.findtext("description", ""),
                "action": policy.findtext("action", "block"),
                "protocol": policy.findtext("protocol", ""),  # Single protocol per XML model
                "source_port": policy.findtext("source_port", ""),
                "destination_port": policy.findtext("destination_port", ""),
                "log_traffic": policy.findtext("log_traffic", "0") == "1",
                "priority": int(policy.findtext("priority", "100") or 100),
            })
    
    # Sort policies by priority (lower number = higher priority)
    return sorted(policies, key=lambda p: p["priority"])

def get_all_zones_info():
    """
    Retrieve information for all enabled zones for dashboard display.

    Returns:
        list: List of configuration dictionaries for enabled zones
    """
    zones_info = []
    for zone in get_zones():
        if zone.findtext("enabled", "0") == "1":
            zone_info = get_zone_config(zone.findtext("name"))
            if zone_info:
                zones_info.append(zone_info)
    return zones_info

def get_all_policies_info():
    """
    Retrieve information for all enabled inter-zone policies for dashboard display, aligned with the XML model.

    Returns:
        list: List of policy dictionaries for enabled policies
    """
    policies_info = []
    for policy in get_inter_zone_policies():
        if policy.findtext("enabled", "0") == "1":
            policies_info.append({
                "name": policy.findtext("name", ""),
                "description": policy.findtext("description", ""),
                "source_zone": policy.findtext("source_zone", ""),
                "destination_zone": policy.findtext("destination_zone", ""),
                "action": policy.findtext("action", "block"),
                "protocol": policy.findtext("protocol", ""),
                "source_port": policy.findtext("source_port", ""),
                "destination_port": policy.findtext("destination_port", ""),
                "log_traffic": policy.findtext("log_traffic", "0") == "1",
                "priority": int(policy.findtext("priority", "100") or 100),
            })
    return policies_info

def get_system_stats():
    """
    Retrieve system statistics for dashboard display.

    Returns:
        dict: Statistics including total and active zones and policies
    """
    zones = get_zones()
    policies = get_inter_zone_policies()
    
    active_zones = sum(1 for zone in zones if zone.findtext("enabled", "0") == "1")
    active_policies = sum(1 for policy in policies if policy.findtext("enabled", "0") == "1")
    
    return {
        "zones": {
            "total": len(zones),
            "active": active_zones
        },
        "policies": {
            "total": len(policies),
            "active": active_policies
        },
    }

def cache_config():
    """
    Cache configuration data for performance, saving to a file for debugging.

    Returns:
        dict: Cached configuration data including zones, policies, and system stats
    """
    global _cache, _cache_time
    
    current_time = time.time()
    if _cache and (current_time - _cache_time) < CACHE_TIMEOUT:
        return _cache
    
    # Build new cache with all configuration data
    _cache = {
        "zones": get_all_zones_info(),
        "policies": get_all_policies_info(),
        "zone_subnet_map": load_zone_subnet_map(),
        "system_stats": get_system_stats()
    }
    _cache_time = current_time
    
    # Save cache to file for debugging
    try:
        with open(CACHE_FILE, 'w') as f:
            json.dump(_cache, f, indent=2)
    except Exception:
        pass
    
    return _cache

def evaluate_packet(packet):
    """
    Evaluate a packet for compatibility with the existing inspector system.

    Args:
        packet: Packet data (not used in current implementation)

    Returns:
        str: Default action ("allow") for compatibility
    """
    return "allow"  # Default for inspector compatibility; NetZones handles actual decisions

if __name__ == "__main__":
    # Test script for configuration loading and debugging
    print("=== NetZones Settings Loader Test ===")
    print(f"Enabled: {load_enabled()}")
    print(f"Interfaces: {load_interfaces()}")
    print(f"Home Networks: {load_home_networks()}")
    print(f"Zone Subnet Map: {load_zone_subnet_map()}")
    
    # Test IP-to-zone resolution
    test_ip = "192.168.1.100"
    zone = get_zone_by_ip(test_ip)
    print(f"IP {test_ip} is in zone: {zone}")
    
    # Test zone configuration retrieval
    if zone != "UNKNOWN":
        config = get_zone_config(zone)
        print(f"Zone config: {config}")
    
    # Test configuration cache
    cache = cache_config()
    print(f"Cached {len(cache['zones'])} zones, {len(cache['policies'])} policies")