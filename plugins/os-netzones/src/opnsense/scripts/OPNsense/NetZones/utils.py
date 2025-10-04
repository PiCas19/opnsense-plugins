#!/usr/local/bin/python3

# protocol_detection.py - Protocol Detection for OPNsense NetZones
#
# This script provides functions to detect and classify network protocols based on port numbers,
# focusing on both standard internet protocols and industrial/OT protocols as defined in the
# NetZones model. It includes risk level assessment and categorization for security analysis,
# ensuring compatibility with the OPNsense ecosystem.
#
# Author: [Not specified]
# Version: 1.0.0
#

def detect_protocol(port):
    """
    Detect the protocol associated with a given port number, aligned with NetZones model definitions.

    Args:
        port (int): Port number to analyze

    Returns:
        str: Detected protocol name (e.g., "http", "modbus_tcp", "tcp")
    """
    # Standard internet protocols mapping
    standard_mapping = {
        # Web protocols
        80: "http",
        443: "https",
        8080: "http",
        8443: "https",
        
        # Network services
        21: "ftp",
        22: "ssh",
        23: "telnet",
        25: "smtp",
        53: "dns",
        67: "dhcp",
        68: "dhcp",
        69: "tftp",
        110: "pop3",
        143: "imap",
        161: "snmp",
        162: "snmp",
        
        # Database protocols
        1433: "mssql",
        1521: "oracle",
        3306: "mysql",
        5432: "postgresql",
        
        # Remote access
        3389: "rdp",
        5900: "vnc",
        
        # File sharing
        135: "rpc",
        139: "netbios",
        445: "smb",
        2049: "nfs",
    }
    
    # Industrial/OT protocols mapping, aligned with NetZones model
    industrial_mapping = {
        # Modbus
        502: "modbus_tcp",
        
        # OPC UA
        4840: "opcua",
        
        # MQTT
        1883: "mqtt",
        8883: "mqtt",  # MQTT over SSL
        
        # BACnet
        47808: "bacnet",
        
        # DNP3
        20000: "dnp3",
        
        # S7comm (Siemens)
        102: "s7comm",
        
        # IEC 104
        2404: "iec104",
        
        # IEC 61850
        102: "iec61850",  # Note: Same port as S7comm, context-dependent
        
        # Profinet
        34962: "profinet",
        34963: "profinet",
        34964: "profinet",
        
        # EtherCAT - typically uses raw Ethernet frames, but some implementations use these ports
        34980: "ethercat",
        88: "ethercat",  # Some EtherCAT over UDP implementations
    }
    
    # Additional industrial protocols for future expansion (not in current NetZones model)
    extended_industrial_mapping = {
        # Additional Modbus variants
        503: "modbus_tcp",  # Modbus over TCP (secure)
        
        # Additional OPC variants
        135: "opc_classic",  # OPC Classic DCOM
        
        # Additional SCADA protocols
        2222: "etherip",     # EtherNet/IP
        44818: "etherip",    # EtherNet/IP explicit messaging
        
        # Rockwell/Allen-Bradley
        2222: "cip",         # Common Industrial Protocol
        44818: "cip",
        
        # Schneider Electric
        502: "modbus_tcp",   # Schneider uses standard Modbus
        
        # GE protocols
        18245: "srtp",       # GE SRTP
        
        # Honeywell
        1962: "pcworx",      # Honeywell PCWorx
        
        # ABB protocols
        1089: "ff_hse",      # Foundation Fieldbus HSE
    }
    
    # Check industrial protocols first (higher priority for OT environments)
    if port in industrial_mapping:
        return industrial_mapping[port]
    
    # Check standard protocols
    if port in standard_mapping:
        return standard_mapping[port]
    
    # Check extended industrial protocols for potential future use
    if port in extended_industrial_mapping:
        return extended_industrial_mapping[port]
    
    # Fallback to port range-based detection for common scenarios
    if 20 <= port <= 21:
        return "ftp"
    elif 67 <= port <= 68:
        return "dhcp"
    elif port in [80, 8080, 8000, 8008]:
        return "http"
    elif port in [443, 8443, 8444]:
        return "https"
    elif 1024 <= port <= 5000:
        return "tcp"  # Likely custom TCP service
    elif 5000 <= port <= 32767:
        return "tcp"  # Registered port range
    elif port >= 32768:
        return "tcp"  # Dynamic/private port range
    
    # Default fallback to TCP
    return "tcp"

def get_protocol_info(port):
    """
    Retrieve detailed information about a protocol based on its port number.

    Args:
        port (int): Port number to analyze

    Returns:
        dict: Dictionary containing protocol name, description, and category
    """
    protocol = detect_protocol(port)
    
    # Comprehensive protocol information mapping
    protocol_info = {
        # Standard protocols
        "http": {"name": "HTTP", "description": "Hypertext Transfer Protocol", "category": "web"},
        "https": {"name": "HTTPS", "description": "HTTP Secure", "category": "web"},
        "ssh": {"name": "SSH", "description": "Secure Shell", "category": "remote"},
        "ftp": {"name": "FTP", "description": "File Transfer Protocol", "category": "file"},
        "dns": {"name": "DNS", "description": "Domain Name System", "category": "network"},
        "dhcp": {"name": "DHCP", "description": "Dynamic Host Configuration Protocol", "category": "network"},
        
        # Industrial protocols, aligned with NetZones model
        "modbus_tcp": {"name": "Modbus TCP", "description": "Modbus over TCP/IP", "category": "industrial"},
        "opcua": {"name": "OPC UA", "description": "OPC Unified Architecture", "category": "industrial"},
        "mqtt": {"name": "MQTT", "description": "Message Queuing Telemetry Transport", "category": "iot"},
        "bacnet": {"name": "BACnet", "description": "Building Automation and Control Networks", "category": "building"},
        "dnp3": {"name": "DNP3", "description": "Distributed Network Protocol v3", "category": "scada"},
        "s7comm": {"name": "S7comm", "description": "Siemens S7 Communication", "category": "industrial"},
        "iec104": {"name": "IEC 104", "description": "IEC 60870-5-104", "category": "scada"},
        "iec61850": {"name": "IEC 61850", "description": "Power Utility Automation", "category": "power"},
        "profinet": {"name": "PROFINET", "description": "Process Field Network", "category": "industrial"},
        "ethercat": {"name": "EtherCAT", "description": "Ethernet for Control Automation Technology", "category": "industrial"},
        
        # Generic fallback
        "tcp": {"name": "TCP", "description": "Transmission Control Protocol", "category": "network"},
        "udp": {"name": "UDP", "description": "User Datagram Protocol", "category": "network"},
        "icmp": {"name": "ICMP", "description": "Internet Control Message Protocol", "category": "network"}
    }
    
    return protocol_info.get(protocol, {
        "name": protocol.upper(),
        "description": f"Unknown protocol on port {port}",
        "category": "unknown"
    })

def is_industrial_protocol(port_or_protocol):
    """
    Check if a port or protocol is associated with industrial/OT systems.

    Args:
        port_or_protocol (int or str): Port number or protocol name

    Returns:
        bool: True if the protocol is industrial, False otherwise
    """
    if isinstance(port_or_protocol, int):
        protocol = detect_protocol(port_or_protocol)
    else:
        protocol = port_or_protocol.lower()
    
    # Set of industrial protocols defined in the NetZones model
    industrial_protocols = {
        "modbus_tcp", "opcua", "mqtt", "bacnet", "dnp3", 
        "s7comm", "iec104", "iec61850", "profinet", "ethercat"
    }
    
    return protocol in industrial_protocols

def get_protocol_risk_level(port_or_protocol):
    """
    Assess the security risk level of a protocol or port.

    Args:
        port_or_protocol (int or str): Port number or protocol name

    Returns:
        str: Risk level ("low", "medium", "high", "critical", or "unknown")
    """
    if isinstance(port_or_protocol, int):
        protocol = detect_protocol(port_or_protocol)
    else:
        protocol = port_or_protocol.lower()
    
    # Risk level mapping for protocols
    risk_levels = {
        # High risk - critical industrial protocols (unencrypted or sensitive)
        "modbus_tcp": "high",
        "dnp3": "high",
        "s7comm": "high",
        "iec104": "high",
        "iec61850": "critical",
        
        # Medium risk - industrial but more secure
        "opcua": "medium",
        "profinet": "medium",
        "ethercat": "medium",
        
        # Low-medium risk - IoT/building automation
        "mqtt": "medium",
        "bacnet": "low",
        
        # Standard protocols
        "https": "low",
        "ssh": "low",
        "http": "medium",
        "ftp": "high",  # Unencrypted
        "telnet": "critical",  # Unencrypted
        
        # Network protocols
        "dns": "low",
        "dhcp": "low",
        "tcp": "low",
        "udp": "low",
        "icmp": "low"
    }
    
    return risk_levels.get(protocol, "unknown")

# Example usage and testing
if __name__ == "__main__":
    # Test with ports relevant to the NetZones model
    test_ports = [80, 443, 22, 502, 4840, 1883, 8883, 47808, 20000, 102, 2404, 34962, 34963, 34964]
    
    print("=== Protocol Detection Test ===")
    for port in test_ports:
        protocol = detect_protocol(port)
        info = get_protocol_info(port)
        risk = get_protocol_risk_level(port)
        industrial = is_industrial_protocol(port)
        
        # Print formatted test results
        print(f"Port {port:5d}: {protocol:12s} | {info['name']:15s} | Risk: {risk:8s} | Industrial: {industrial}")
    
    print("\n=== Industrial Protocol Check ===")
    industrial_ports = [port for port in test_ports if is_industrial_protocol(port)]
    print(f"Industrial ports detected: {industrial_ports}")