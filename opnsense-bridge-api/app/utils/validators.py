import ipaddress
from typing import Any, Dict, List

def validate_ip_address(ip: str) -> bool:
    """Validate IP address format"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def validate_ip_network(network: str) -> bool:
    """Validate IP network format (CIDR)"""
    try:
        ipaddress.ip_network(network, strict=False)
        return True
    except ValueError:
        return False

def validate_request_data(data: Dict[str, Any], required_fields: List[str]) -> bool:
    """Validate request data has required fields"""
    if not isinstance(data, dict):
        return False
    
    return all(field in data and data[field] is not None for field in required_fields)

def validate_port_number(port: Any) -> bool:
    """Validate port number"""
    try:
        port_num = int(port)
        return 1 <= port_num <= 65535
    except (ValueError, TypeError):
        return False

def validate_rule_uuid(uuid: str) -> bool:
    """Validate firewall rule UUID format"""
    if not isinstance(uuid, str):
        return False
    
    # Basic UUID validation
    return len(uuid) > 0 and len(uuid) <= 64