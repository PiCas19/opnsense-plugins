import re
import ipaddress
import hashlib
import secrets
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone

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

def sanitize_description(description: str) -> str:
    """Sanitize description for firewall rules"""
    # Remove potentially dangerous characters
    sanitized = re.sub(r'[<>"\';]', '', description)
    # Limit length
    return sanitized[:255]

def format_timestamp(dt: Optional[datetime] = None) -> str:
    """Format timestamp for consistent output"""
    if dt is None:
        dt = datetime.now(timezone.utc)
    return dt.isoformat() + "Z"

def parse_duration_to_seconds(duration: str) -> int:
    """Parse duration string to seconds"""
    # Examples: "1h", "30m", "24h", "1d"
    try:
        if duration.endswith('s'):
            return int(duration[:-1])
        elif duration.endswith('m'):
            return int(duration[:-1]) * 60
        elif duration.endswith('h'):
            return int(duration[:-1]) * 3600
        elif duration.endswith('d'):
            return int(duration[:-1]) * 86400
        else:
            return int(duration)  # Assume seconds
    except ValueError:
        return 3600  # Default to 1 hour

def extract_numeric_value(value: Any) -> float:
    """Extract numeric value from various formats"""
    try:
        if isinstance(value, (int, float)):
            return float(value)
        elif isinstance(value, str):
            # Remove % and other non-numeric characters
            numeric_str = ''.join(c for c in value if c.isdigit() or c == '.')
            return float(numeric_str) if numeric_str else 0.0
        elif isinstance(value, dict):
            # Try common keys
            for key in ["usage", "percent", "value", "used"]:
                if key in value:
                    return extract_numeric_value(value[key])
            return 0.0
        else:
            return 0.0
    except (ValueError, TypeError):
        return 0.0

def create_operation_id(prefix: str = "op") -> str:
    """Create unique operation ID"""
    timestamp = int(datetime.now(timezone.utc).timestamp())
    random_suffix = secrets.token_hex(4)
    return f"{prefix}_{timestamp}_{random_suffix}"

def mask_sensitive_data(data: Dict[str, Any], sensitive_keys: List[str] = None) -> Dict[str, Any]:
    """Mask sensitive data in dictionary"""
    if sensitive_keys is None:
        sensitive_keys = ["password", "secret", "key", "token", "auth"]
    
    masked_data = data.copy()
    
    for key, value in masked_data.items():
        if any(sensitive_key in key.lower() for sensitive_key in sensitive_keys):
            if isinstance(value, str) and len(value) > 4:
                masked_data[key] = value[:2] + "*" * (len(value) - 4) + value[-2:]
            else:
                masked_data[key] = "****"
        elif isinstance(value, dict):
            masked_data[key] = mask_sensitive_data(value, sensitive_keys)
    
    return masked_data

def generate_rule_hash(rule_data: Dict[str, Any]) -> str:
    """Generate hash for firewall rule"""
    # Create consistent string from rule data
    rule_string = f"{rule_data.get('action', '')}{rule_data.get('source_net', '')}{rule_data.get('destination_net', '')}{rule_data.get('destination_port', '')}"
    return hashlib.md5(rule_string.encode()).hexdigest()[:8]

def parse_uptime_string(uptime_str: str) -> Dict[str, int]:
    """Parse uptime string to components"""
    try:
        components = {"days": 0, "hours": 0, "minutes": 0}
        
        # Extract days
        day_match = re.search(r'(\d+)\s*day', uptime_str)
        if day_match:
            components["days"] = int(day_match.group(1))
        
        # Extract hours
        hour_match = re.search(r'(\d+)\s*hour', uptime_str)
        if hour_match:
            components["hours"] = int(hour_match.group(1))
        
        # Extract minutes
        minute_match = re.search(r'(\d+)\s*minute', uptime_str)
        if minute_match:
            components["minutes"] = int(minute_match.group(1))
        
        return components
    except:
        return {"days": 0, "hours": 0, "minutes": 0}

def calculate_percentage(part: float, total: float) -> float:
    """Calculate percentage safely"""
    if total == 0:
        return 0.0
    return (part / total) * 100.0

def truncate_string(text: str, max_length: int = 100) -> str:
    """Truncate string to max length"""
    if len(text) <= max_length:
        return text
    return text[:max_length-3] + "..."

def is_private_ip(ip: str) -> bool:
    """Check if IP is private"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False

def format_bytes(bytes_value: int) -> str:
    """Format bytes to human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.1f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.1f} PB"