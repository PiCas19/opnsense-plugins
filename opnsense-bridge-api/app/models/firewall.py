from datetime import datetime
from typing import Optional, Dict
from pydantic import BaseModel, Field, validator

class FirewallRule(BaseModel):
    """Firewall rule model"""
    uuid: Optional[str] = None
    enabled: str = Field(..., regex="^[01]$")
    interface: str = Field(..., min_length=1)
    direction: str = Field("in", regex="^(in|out)$")
    action: str = Field(..., regex="^(pass|block|reject)$")
    protocol: Optional[str] = "any"
    source_net: Optional[str] = "any"
    source_port: Optional[str] = "any"
    destination_net: Optional[str] = "any"
    destination_port: Optional[str] = "any"
    description: Optional[str] = ""
    log: str = Field("0", regex="^[01]$")
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    
    @validator('description')
    def sanitize_description(cls, v):
        if v:
            # Remove potentially dangerous characters
            import re
            return re.sub(r'[<>"\';]', '', v)[:255]
        return v

class FirewallRuleCreate(BaseModel):
    """Model for creating firewall rules"""
    enabled: str = Field("1", regex="^[01]$")
    interface: str = Field(..., min_length=1)
    direction: str = Field("in", regex="^(in|out)$")
    action: str = Field(..., regex="^(pass|block|reject)$")
    protocol: Optional[str] = "any"
    source_net: Optional[str] = "any"
    source_port: Optional[str] = "any"
    destination_net: Optional[str] = "any"
    destination_port: Optional[str] = "any"
    description: Optional[str] = ""
    log: str = Field("0", regex="^[01]$")

class FirewallRuleUpdate(BaseModel):
    """Model for updating firewall rules"""
    enabled: Optional[str] = Field(None, regex="^[01]$")
    interface: Optional[str] = None
    direction: Optional[str] = Field(None, regex="^(in|out)$")
    action: Optional[str] = Field(None, regex="^(pass|block|reject)$")
    protocol: Optional[str] = None
    source_net: Optional[str] = None
    source_port: Optional[str] = None
    destination_net: Optional[str] = None
    destination_port: Optional[str] = None
    description: Optional[str] = None
    log: Optional[str] = Field(None, regex="^[01]$")

class FirewallLog(BaseModel):
    """Firewall log entry model"""
    timestamp: datetime
    interface: str
    action: str
    protocol: str
    source_ip: str
    source_port: Optional[str] = None
    destination_ip: str
    destination_port: Optional[str] = None
    length: Optional[int] = None
    flags: Optional[str] = None
    rule_number: Optional[int] = None
    rule_description: Optional[str] = None

class FirewallStats(BaseModel):
    """Firewall statistics model"""
    timestamp: datetime
    total_rules: int
    active_rules: int
    inactive_rules: int
    by_action: Dict[str, int] = {}
    by_interface: Dict[str, int] = {}
    by_protocol: Dict[str, int] = {}
    performance_score: float = 0.0