from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field

class ThreatType:
    """Threat type constants"""
    PORT_SCAN = "port_scan"
    BRUTE_FORCE = "brute_force"
    DDOS = "ddos"
    MALWARE = "malware"
    INTRUSION = "intrusion"
    RECONNAISSANCE = "reconnaissance"
    EXPLOITATION = "exploitation"

class ThreatSeverity:
    """Threat severity levels"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ThreatIndicator(BaseModel):
    """Threat indicator model"""
    id: str
    timestamp: datetime
    type: str
    value: str
    source: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    description: Optional[str] = None
    tags: List[str] = []
    ttl: Optional[datetime] = None  # Time to live

class ThreatEvent(BaseModel):
    """Threat event model"""
    id: str
    timestamp: datetime
    threat_type: str
    severity: str = Field(..., regex="^(info|low|medium|high|critical)$")
    source_ip: str
    destination_ip: Optional[str] = None
    destination_port: Optional[str] = None
    protocol: Optional[str] = None
    attack_vector: Optional[str] = None
    indicators: List[str] = []  # List of indicator IDs
    raw_data: Dict[str, Any] = {}
    processed: bool = False
    blocked: bool = False

class ThreatPattern(BaseModel):
    """Threat pattern model"""
    pattern_id: str
    name: str
    description: str
    pattern_type: str
    rules: List[Dict[str, Any]] = []
    threshold: int = 1
    time_window: int = 3600  # seconds
    severity: str = Field(..., regex="^(info|low|medium|high|critical)$")
    enabled: bool = True
    last_triggered: Optional[datetime] = None

class RiskAssessment(BaseModel):
    """Risk assessment model"""
    timestamp: datetime
    overall_score: int = Field(..., ge=0, le=100)
    categories: Dict[str, int] = {}
    threats_detected: int = 0
    unique_sources: int = 0
    blocked_attempts: int = 0
    recommendations: List[str] = []

class EmergencyResponse(BaseModel):
    """Emergency response model"""
    operation_id: str
    timestamp: datetime
    trigger_event: str
    response_type: str = Field(..., regex="^(block_ip|bulk_block|toggle_rule|isolate_network)$")
    target: str  # IP, rule UUID, network, etc.
    reason: str
    status: str = Field("pending", regex="^(pending|in_progress|completed|failed)$")
    result: Optional[Dict[str, Any]] = None
    auto_generated: bool = True
    operator: Optional[str] = None

class BlockedIP(BaseModel):
    """Blocked IP model"""
    ip_address: str
    timestamp: datetime
    reason: str
    rule_uuid: Optional[str] = None
    block_duration: Optional[int] = None  # seconds
    source_event_id: Optional[str] = None
    auto_blocked: bool = True
    expires_at: Optional[datetime] = None
    active: bool = True

class ThreatIntelligence(BaseModel):
    """Threat intelligence model"""
    timestamp: datetime
    analysis_period_hours: int = 24
    total_events: int = 0
    unique_sources: int = 0
    threat_breakdown: Dict[str, int] = {}
    top_sources: List[Dict[str, Any]] = []
    patterns_detected: List[str] = []
    risk_score: int = Field(..., ge=0, le=100)
    recommendations: List[str] = []