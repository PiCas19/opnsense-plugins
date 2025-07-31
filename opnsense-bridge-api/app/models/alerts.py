from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field

class AlertSeverity:
    """Alert severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class AlertStatus:
    """Alert status types"""
    ACTIVE = "active"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    SUPPRESSED = "suppressed"

class Alert(BaseModel):
    """Base alert model"""
    id: str
    timestamp: datetime
    severity: str = Field(..., regex="^(low|medium|high|critical)$")
    title: str
    description: str
    component: str
    source: str = "opnsense_bridge"
    status: str = Field("active", regex="^(active|acknowledged|resolved|suppressed)$")
    details: Dict[str, Any] = {}
    tags: List[str] = []

class SecurityAlert(Alert):
    """Security-specific alert model"""
    threat_type: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[str] = None
    attack_vector: Optional[str] = None
    risk_score: Optional[int] = Field(None, ge=0, le=100)

class SystemAlert(Alert):
    """System-specific alert model"""
    metric_name: str
    current_value: float
    threshold_value: float
    unit: Optional[str] = None

class EmergencyAlert(Alert):
    """Emergency operation alert model"""
    operation_id: str
    operation_type: str
    affected_resources: List[str] = []
    auto_resolved: bool = False

class NotificationChannel(BaseModel):
    """Notification channel configuration"""
    name: str
    type: str = Field(..., regex="^(email|slack|teams|webhook)$")
    enabled: bool = True
    config: Dict[str, Any] = {}
    severity_filter: List[str] = ["medium", "high", "critical"]

class NotificationMessage(BaseModel):
    """Notification message model"""
    id: str
    timestamp: datetime
    channel: str
    recipient: str
    subject: str
    message: str
    status: str = Field("pending", regex="^(pending|sent|failed|retrying)$")
    attempts: int = 0
    last_attempt: Optional[datetime] = None
    error_message: Optional[str] = None