from datetime import datetime
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field

class SystemStatus(BaseModel):
    """System status model"""
    timestamp: datetime
    hostname: str
    version: str
    uptime: str
    uptime_hours: float = 0.0
    cpu_usage: float = 0.0
    memory_usage: float = 0.0
    disk_usage: float = 0.0
    temperature: Optional[str] = None
    load_average: Optional[str] = None

class PerformanceMetrics(BaseModel):
    """Performance metrics model"""
    timestamp: datetime
    cpu: Dict[str, Any] = {}
    memory: Dict[str, Any] = {}
    disk: Dict[str, Any] = {}
    network: Dict[str, Any] = {}
    firewall: Dict[str, Any] = {}

class MonitoringAlert(BaseModel):
    """Monitoring alert model"""
    id: str
    timestamp: datetime
    severity: str = Field(..., regex="^(low|medium|high|critical)$")
    component: str
    message: str
    details: Dict[str, Any] = {}
    acknowledged: bool = False
    resolved: bool = False

class HealthCheck(BaseModel):
    """Health check result model"""
    timestamp: datetime
    status: str = Field(..., regex="^(healthy|degraded|unhealthy)$")
    components: Dict[str, str] = {}
    system: Dict[str, Any] = {}
    version: str = "1.0.0"

class NagiosCheck(BaseModel):
    """Nagios check result model"""
    status_code: int = Field(..., ge=0, le=3)  # 0=OK, 1=WARNING, 2=CRITICAL, 3=UNKNOWN
    status_text: str
    performance_data: str = ""
    timestamp: Optional[datetime] = None

class PRTGSensor(BaseModel):
    """PRTG sensor data model"""
    result: list = []
    error: Optional[int] = None
    text: Optional[str] = None

class PRTGChannel(BaseModel):
    """PRTG channel model"""
    channel: str
    value: float
    unit: str = "Count"
    limitmaxwarning: Optional[float] = None
    limitmaxerror: Optional[float] = None
    limitmode: Optional[int] = None