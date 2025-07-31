import logging
from fastapi import APIRouter

from app.services.opnsense_client import get_opnsense_client
from app.services.monitoring import MonitoringService

logger = logging.getLogger(__name__)
router = APIRouter()

monitoring_service = MonitoringService()

@router.get("/firewall-rules")
async def nagios_check_firewall_rules(warning: int = 5, critical: int = 2):
    """Nagios-compatible firewall rules check"""
    try:
        client = await get_opnsense_client()
        
        async with client:
            rules = await client.get_active_firewall_rules()
            rules_count = len(rules)
            
            # Determine Nagios status
            if rules_count <= critical:
                status_code = 2  # CRITICAL
                status_text = f"CRITICAL: Only {rules_count} active firewall rules"
            elif rules_count <= warning:
                status_code = 1  # WARNING
                status_text = f"WARNING: Only {rules_count} active firewall rules"
            else:
                status_code = 0  # OK
                status_text = f"OK: {rules_count} active firewall rules"
            
            performance_data = f"active_rules={rules_count};{warning};{critical};0;"
            
            return {
                "status_code": status_code,
                "status_text": status_text,
                "performance_data": performance_data
            }
    except Exception as e:
        return {
            "status_code": 3,  # UNKNOWN
            "status_text": f"UNKNOWN: {str(e)}",
            "performance_data": ""
        }

@router.get("/system-health")
async def nagios_system_health(
    cpu_warning: float = 80.0,
    cpu_critical: float = 95.0,
    memory_warning: float = 85.0,
    memory_critical: float = 95.0
):
    """Nagios-compatible system health check"""
    try:
        client = await get_opnsense_client()
        
        async with client:
            system_status = await client.get_system_status()
            
            cpu_usage = monitoring_service.calculate_cpu_usage(system_status)
            memory_usage = monitoring_service.calculate_memory_usage(system_status)
            
            # Determine status
            status_code = 0
            status_messages = []
            
            # Check CPU
            if cpu_usage >= cpu_critical:
                status_code = max(status_code, 2)
                status_messages.append(f"CPU {cpu_usage:.1f}% (CRITICAL)")
            elif cpu_usage >= cpu_warning:
                status_code = max(status_code, 1)
                status_messages.append(f"CPU {cpu_usage:.1f}% (WARNING)")
            else:
                status_messages.append(f"CPU {cpu_usage:.1f}% (OK)")
            
            # Check Memory
            if memory_usage >= memory_critical:
                status_code = max(status_code, 2)
                status_messages.append(f"Memory {memory_usage:.1f}% (CRITICAL)")
            elif memory_usage >= memory_warning:
                status_code = max(status_code, 1)
                status_messages.append(f"Memory {memory_usage:.1f}% (WARNING)")
            else:
                status_messages.append(f"Memory {memory_usage:.1f}% (OK)")
            
            # Create status text
            if status_code == 0:
                status_text = "OK: " + ", ".join(status_messages)
            elif status_code == 1:
                status_text = "WARNING: " + ", ".join(status_messages)
            else:
                status_text = "CRITICAL: " + ", ".join(status_messages)
            
            performance_data = f"cpu_usage={cpu_usage:.1f}%;{cpu_warning};{cpu_critical};0;100 memory_usage={memory_usage:.1f}%;{memory_warning};{memory_critical};0;100"
            
            return {
                "status_code": status_code,
                "status_text": status_text,
                "performance_data": performance_data
            }
    except Exception as e:
        return {
            "status_code": 3,
            "status_text": f"UNKNOWN: System health check failed - {str(e)}",
            "performance_data": ""
        }