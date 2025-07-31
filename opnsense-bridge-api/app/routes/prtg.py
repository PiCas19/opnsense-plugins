import logging
from fastapi import APIRouter

from app.services.opnsense_client import get_opnsense_client
from app.services.monitoring import MonitoringService

logger = logging.getLogger(__name__)
router = APIRouter()

monitoring_service = MonitoringService()

@router.get("/firewall-statistics")
async def prtg_firewall_statistics():
    """PRTG-compatible XML sensor for firewall statistics"""
    try:
        client = await get_opnsense_client()
        
        async with client:
            rules = await client.get_active_firewall_rules()
            logs = await client.get_firewall_logs(limit=100, filter_blocked=True)
            
            # Calculate statistics
            total_rules = len(rules)
            security_rules = len([r for r in rules if r.get("action") in ["block", "reject"]])
            recent_blocks = len(logs)
            
            # PRTG XML format
            prtg_data = {
                "result": [
                    {
                        "channel": "Active Firewall Rules",
                        "value": total_rules,
                        "unit": "Count"
                    },
                    {
                        "channel": "Security Rules",
                        "value": security_rules,
                        "unit": "Count"
                    },
                    {
                        "channel": "Recent Blocks",
                        "value": recent_blocks,
                        "unit": "Count"
                    }
                ]
            }
            
            return {"prtg": prtg_data}
    except Exception as e:
        return {
            "prtg": {
                "error": 1,
                "text": f"Error: {str(e)}"
            }
        }

@router.get("/system-performance")
async def prtg_system_performance():
    """PRTG system performance metrics"""
    try:
        client = await get_opnsense_client()
        
        async with client:
            system_status = await client.get_system_status()
            
            cpu_usage = monitoring_service.calculate_cpu_usage(system_status)
            memory_usage = monitoring_service.calculate_memory_usage(system_status)
            uptime_hours = monitoring_service.parse_uptime(system_status.get("uptime", "0"))
            
            prtg_data = {
                "result": [
                    {
                        "channel": "CPU Usage",
                        "value": cpu_usage,
                        "unit": "Percent",
                        "limitmaxwarning": 80,
                        "limitmaxerror": 95
                    },
                    {
                        "channel": "Memory Usage",
                        "value": memory_usage,
                        "unit": "Percent",
                        "limitmaxwarning": 85,
                        "limitmaxerror": 95
                    },
                    {
                        "channel": "Uptime",
                        "value": uptime_hours,
                        "unit": "TimeHours"
                    }
                ]
            }
            
            return {"prtg": prtg_data}
    except Exception as e:
        return {
            "prtg": {
                "error": 1,
                "text": f"Error: {str(e)}"
            }
        }
