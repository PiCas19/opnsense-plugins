import logging
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException

from app.services.opnsense_client import get_opnsense_client
from app.services.monitoring import MonitoringService
from app.services.statistics import StatisticsService

logger = logging.getLogger(__name__)
router = APIRouter()

monitoring_service = MonitoringService()
statistics_service = StatisticsService()

@router.get("/status")
async def get_monitoring_status():
    """Get comprehensive monitoring status for dashboards"""
    try:
        client = await get_opnsense_client()
        
        async with client:
            # Get system status
            system_status = await client.get_system_status()
            
            # Get active rules
            rules = await client.get_active_firewall_rules()
            
            # Calculate metrics
            performance_data = {
                "active_rules_count": len(rules),
                "security_rules": len([r for r in rules if "block" in r.get("action", "").lower()]),
                "system_uptime_hours": monitoring_service.parse_uptime(system_status.get("uptime", "0")),
                "memory_usage_percent": monitoring_service.calculate_memory_usage(system_status),
                "cpu_usage_percent": monitoring_service.calculate_cpu_usage(system_status)
            }
            
            return {
                "status": "operational",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "opnsense_version": system_status.get("version", "unknown"),
                "hostname": system_status.get("hostname", "unknown"),
                "performance_data": performance_data,
                "firewall_stats": {
                    "total_active_rules": len(rules),
                    "pass_rules": len([r for r in rules if r.get("action") == "pass"]),
                    "block_rules": len([r for r in rules if r.get("action") == "block"]),
                    "interfaces": list(set(r.get("interface", "") for r in rules))
                }
            }
    except Exception as e:
        logger.error(f"Monitoring status failed: {e}")
        raise HTTPException(status_code=503, detail=f"Monitoring failed: {str(e)}")

@router.get("/system-stats")
async def get_system_statistics():
    """Get system statistics and performance data"""
    try:
        client = await get_opnsense_client()
        
        async with client:
            system_status = await client.get_system_status()
            stats = statistics_service.calculate_system_performance_stats(system_status)
            
            return stats
    except Exception as e:
        logger.error(f"Get system stats failed: {e}")
        raise HTTPException(status_code=503, detail=f"Failed to get stats: {str(e)}")

@router.get("/performance")
async def get_performance_metrics():
    """Get performance metrics for monitoring systems"""
    try:
        client = await get_opnsense_client()
        
        async with client:
            system_status = await client.get_system_status()
            rules = await client.get_active_firewall_rules()
            
            # Calculate performance metrics
            firewall_performance = monitoring_service.analyze_firewall_performance(rules)
            system_performance = statistics_service.calculate_system_performance_stats(system_status)
            
            return {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "firewall": firewall_performance,
                "system": system_performance
            }
    except Exception as e:
        logger.error(f"Get performance metrics failed: {e}")
        raise HTTPException(status_code=503, detail=f"Failed to get performance: {str(e)}")