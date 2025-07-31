import logging
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException

from app.services.opnsense_client import get_opnsense_client
from app.services.statistics import StatisticsService

logger = logging.getLogger(__name__)
router = APIRouter()

statistics_service = StatisticsService()

@router.get("/rules")
async def get_firewall_rules():
    """Get all firewall rules (active and inactive)"""
    try:
        client = await get_opnsense_client()
        
        async with client:
            all_rules = await client.get_all_firewall_rules()
            active_rules = [r for r in all_rules if r.get("enabled") == "1"]
            inactive_rules = [r for r in all_rules if r.get("enabled") != "1"]
            
            return {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "total_rules": len(all_rules),
                "active_rules": len(active_rules),
                "inactive_rules": len(inactive_rules),
                "rules": {
                    "active": active_rules,
                    "inactive": inactive_rules
                }
            }
    except Exception as e:
        logger.error(f"Get firewall rules failed: {e}")
        raise HTTPException(status_code=503, detail=f"Failed to get rules: {str(e)}")

@router.get("/rules/active")
async def get_active_firewall_rules():
    """Get only active firewall rules"""
    try:
        client = await get_opnsense_client()
        
        async with client:
            active_rules = await client.get_active_firewall_rules()
            
            return {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "total_active_rules": len(active_rules),
                "rules": active_rules
            }
    except Exception as e:
        logger.error(f"Get active firewall rules failed: {e}")
        raise HTTPException(status_code=503, detail=f"Failed to get active rules: {str(e)}")
    
@router.get("/statistics")
async def get_firewall_statistics():
    """Get firewall statistics"""
    try:
        client = await get_opnsense_client()
        
        async with client:
            all_rules = await client.get_all_firewall_rules()
            stats = statistics_service.calculate_firewall_stats(all_rules)
            
            return {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                **stats
            }
    except Exception as e:
        logger.error(f"Get firewall statistics failed: {e}")
        raise HTTPException(status_code=503, detail=f"Failed to get statistics: {str(e)}")

@router.get("/logs")
async def get_firewall_logs(limit: int = 100, filter_blocked: bool = False):
    """Get firewall logs"""
    try:
        client = await get_opnsense_client()
        
        async with client:
            logs = await client.get_firewall_logs(limit=limit, filter_blocked=filter_blocked)
            
            return {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "total_logs": len(logs),
                "filter_blocked": filter_blocked,
                "logs": logs
            }
    except Exception as e:
        logger.error(f"Get firewall logs failed: {e}")
        raise HTTPException(status_code=503, detail=f"Failed to get logs: {str(e)}")