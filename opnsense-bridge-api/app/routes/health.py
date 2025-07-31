import logging
from datetime import datetime, timezone
from fastapi import APIRouter
from fastapi.responses import JSONResponse

from app.services.opnsense_client import test_opnsense_connection

logger = logging.getLogger(__name__)
router = APIRouter()

@router.get("/health")
async def basic_health():
    """Basic health check for load balancers"""
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "service": "OPNsense Monitoring Bridge",
        "version": "1.0.0"
    }

@router.get("/health/detailed")
async def detailed_health():
    """Detailed health check with all system components"""
    try:
        # Test OPNsense connectivity
        opnsense_healthy = await test_opnsense_connection()
        
        # Get system metrics
        import psutil
        system_health = {
            "cpu_percent": psutil.cpu_percent(interval=1),
            "memory_percent": psutil.virtual_memory().percent,
            "disk_percent": psutil.disk_usage('/').percent,
            "uptime_seconds": (datetime.now() - datetime.fromtimestamp(psutil.boot_time())).total_seconds()
        }
        
        # Overall status
        overall_status = "healthy" if opnsense_healthy else "degraded"
        
        return {
            "status": overall_status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "components": {
                "opnsense_api": "healthy" if opnsense_healthy else "unhealthy",
                "monitoring_service": "healthy",
                "cyber_defense": "healthy"
            },
            "system": system_health,
            "version": "1.0.0"
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return JSONResponse(
            status_code=503,
            content={
                "status": "unhealthy",
                "error": str(e),
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        )