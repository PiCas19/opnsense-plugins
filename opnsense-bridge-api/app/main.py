import logging
import sys
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST

# Internal imports
from app.config import get_settings
from app.services.opnsense_client import test_opnsense_connection
from app.middleware.security import SecurityMiddleware
from app.middleware.logging import LoggingMiddleware
from app.middleware.rate_limiting import RateLimitMiddleware
from app.middleware.authentication import AuthenticationMiddleware

# Route imports
from app.routes import health, monitoring, nagios, prtg, emergency, firewall

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('/app/logs/bridge.log')
    ]
)
logger = logging.getLogger(__name__)

settings = get_settings()

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle management"""
    logger.info("Starting OPNsense Monitoring Bridge")
    
    # Test OPNsense connectivity
    if not await test_opnsense_connection():
        logger.error("Cannot connect to OPNsense API")
        if not settings.allow_startup_without_opnsense:
            sys.exit(1)
    else:
        logger.info("OPNsense API connection successful")
    
    logger.info("All services initialized")
    yield
    
    logger.info("Shutting down OPNsense Monitoring Bridge")

# Create FastAPI application
app = FastAPI(
    title="OPNsense Monitoring Bridge",
    description="API REST bridge per sistemi di monitoraggio",
    version="1.0.0",
    docs_url="/docs" if settings.debug else None,
    redoc_url="/redoc" if settings.debug else None,
    lifespan=lifespan
)

# Add middleware
app.add_middleware(SecurityMiddleware)
app.add_middleware(LoggingMiddleware)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(AuthenticationMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)

# Include routers
app.include_router(health.router, prefix="", tags=["Health"])
app.include_router(monitoring.router, prefix="/monitoring", tags=["Monitoring"])
app.include_router(nagios.router, prefix="/nagios", tags=["Nagios"])
app.include_router(prtg.router, prefix="/prtg", tags=["PRTG"])
app.include_router(emergency.router, prefix="/emergency", tags=["Emergency"])
app.include_router(firewall.router, prefix="/firewall", tags=["Firewall"])

# Metrics endpoint
@app.get("/metrics")
async def prometheus_metrics():
    """Prometheus metrics endpoint"""
    from fastapi import Response
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

# Root endpoint
@app.get("/")
async def root():
    """Root endpoint with service information"""
    return {
        "service": "OPNsense Monitoring Bridge",
        "version": "1.0.0", 
        "status": "OPERATIONAL",
        "description": "API REST bridge per sistemi di monitoraggio",
        "features": [
            "Native OPNsense API Integration",
            "Nagios/PRTG Monitoring",
            "Emergency Cyber Defense",
            "Prometheus Metrics",
            "Real-time Data"
        ],
        "endpoints": {
            "health": "/health",
            "monitoring": "/monitoring/*",
            "nagios": "/nagios/*",
            "prtg": "/prtg/*", 
            "emergency": "/emergency/*",
            "firewall": "/firewall/*",
            "metrics": "/metrics"
        }
    }

if __name__ == "__main__":
    print("OPNSENSE MONITORING BRIDGE STARTING")
    
    uvicorn.run(
        "app.main:app",
        host=settings.bridge_host,
        port=settings.bridge_port,
        ssl_keyfile="/app/certs/server.key" if settings.use_ssl else None,
        ssl_certfile="/app/certs/server.crt" if settings.use_ssl else None,
        reload=settings.debug,
        log_level="info"
    )