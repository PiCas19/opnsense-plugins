from fastapi import FastAPI
from src.routes import auth, proxy_rules
from src.utils.logger import logger

api = FastAPI(title="DMZ BFF for OPNsense")

api.include_router(auth.router)
api.include_router(proxy_rules.router)

logger.info("DMZ FastAPI started. UI served by NGINX. API under /api/*")