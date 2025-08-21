from fastapi import FastAPI
from fastapi.responses import FileResponse
from pathlib import Path
from src.routes import health, rules
from src.utils.logger import logger

api = FastAPI(title="OPNsense Wrapper (Python)")

api.include_router(health.router)
api.include_router(rules.router)

SWAGGER_PATH = Path(__file__).resolve().parent / "swagger" / "openapi.yaml"

@api.get("/swagger.yaml", include_in_schema=False)
def swagger_file():
    return FileResponse(str(SWAGGER_PATH), media_type="text/yaml")

@api.get("/")
def root():
    return {"ok": True, "service": "opnsense-wrapper-python", "docs": "/docs", "swagger": "/swagger.yaml"}

logger.info("FastAPI avviata. Docs: /docs  |  Swagger YAML: /swagger.yaml")