# src/routes/health.py
from fastapi import APIRouter, HTTPException
from time import perf_counter
from src.opnsense.client import client
from src.opnsense.errors import HttpError
from src import config

router = APIRouter(prefix="/api/health", tags=["health"])

@router.get("")
def health_root():
    return {
        "ok": True,
        "service": "opnsense-wrapper-python",
        "docs": "/docs",
        "swagger": "/swagger.yaml"
    }

@router.get("/opnsense")
def health_opnsense():
    """
    Verifica la raggiungibilità di OPNsense eseguendo una search minimale sulle regole.
    Misura la latenza ed espone qualche metadato utile al troubleshooting.
    """
    t0 = perf_counter()
    try:
        res = client.search_rules(search_phrase="", row_count=1)
        latency = int((perf_counter() - t0) * 1000)
        return {
            "ok": True,
            "upstream": "opnsense",
            "latency_ms": latency,
            "details": {
                "total_rules": res.get("total", None),
                "verify_ssl": config.OPNSENSE_VERIFY_SSL,
                "base_url": config.OPNSENSE_URL
            }
        }
    except HttpError as e:
        latency = int((perf_counter() - t0) * 1000)
        # Mappa i 5xx upstream a 502 Bad Gateway
        status = 502 if e.status >= 500 else e.status
        raise HTTPException(
            status_code=status,
            detail={
                "ok": False,
                "latency_ms": latency,
                "upstream_status": e.status,
                "upstream_url": e.url,
                "body": e.body
            }
        )
    except Exception as e:
        latency = int((perf_counter() - t0) * 1000)
        raise HTTPException(
            status_code=500,
            detail={"ok": False, "latency_ms": latency, "error": str(e)}
        )