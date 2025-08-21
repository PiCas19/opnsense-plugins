"""Health endpoints for the OPNsense Python wrapper.

This module exposes simple health probes:
- `/api/health`            : local liveness/readiness of this service
- `/api/health/opnsense`   : upstream reachability check against OPNsense
"""

from fastapi import APIRouter, HTTPException
from time import perf_counter
from src.opnsense.client import client
from src.opnsense.errors import HttpError
from src import config

router = APIRouter(prefix="/api/health", tags=["health"])

@router.get("")
def health_root():
    """Return basic service metadata to indicate the API is alive."""
    return {
        "ok": True,
        "service": "opnsense-wrapper-python",
        "docs": "/docs",
        "swagger": "/swagger.yaml"
    }

@router.get("/opnsense")
def health_opnsense():
    """Check OPNsense reachability by performing a minimal rules search.

    - Executes a very small `/firewall/filter/searchRule` request (rowCount=1).
    - Measures end-to-end latency in milliseconds and includes it in the response.
    - Exposes a few configuration hints (verify_ssl, base_url) to aid troubleshooting.

    Error handling:
    - Upstream 4xx errors are propagated with the same status code.
    - Upstream 5xx errors are mapped to HTTP 502 (Bad Gateway).
    - Any unexpected local error returns HTTP 500 with a short message.

    Returns:
        dict: A JSON payload with `ok`, `latency_ms`, and `details`.
    """
    t0 = perf_counter()
    try:
        # Minimal call just to assert reachability; avoid heavy payloads.
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
        # Convert upstream HTTP errors into API responses with useful context.
        # Map 5xx from upstream to 502 (Bad Gateway) on our side.
        latency = int((perf_counter() - t0) * 1000)
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