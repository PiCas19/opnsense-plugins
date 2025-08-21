from __future__ import annotations
import os

# Base URL deve terminare con /api (es: https://192.168.1.1/api)
OPNSENSE_URL = os.getenv("OPNSENSE_URL", "").rstrip("/")
if not OPNSENSE_URL.endswith("/api"):
    raise RuntimeError("OPNSENSE_URL deve terminare con /api (es: https://fw/api)")

OPNSENSE_KEY = os.getenv("OPNSENSE_KEY", "")
OPNSENSE_SECRET = os.getenv("OPNSENSE_SECRET", "")
if not OPNSENSE_KEY or not OPNSENSE_SECRET:
    raise RuntimeError("OPNSENSE_KEY/OPNSENSE_SECRET mancanti")

OPNSENSE_VERIFY_SSL = os.getenv("OPNSENSE_VERIFY_SSL", "true").lower() == "true"
OPNSENSE_TIMEOUT = int(os.getenv("OPNSENSE_TIMEOUT", "10"))

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
PORT = int(os.getenv("PORT", "8080"))