# tests/conftest.py
import os
import sys
import importlib
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

# Assicuro che "src" sia importabile
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# ENV di default per la DMZ app
DEFAULT_ENV = {
    "DMZ_HOST": "0.0.0.0",
    "DMZ_PORT": "8000",
    "LOG_LEVEL": "DEBUG",

    "DEMO_USERNAME": "admin",
    "DEMO_PASSWORD": "changeme",

    "JWT_SECRET": "test_access_secret",
    "JWT_EXPIRE_MINUTES": "1",
    "JWT_REFRESH_SECRET": "test_refresh_secret",
    "JWT_REFRESH_EXPIRE_DAYS": "7",

    # il validator forza il suffisso /api se manca
    "WRAPPER_BASE_URL": "http://opn-wrapper.local/api",
    "WRAPPER_VERIFY_SSL": "false",
    "WRAPPER_TIMEOUT": "5",
}

@pytest.fixture(autouse=True)
def _env(monkeypatch):
    for k, v in DEFAULT_ENV.items():
        monkeypatch.setenv(k, v)

    # Ricarico i moduli che leggono ENV a import-time
    for mod in (
        "src.config",
        "src.utils.security",
        "src.routes.auth",
        "src.routes.proxy_rules",
        "src.app",
    ):
        if mod in sys.modules:
            importlib.reload(sys.modules[mod])
    yield

@pytest.fixture(scope="session")
def app():
    from src.app import api
    return api

@pytest.fixture
def client(app):
    from src.routes.proxy_rules import get_current_user
    # bypass JWT nelle route proxy
    app.dependency_overrides[get_current_user] = lambda: "test-user"
    return TestClient(app)
