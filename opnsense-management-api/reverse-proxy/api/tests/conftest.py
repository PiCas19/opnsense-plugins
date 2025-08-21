# tests/conftest.py
import os, sys, importlib
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

# assicura import "src"
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

DEFAULT_ENV = {
    "DMZ_HOST": "0.0.0.0",
    "DMZ_PORT": "8000",
    "LOG_LEVEL": "DEBUG",
    "DEMO_USERNAME": "admin",
    "DEMO_PASSWORD": "changeme",
    "JWT_SECRET": "test_secret",
    "JWT_EXPIRE_MINUTES": "1",
    "JWT_REFRESH_SECRET": "test_refresh_secret",
    "JWT_REFRESH_EXPIRE_DAYS": "7",
    "WRAPPER_BASE_URL": "http://wrapper.local/api",
    "WRAPPER_VERIFY_SSL": "false",
    "WRAPPER_TIMEOUT": "2",
}

@pytest.fixture(autouse=True)
def _env(monkeypatch):
    for k, v in DEFAULT_ENV.items():
        monkeypatch.setenv(k, v)
    # reload dei moduli che leggono ENV a import-time
    for m in ["src.config", "src.utils.security"]:
        if m in sys.modules:
            importlib.reload(sys.modules[m])
    yield

@pytest.fixture(scope="session")
def app():
    from src.app import api
    return api

@pytest.fixture
def client(app):
    return TestClient(app)