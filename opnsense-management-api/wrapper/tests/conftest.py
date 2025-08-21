# tests/conftest.py
import os
import sys
import importlib
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

# --- assicurati che 'src' sia importabile ---
ROOT = Path(__file__).resolve().parents[1]  # -> <repo>/wrapper
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# --- set ENV SUBITO (prima della collection) ---
DEFAULT_ENV = {
    "OPNSENSE_URL": "https://opn.local/api",
    "OPNSENSE_KEY": "TESTKEY1234",
    "OPNSENSE_SECRET": "TESTSECRET5678",
    "OPNSENSE_VERIFY_SSL": "false",
    "OPNSENSE_TIMEOUT": "5",
    "LOG_LEVEL": "DEBUG",
    "PORT": "8080",
}
for k, v in DEFAULT_ENV.items():
    os.environ.setdefault(k, v)

@pytest.fixture(autouse=True)
def _env(monkeypatch):
    # riaffermiamo le env per ogni test e ricarichiamo moduli
    for k, v in DEFAULT_ENV.items():
        monkeypatch.setenv(k, v)

    # ricarica config e client se già importati
    if "src.config" in sys.modules:
        importlib.reload(sys.modules["src.config"])
    if "src.opnsense.client" in sys.modules:
        importlib.reload(sys.modules["src.opnsense.client"])
    yield

@pytest.fixture(scope="session")
def app():
    from src.app import api
    return api

@pytest.fixture
def client(app):
    return TestClient(app)

# respx fornisce la fixture 'respx_mock'; la “ri-esponiamo” col nome che usano i test
@pytest.fixture
def respx_mock_global(respx_mock):
    yield respx_mock
