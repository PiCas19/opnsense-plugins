# tests/conftest.py
import os
import sys
from pathlib import Path
import importlib
import pytest
from fastapi.testclient import TestClient

# assicura che 'src' sia importabile
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# valori di default per i test
DEFAULT_ENV = {
    "OPNSENSE_URL": "https://opn.local/api",
    "OPNSENSE_KEY": "TESTKEY1234",
    "OPNSENSE_SECRET": "TESTSECRET5678",
    "OPNSENSE_VERIFY_SSL": "false",
    "OPNSENSE_TIMEOUT": "5",
    "LOG_LEVEL": "DEBUG",
    "PORT": "8080",
}

@pytest.fixture(autouse=True)
def _env(monkeypatch):
    # applica env per ogni test PRIMA degli import dei moduli src.*
    for k, v in DEFAULT_ENV.items():
        monkeypatch.setenv(k, v)
    # ricarica config e client con le nuove env pulite
    if "src.config" in sys.modules:
        importlib.reload(sys.modules["src.config"])
    if "src.opnsense.client" in sys.modules:
        importlib.reload(sys.modules["src.opnsense.client"])
    yield

@pytest.fixture(scope="session")
def app():
    # importa l'app FastAPI
    from src.app import api
    return api

@pytest.fixture
def client(app):
    return TestClient(app)

# respx mock globale per comoda patch delle request verso OPNsense
@pytest.fixture
def respx_mock_global(respx_mock):
    yield respx_mock
