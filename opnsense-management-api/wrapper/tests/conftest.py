# tests/conftest.py
import os
import sys
from pathlib import Path
import importlib
import pytest

# Assicura che 'src' sia importabile
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# --- NUOVO: set env SUBITO, prima che i test importino moduli ---
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
# ---------------------------------------------------------------

@pytest.fixture(autouse=True)
def _env(monkeypatch):
    # ribadisce le env per ogni test e fa i reload puliti
    for k, v in DEFAULT_ENV.items():
        monkeypatch.setenv(k, v)

    if "src.config" in sys.modules:
        importlib.reload(sys.modules["src.config"])
    if "src.opnsense.client" in sys.modules:
        importlib.reload(sys.modules["src.opnsense.client"])
    yield