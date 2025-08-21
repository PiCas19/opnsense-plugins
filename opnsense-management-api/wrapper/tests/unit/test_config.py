import importlib
import pytest

def test_config_happy_path(monkeypatch):
    monkeypatch.setenv("OPNSENSE_URL", "https://fw/api")
    monkeypatch.setenv("OPNSENSE_KEY", "K")
    monkeypatch.setenv("OPNSENSE_SECRET", "S")
    cfg = importlib.import_module("src.config")
    assert cfg.OPNSENSE_URL.endswith("/api")
    assert cfg.OPNSENSE_KEY == "K"
    assert cfg.OPNSENSE_SECRET == "S"

def test_config_requires_api_suffix(monkeypatch):
    monkeypatch.setenv("OPNSENSE_URL", "https://fw")  # manca /api
    monkeypatch.setenv("OPNSENSE_KEY", "K")
    monkeypatch.setenv("OPNSENSE_SECRET", "S")
    # forza reload per scatenare la validazione a import time
    if "src.config" in importlib.sys.modules:
        del importlib.sys.modules["src.config"]
    with pytest.raises(RuntimeError):
        importlib.import_module("src.config")

def test_config_requires_creds(monkeypatch):
    monkeypatch.setenv("OPNSENSE_URL", "https://fw/api")
    monkeypatch.delenv("OPNSENSE_KEY", raising=False)
    monkeypatch.delenv("OPNSENSE_SECRET", raising=False)
    if "src.config" in importlib.sys.modules:
        del importlib.sys.modules["src.config"]
    with pytest.raises(RuntimeError):
        importlib.import_module("src.config")
