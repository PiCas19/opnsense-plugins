# tests/unit/test_config.py
import importlib, sys, os

def test_wrapper_base_url_suffix(monkeypatch):
    monkeypatch.setenv("WRAPPER_BASE_URL", "http://x.y.z")  # senza /api
    if "src.config" in sys.modules:
        del sys.modules["src.config"]
    cfg = importlib.import_module("src.config")
    assert cfg.settings.WRAPPER_BASE_URL.endswith("/api")