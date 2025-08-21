# tests/unit/test_config.py
import importlib
import os

def test_wrapper_url_suffix_added(monkeypatch):
    monkeypatch.setenv("WRAPPER_BASE_URL", "http://x")  # senza /api
    if "src.config" in importlib.sys.modules:
        del importlib.sys.modules["src.config"]
    from src.config import settings
    assert settings.WRAPPER_BASE_URL.endswith("/api")

def test_wrapper_url_suffix_kept(monkeypatch):
    monkeypatch.setenv("WRAPPER_BASE_URL", "http://x/api")
    if "src.config" in importlib.sys.modules:
        del importlib.sys.modules["src.config"]
    from src.config import settings
    assert settings.WRAPPER_BASE_URL == "http://x/api"