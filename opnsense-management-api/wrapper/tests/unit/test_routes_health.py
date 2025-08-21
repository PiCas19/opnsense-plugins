from fastapi.testclient import TestClient
import types

from src.app import api
from src.routes import health as health_module
from src.opnsense.errors import HttpError
from src import config


def _swap_client(monkeypatch, **impls):
    """
    Rimpiazza health_module.client con un fake che espone i metodi passati.
    Esempio: _swap_client(monkeypatch, search_rules=lambda **k: {...})
    """
    fake = types.SimpleNamespace(**impls)
    monkeypatch.setattr(health_module, "client", fake, raising=True)
    return fake


def test_health_root_ok():
    c = TestClient(api)
    r = c.get("/api/health")
    assert r.status_code == 200
    j = r.json()
    assert j["ok"] is True
    assert j["service"] == "opnsense-wrapper-python"
    assert j["docs"] == "/docs" and j["swagger"] == "/swagger.yaml"


def test_health_opnsense_ok(monkeypatch):
    # success path -> ritorna 200 con details/latency_ms
    _swap_client(monkeypatch, search_rules=lambda **k: {"total": 7})
    c = TestClient(api)
    r = c.get("/api/health/opnsense")
    assert r.status_code == 200
    j = r.json()
    assert j["ok"] is True
    assert isinstance(j["latency_ms"], int) and j["latency_ms"] >= 0
    assert j["details"]["total_rules"] == 7
    assert j["details"]["verify_ssl"] == config.OPNSENSE_VERIFY_SSL
    assert j["details"]["base_url"] == config.OPNSENSE_URL


def test_health_opnsense_upstream_401(monkeypatch):
    # HttpError 4xx -> lo stesso status code
    def boom(**k):
        raise HttpError(401, {"msg": "bad auth"}, "https://fw/api/...")
    _swap_client(monkeypatch, search_rules=boom)
    c = TestClient(api)
    r = c.get("/api/health/opnsense")
    assert r.status_code == 401
    j = r.json()
    assert j["detail"]["upstream_status"] == 401
    assert "latency_ms" in j["detail"]


def test_health_opnsense_upstream_503_maps_to_502(monkeypatch):
    # HttpError 5xx -> mappato a 502
    def boom(**k):
        raise HttpError(503, {"msg": "down"}, "https://fw/api/...")
    _swap_client(monkeypatch, search_rules=boom)
    c = TestClient(api)
    r = c.get("/api/health/opnsense")
    assert r.status_code == 502
    j = r.json()
    assert j["detail"]["upstream_status"] == 503


def test_health_opnsense_generic_exception_500(monkeypatch):
    # Eccezione generica -> 500
    def boom(**k):
        raise RuntimeError("boom")
    _swap_client(monkeypatch, search_rules=boom)
    c = TestClient(api)
    r = c.get("/api/health/opnsense")
    assert r.status_code == 500
    assert "error" in r.json()["detail"]
