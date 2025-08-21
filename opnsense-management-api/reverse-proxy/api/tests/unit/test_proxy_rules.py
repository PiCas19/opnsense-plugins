# tests/unit/test_proxy_rules.py
import httpx
from fastapi.testclient import TestClient
from src.app import api
from src.config import settings
from src.routes import proxy_rules as pr

class FakeClient:
    """Client httpx finto usato via monkeypatch su pr.client()"""
    def __init__(self, table):
        self.table = table

    def __enter__(self): return self
    def __exit__(self, *a): return False

    def _resp(self, method, url, data=None):
        key = (method, url)
        if key not in self.table:
            return httpx.Response(404, json={"err": "no route"}, request=httpx.Request(method, url))
        val = self.table[key]
        if callable(val):
            return val(data)
        return val

    def get(self, url, params=None):
        return self._resp("GET", url, params)

    def post(self, url, json=None):
        return self._resp("POST", url, json)

    def put(self, url, json=None):
        return self._resp("PUT", url, json)

    def delete(self, url):
        return self._resp("DELETE", url, None)

def _url(p): return f"{settings.WRAPPER_BASE_URL}{p}"

def test_all_happy_paths(monkeypatch):
    table = {
        ("GET",    _url("/rules")):                    httpx.Response(200, json={"total": 1, "rows": [{"uuid":"u1"}]}, request=httpx.Request("GET", _url("/rules"))),
        ("GET",    _url("/rules/u1")):                 httpx.Response(200, json={"rule": {"uuid":"u1"}}, request=httpx.Request("GET", _url("/rules/u1"))),
        ("POST",   _url("/rules")):                    httpx.Response(200, json={"ok": True}, request=httpx.Request("POST", _url("/rules"))),
        ("POST",   _url("/rules/u1/toggle")):          httpx.Response(200, json={"ok": True}, request=httpx.Request("POST", _url("/rules/u1/toggle"))),
        ("PUT",    _url("/rules/u1")):                 httpx.Response(200, json={"ok": True}, request=httpx.Request("PUT", _url("/rules/u1"))),
        ("DELETE", _url("/rules/u1")):                 httpx.Response(200, json={"ok": True}, request=httpx.Request("DELETE", _url("/rules/u1"))),
        ("POST",   _url("/rules/apply")):              httpx.Response(200, json={"status": "applied"}, request=httpx.Request("POST", _url("/rules/apply"))),
    }
    monkeypatch.setattr(pr, "client", lambda: FakeClient(table))

    c = TestClient(api)
    # dependency override già in conftest
    assert c.get("/api/rules").status_code == 200
    assert c.get("/api/rules/u1").status_code == 200
    assert c.post("/api/rules", json={"rule": {"description":"x"}, "apply": False}).status_code == 200
    assert c.post("/api/rules/u1/toggle", json={"enabled": True}).status_code == 200
    assert c.put("/api/rules/u1", json={"rule": {"description":"y"}}).status_code == 200
    assert c.delete("/api/rules/u1").status_code == 200
    assert c.post("/api/rules/apply").status_code == 200

def test_error_mapping_to_502(monkeypatch):
    # Upstream 503 -> DMZ 502 con detail
    table = {
        ("GET", _url("/rules")): httpx.Response(
            503, text="maintenance", request=httpx.Request("GET", _url("/rules"))
        )
    }
    monkeypatch.setattr(pr, "client", lambda: FakeClient(table))
    c = TestClient(api)
    r = c.get("/api/rules")
    assert r.status_code == 502
    j = r.json()
    assert j["detail"]["upstream"] == 503
    assert "maintenance" in j["detail"]["body"]