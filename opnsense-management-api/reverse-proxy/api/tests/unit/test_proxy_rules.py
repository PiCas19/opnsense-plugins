# tests/unit/test_proxy_routes.py
import types
from fastapi.testclient import TestClient
from src.app import api
import src.routes.proxy_rules as pr
from src.utils.security import create_access_token
from src.config import settings

class FakeResponse:
    def __init__(self, status_code=200, json_data=None, text=""):
        self.status_code = status_code
        self._json = json_data
        self.text = text
    def json(self):
        return self._json

class FakeClient:
    def __init__(self, mapping):
        self.map = mapping
    def __enter__(self): return self
    def __exit__(self, exc_type, exc, tb): return False
    def _resp(self, method, url):
        return self.map[(method, url)]
    def get(self, url, **kw):    return self._resp("GET", url)
    def post(self, url, **kw):   return self._resp("POST", url)
    def put(self, url, **kw):    return self._resp("PUT", url)
    def delete(self, url, **kw): return self._resp("DELETE", url)

def auth_headers():
    return {"Authorization": "Bearer " + create_access_token("admin")}

def url(path): return f"{settings.WRAPPER_BASE_URL}{path}"

def test_happy_paths(monkeypatch):
    mapping = {
        ("GET", url("/rules")): FakeResponse(200, {"rows":[{"uuid":"u1","description":"r1","action":"pass","enabled":"1"}], "total": 1}),
        ("GET", url("/rules/u1")): FakeResponse(200, {"rule": {"uuid":"u1","description":"r1"}}),
        ("POST", url("/rules")): FakeResponse(200, {"result":{"uuid":"new"}}),
        ("POST", url("/rules/u1/toggle")): FakeResponse(200, {"result":"ok"}),
        ("PUT", url("/rules/u1")): FakeResponse(200, {"result":"ok"}),
        ("DELETE", url("/rules/u1")): FakeResponse(200, {"result":"ok"}),
        ("POST", url("/rules/apply")): FakeResponse(200, {"result":"applied"}),
    }
    monkeypatch.setattr(pr, "client", lambda: FakeClient(mapping))
    c = TestClient(api)

    r = c.get("/api/rules?search=", headers=auth_headers());  assert r.status_code == 200 and r.json()["total"] == 1
    r = c.get("/api/rules/u1", headers=auth_headers());       assert r.status_code == 200 and r.json()["rule"]["uuid"] == "u1"
    r = c.post("/api/rules", json={"rule":{}, "apply": False}, headers=auth_headers());  assert r.status_code == 200
    r = c.post("/api/rules/u1/toggle", json={"enabled": True,"apply": False}, headers=auth_headers()); assert r.status_code == 200
    r = c.put("/api/rules/u1", json={"rule":{}}, headers=auth_headers()); assert r.status_code == 200
    r = c.delete("/api/rules/u1", headers=auth_headers());    assert r.status_code == 200
    r = c.post("/api/rules/apply", headers=auth_headers());   assert r.status_code == 200

def test_upstream_error_is_mapped_to_502(monkeypatch):
    mapping = {("GET", url("/rules")): FakeResponse(500, {"msg":"boom"})}
    monkeypatch.setattr(pr, "client", lambda: FakeClient(mapping))
    c = TestClient(api)
    r = c.get("/api/rules", headers=auth_headers())
    assert r.status_code == 502
    j = r.json()
    assert j["detail"]["upstream"] == 500