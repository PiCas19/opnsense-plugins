# tests/unit/test_proxy_routes.py
from fastapi.testclient import TestClient
import src.routes.proxy_rules as pr
from src.app import api
from src.utils.security import create_access_token
from src.config import settings

# --------- helper finti httpx.Client / Response ---------
class FakeResponse:
    def __init__(self, status_code=200, json_data=None, text=""):
        self.status_code = status_code
        self._json = json_data
        self.text = text

    def json(self):
        # Simula .json() che fallisce quando non c'è json_data
        if self._json is None:
            raise ValueError("no json")
        return self._json


class FakeClient:
    """Sostituisce httpx.Client: sceglie la risposta dalla mappa (method, url)."""
    def __init__(self, mapping):
        self.map = mapping

    def __enter__(self):  # context manager compatibile con 'with client() as c'
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def _resp(self, method, url):
        return self.map[(method, url)]

    def get(self, url, **kw):    return self._resp("GET", url)
    def post(self, url, **kw):   return self._resp("POST", url)
    def put(self, url, **kw):    return self._resp("PUT", url)
    def delete(self, url, **kw): return self._resp("DELETE", url)

# --------- utility ---------
def auth_headers():
    return {"Authorization": "Bearer " + create_access_token("admin")}

def full_url(path: str) -> str:
    return f"{settings.WRAPPER_BASE_URL}{path}"

# --------- test: tutti i percorsi OK ---------
def test_happy_paths(monkeypatch):
    mapping = {
        ("GET",    full_url("/rules")):             FakeResponse(200, {"rows":[{"uuid":"u1","description":"r1","action":"pass","enabled":"1"}], "total": 1}),
        ("GET",    full_url("/rules/u1")):          FakeResponse(200, {"rule": {"uuid":"u1","description":"r1"}}),
        ("POST",   full_url("/rules")):             FakeResponse(200, {"result":{"uuid":"new"}}),
        ("POST",   full_url("/rules/u1/toggle")):   FakeResponse(200, {"result":"ok"}),
        ("PUT",    full_url("/rules/u1")):          FakeResponse(200, {"result":"ok"}),
        ("DELETE", full_url("/rules/u1")):          FakeResponse(200, {"result":"ok"}),
        ("POST",   full_url("/rules/apply")):       FakeResponse(200, {"result":"applied"}),
    }
    monkeypatch.setattr(pr, "client", lambda: FakeClient(mapping))
    c = TestClient(api)

    assert c.get("/api/rules?search=", headers=auth_headers()).json()["total"] == 1
    assert c.get("/api/rules/u1", headers=auth_headers()).json()["rule"]["uuid"] == "u1"
    assert c.post("/api/rules", json={"rule":{}, "apply": False}, headers=auth_headers()).status_code == 200
    assert c.post("/api/rules/u1/toggle", json={"enabled": True,"apply": False}, headers=auth_headers()).status_code == 200
    assert c.put("/api/rules/u1", json={"rule":{}}, headers=auth_headers()).status_code == 200
    assert c.delete("/api/rules/u1", headers=auth_headers()).status_code == 200
    assert c.post("/api/rules/apply", headers=auth_headers()).status_code == 200

# --------- test: mapping error 5xx -> 502 (branch body=TEXT) ---------
def test_upstream_5xx_is_mapped_to_502_with_text_body(monkeypatch):
    # Nessun JSON, .json() deve alzare; _raise_upstream deve usare r.text
    mapping = {("POST", full_url("/rules")): FakeResponse(503, None, text="down")}
    monkeypatch.setattr(pr, "client", lambda: FakeClient(mapping))
    c = TestClient(api)

    r = c.post("/api/rules", json={"rule":{}, "apply": False}, headers=auth_headers())
    assert r.status_code == 502
    j = r.json()
    assert j["detail"]["upstream"] == 503
    assert j["detail"]["body"] == "down"

# --------- test: mapping error non-5xx -> stesso status (branch body=JSON) ---------
def test_upstream_404_passthrough_with_json_body(monkeypatch):
    mapping = {("GET", full_url("/rules/miss")): FakeResponse(404, {"msg":"nope"})}
    monkeypatch.setattr(pr, "client", lambda: FakeClient(mapping))
    c = TestClient(api)

    r = c.get("/api/rules/miss", headers=auth_headers())
    assert r.status_code == 404
    j = r.json()
    assert j["detail"]["upstream"] == 404
    assert j["detail"]["body"] == {"msg":"nope"}

# --------- test: dipendenza auth -> 401 senza Authorization ---------
def test_auth_required_returns_401_when_missing_header(monkeypatch):
    # anche con client finto, la dipendenza scatta prima della chiamata upstream
    mapping = {("GET", full_url("/rules")): FakeResponse(200, {"rows": [], "total": 0})}
    monkeypatch.setattr(pr, "client", lambda: FakeClient(mapping))
    c = TestClient(api)

    r = c.get("/api/rules")  # niente Authorization
    assert r.status_code == 401