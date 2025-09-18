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
    """Sostituisce httpx.Client: sceglie la risposta dalla mappa (method, url, params)."""
    def __init__(self, mapping):
        self.map = mapping

    def __enter__(self):  # context manager compatibile con 'with client() as c'
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def _resp(self, method, url, params=None):
        # Converte params dict in tuple di tuple per renderlo hashable
        hashable_params = None
        if params is not None:
            hashable_params = tuple(sorted(params.items()))
        
        # Prima prova con params specifici
        key_with_params = (method, url, hashable_params)
        if key_with_params in self.map:
            return self.map[key_with_params]
        
        # Fallback: cerca senza params
        key_without_params = (method, url)
        if key_without_params in self.map:
            return self.map[key_without_params]
            
        # Se non trovato, ritorna errore 404
        return FakeResponse(404, {"error": "not mocked"})

    def get(self, url, params=None, **kw):    
        return self._resp("GET", url, params)
    def post(self, url, json=None, **kw):   
        return self._resp("POST", url)
    def put(self, url, json=None, **kw):    
        return self._resp("PUT", url)
    def delete(self, url, **kw): 
        return self._resp("DELETE", url)

# --------- utility ---------
def auth_headers():
    return {"Authorization": "Bearer " + create_access_token("admin")}

def full_url(path: str) -> str:
    return f"{settings.WRAPPER_BASE_URL}{path}"

# Helper function per creare chiavi hashable per i params
def make_params_key(*items):
    return tuple(sorted(items))

# --------- test: tutti i percorsi OK ---------
def test_happy_paths(monkeypatch):
    mapping = {
        # GET /rules con params specifici (interface è obbligatorio)
        # Usa la helper function per creare la chiave hashable
        ("GET", full_url("/rules"), make_params_key(("automation_only", False), ("interface", "lan"))): 
            FakeResponse(200, {"rows":[{"uuid":"u1","description":"r1","action":"pass","enabled":"1"}], "total": 1}),
        
        # GET /rules senza params specifici (fallback)
        ("GET", full_url("/rules")): 
            FakeResponse(200, {"rows":[{"uuid":"u1","description":"r1","action":"pass","enabled":"1"}], "total": 1}),
            
        ("GET",    full_url("/rules/u1")):          FakeResponse(200, {"rule": {"uuid":"u1","description":"r1"}}),
        ("POST",   full_url("/rules")):             FakeResponse(200, {"result":{"uuid":"new"}}),
        ("POST",   full_url("/rules/u1/toggle")):   FakeResponse(200, {"result":"ok"}),
        ("PUT",    full_url("/rules/u1")):          FakeResponse(200, {"result":"ok"}),
        ("DELETE", full_url("/rules/u1")):          FakeResponse(200, {"result":"ok"}),
        ("POST",   full_url("/rules/apply")):       FakeResponse(200, {"result":"applied"}),
    }
    monkeypatch.setattr(pr, "client", lambda: FakeClient(mapping))
    c = TestClient(api)

    # Ora interface è obbligatorio
    assert c.get("/api/rules?interface=lan&search=", headers=auth_headers()).json()["total"] == 1
    assert c.get("/api/rules/u1", headers=auth_headers()).json()["rule"]["uuid"] == "u1"
    assert c.post("/api/rules", json={"rule":{}, "apply": False}, headers=auth_headers()).status_code == 200
    assert c.post("/api/rules/u1/toggle", json={"enabled": True,"apply": False}, headers=auth_headers()).status_code == 200
    assert c.put("/api/rules/u1", json={"rule":{}}, headers=auth_headers()).status_code == 200
    assert c.delete("/api/rules/u1", headers=auth_headers()).status_code == 200
    assert c.post("/api/rules/apply", headers=auth_headers()).status_code == 200

# --------- test: interface obbligatorio ---------
def test_interface_is_mandatory(monkeypatch):
    """Test che interface sia obbligatorio per list_rules"""
    mapping = {}  # Non serve nessuna risposta mock per il primo test
    monkeypatch.setattr(pr, "client", lambda: FakeClient(mapping))
    c = TestClient(api)

    # Senza interface dovrebbe dare errore 422 (validation error)
    r = c.get("/api/rules", headers=auth_headers())
    assert r.status_code == 422
    
    # Con interface dovrebbe funzionare - aggiorniamo il mapping
    mapping_with_response = {
        ("GET", full_url("/rules")): FakeResponse(200, {"rows": [], "total": 0})
    }
    monkeypatch.setattr(pr, "client", lambda: FakeClient(mapping_with_response))
    
    r = c.get("/api/rules?interface=lan", headers=auth_headers())
    assert r.status_code == 200

# --------- test: automation_only sempre False ---------
def test_automation_only_always_false(monkeypatch):
    """Test che automation_only sia sempre False nei parametri inviati al wrapper"""
    captured_params = {}
    
    class ParamsCapturingClient:
        def __enter__(self): return self
        def __exit__(self, exc_type, exc, tb): return False
        
        def get(self, url, params=None, **kw):
            captured_params.update(params or {})
            return FakeResponse(200, {"rows": [], "total": 0})
    
    monkeypatch.setattr(pr, "client", lambda: ParamsCapturingClient())
    c = TestClient(api)
    
    # Chiamata senza automation_only esplicito
    c.get("/api/rules?interface=lan", headers=auth_headers())
    assert captured_params.get("automation_only") is False
    
    # Anche se non è più un parametro dell'API, verifichiamo che sia sempre False
    assert "automation_only" in captured_params
    assert captured_params["automation_only"] is False

# --------- test: mapping error 5xx -> 502 (branch body=TEXT) ---------
def test_upstream_5xx_is_mapped_to_502_with_text_body(monkeypatch):
    # Nessun JSON, .json() deve alzare; raise_upstream deve usare r.text
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

    # Senza Authorization header
    r = c.get("/api/rules?interface=lan")  # interface è obbligatorio
    assert r.status_code == 401

# --------- test: validazione interface values ---------
def test_interface_validation(monkeypatch):
    """Test che interface accetti tutti i valori (la validazione è nel wrapper, non nel proxy)"""
    mapping = {("GET", full_url("/rules")): FakeResponse(200, {"rows": [], "total": 0})}
    monkeypatch.setattr(pr, "client", lambda: FakeClient(mapping))
    c = TestClient(api)

    # Valori che dovrebbero essere accettati dal proxy (la validazione è nel wrapper)
    valid_interfaces = ["lan", "wan", "dmz", "lan|wan", "lan|dmz", "wan|dmz", "lan|wan|dmz"]
    for iface in valid_interfaces:
        r = c.get(f"/api/rules?interface={iface}", headers=auth_headers())
        assert r.status_code == 200, f"Interface {iface} should be valid"

# --------- test: parametri passati correttamente ---------
def test_parameters_passed_correctly(monkeypatch):
    """Test che tutti i parametri vengano passati correttamente al wrapper"""
    captured_params = {}
    
    class ParamsCapturingClient:
        def __enter__(self): return self
        def __exit__(self, exc_type, exc, tb): return False
        
        def get(self, url, params=None, **kw):
            captured_params.clear()
            captured_params.update(params or {})
            return FakeResponse(200, {"rows": [], "total": 0})
    
    monkeypatch.setattr(pr, "client", lambda: ParamsCapturingClient())
    c = TestClient(api)
    
    # Test con tutti i parametri
    r = c.get("/api/rules?interface=lan&search=test&row_count=100", headers=auth_headers())
    assert r.status_code == 200
    
    # Verifica parametri catturati
    assert captured_params["interface"] == "lan"
    assert captured_params["search"] == "test"
    assert captured_params["row_count"] == 100
    assert captured_params["automation_only"] is False
    
    # Test con parametri di default
    captured_params.clear()
    r = c.get("/api/rules?interface=wan", headers=auth_headers())
    assert r.status_code == 200
    
    # row_count=2000 non dovrebbe essere incluso (è il default)
    assert "row_count" not in captured_params
    assert captured_params["interface"] == "wan"
    assert captured_params["automation_only"] is False