# tests/unit/test_rules_full_coverage.py
from fastapi.testclient import TestClient
import types

from src.app import api
from src.opnsense.errors import HttpError
from src.routes import rules as rules_module


def _swap_client(monkeypatch, **impls):
    """
    Sostituisce rules_module.client con un fake che espone i metodi passati.
    Es: _swap_client(monkeypatch, search_rules_clean=lambda **k: [{"uuid":"u1"}])
    """
    fake = types.SimpleNamespace(**impls)
    monkeypatch.setattr(rules_module, "client", fake)
    return fake


# -------------------- list_rules --------------------

def test_list_rules_ok(monkeypatch):
    # Il router list_rules() chiama client.search_rules_clean(), non search_rules()
    _swap_client(monkeypatch, search_rules_clean=lambda **k: [{"uuid":"u1"}])
    c = TestClient(api)
    r = c.get("/api/rules?search=")
    assert r.status_code == 200
    j = r.json()
    assert j["success"] is True and j["total"] == 1 and j["rows"][0]["uuid"] == "u1"


def test_list_rules_upstream_404(monkeypatch):
    def boom(**k): raise HttpError(404, {"msg":"nope"}, "u")
    _swap_client(monkeypatch, search_rules_clean=boom)
    c = TestClient(api)
    r = c.get("/api/rules?search=x")
    assert r.status_code == 404
    assert r.json()["detail"]["upstream"] == 404


def test_list_rules_upstream_503_maps_to_502(monkeypatch):
    def boom(**k): raise HttpError(503, {"msg":"down"}, "u")
    _swap_client(monkeypatch, search_rules_clean=boom)
    c = TestClient(api)
    r = c.get("/api/rules?search=x")
    assert r.status_code == 502


# -------------------- list_rules con filtri --------------------

def test_list_rules_with_interface_filter(monkeypatch):
    captured_params = {}
    def capture_and_return(**kwargs):
        captured_params.update(kwargs)
        return [{"uuid": "u1", "interface": "lan"}]
    
    _swap_client(monkeypatch, search_rules_clean=capture_and_return)
    c = TestClient(api)
    r = c.get("/api/rules?interface=lan&automation_only=true")
    
    assert r.status_code == 200
    assert captured_params["interface"] == "lan"
    assert captured_params["automation_only"] is True


def test_list_rules_with_search_filter(monkeypatch):
    # Test che il filtro search venga applicato client-side
    rules = [
        {"uuid": "u1", "description": "HTTPS rule"},
        {"uuid": "u2", "descr": "SSH rule"},
        {"uuid": "u3", "description": "FTP rule"}
    ]
    _swap_client(monkeypatch, search_rules_clean=lambda **k: rules)
    
    c = TestClient(api)
    r = c.get("/api/rules?search=ssh")
    
    assert r.status_code == 200
    j = r.json()
    assert j["total"] == 1
    assert j["rows"][0]["uuid"] == "u2"


def test_list_rules_search_case_insensitive(monkeypatch):
    rules = [
        {"uuid": "u1", "description": "HTTPS Rule"},
        {"uuid": "u2", "description": "ssh connection"}
    ]
    _swap_client(monkeypatch, search_rules_clean=lambda **k: rules)
    
    c = TestClient(api)
    r = c.get("/api/rules?search=HTTPS")  # Maiuscolo
    
    assert r.status_code == 200
    j = r.json()
    assert j["total"] == 1
    assert j["rows"][0]["uuid"] == "u1"


# -------------------- get_rule --------------------

def test_get_rule_ok(monkeypatch):
    _swap_client(monkeypatch, get_rule=lambda uuid: {"uuid": uuid, "description": "ok"})
    c = TestClient(api)
    r = c.get("/api/rules/abc")
    assert r.status_code == 200 and r.json()["rule"]["uuid"] == "abc"


def test_get_rule_not_found(monkeypatch):
    _swap_client(monkeypatch, get_rule=lambda uuid: None)
    c = TestClient(api)
    r = c.get("/api/rules/missing")
    assert r.status_code == 404


def test_get_rule_upstream_500_to_502(monkeypatch):
    def boom(uuid): raise HttpError(500, {"err":"x"}, "u")
    _swap_client(monkeypatch, get_rule=boom)
    c = TestClient(api)
    r = c.get("/api/rules/any")
    assert r.status_code == 502


# -------------------- create_rule --------------------

def test_create_rule_ok_apply_false(monkeypatch):
    _swap_client(monkeypatch, add_rule=lambda rule: {"uuid": "new"})
    c = TestClient(api)
    r = c.post("/api/rules", json={"rule": {"description":"x"}, "apply": False})
    assert r.status_code == 200 and r.json()["applied"] is False


def test_create_rule_ok_apply_true_calls_apply(monkeypatch):
    flags = {"applied": False}
    def add_rule(rule): return {"uuid": "new"}
    def apply(): flags["applied"] = True; return {"status":"ok"}

    _swap_client(monkeypatch, add_rule=add_rule, apply=apply)
    c = TestClient(api)
    r = c.post("/api/rules", json={"rule": {"description":"x"}, "apply": True})
    assert r.status_code == 200
    assert r.json()["applied"] is True
    assert flags["applied"] is True


def test_create_rule_upstream_400(monkeypatch):
    def boom(rule): raise HttpError(400, {"e": "bad"}, "u")
    _swap_client(monkeypatch, add_rule=boom)
    c = TestClient(api)
    r = c.post("/api/rules", json={"rule": {"description":"x"}, "apply": False})
    assert r.status_code == 400


# -------------------- toggle_rule --------------------

def test_toggle_rule_enabled_none_apply_false(monkeypatch):
    _swap_client(monkeypatch, toggle_rule=lambda uuid, enabled: {"result":"ok"})
    c = TestClient(api)
    r = c.post("/api/rules/u1/toggle", json={})  # enabled = None, apply False (default)
    assert r.status_code == 200
    j = r.json()
    assert j["success"] is True and j["applied"] is False and j["result"]["result"] == "ok"


def test_toggle_rule_apply_true(monkeypatch):
    flags = {"applied": False}
    def toggle_rule(uuid, enabled): return {"result":"ok", "uuid": uuid, "enabled": enabled}
    def apply(): flags["applied"] = True; return {"status":"ok"}
    _swap_client(monkeypatch, toggle_rule=toggle_rule, apply=apply)

    c = TestClient(api)
    r = c.post("/api/rules/u1/toggle", json={"enabled": True, "apply": True})
    assert r.status_code == 200
    j = r.json()
    assert j["applied"] is True and flags["applied"] is True and j["result"]["enabled"] is True


def test_toggle_rule_upstream_500(monkeypatch):
    def boom(uuid, enabled): raise HttpError(500, {"e":"x"}, "u")
    _swap_client(monkeypatch, toggle_rule=boom)
    c = TestClient(api)
    r = c.post("/api/rules/u1/toggle", json={"enabled": False})
    assert r.status_code == 502


# -------------------- update_rule --------------------

def test_update_rule_ok(monkeypatch):
    _swap_client(monkeypatch, set_rule=lambda uuid, rule: {"status":"ok"})
    c = TestClient(api)
    r = c.put("/api/rules/u1", json={"rule": {"description":"upd"}})
    assert r.status_code == 200 and r.json()["result"]["status"] == "ok"


def test_update_rule_upstream_400(monkeypatch):
    def boom(uuid, rule): raise HttpError(400, {"e":"bad"}, "u")
    _swap_client(monkeypatch, set_rule=boom)
    c = TestClient(api)
    r = c.put("/api/rules/u1", json={"rule": {"description":"upd"}})
    assert r.status_code == 400


# -------------------- delete_rule --------------------

def test_delete_rule_ok(monkeypatch):
    _swap_client(monkeypatch, del_rule=lambda uuid: {"deleted": True})
    c = TestClient(api)
    r = c.delete("/api/rules/u1")
    assert r.status_code == 200 and r.json()["result"]["deleted"] is True


def test_delete_rule_upstream_503_to_502(monkeypatch):
    def boom(uuid): raise HttpError(503, {"e":"down"}, "u")
    _swap_client(monkeypatch, del_rule=boom)
    c = TestClient(api)
    r = c.delete("/api/rules/u1")
    assert r.status_code == 502


# -------------------- apply_config --------------------

def test_apply_config_ok(monkeypatch):
    _swap_client(monkeypatch, apply=lambda: {"status":"ok"})
    c = TestClient(api)
    r = c.post("/api/rules/apply")
    assert r.status_code == 200 and r.json()["result"]["status"] == "ok"


def test_apply_config_upstream_500(monkeypatch):
    def boom(): raise HttpError(500, {"e":"x"}, "u")
    _swap_client(monkeypatch, apply=boom)
    c = TestClient(api)
    r = c.post("/api/rules/apply")
    assert r.status_code == 502


# -------------------- test edge cases --------------------

def test_list_rules_empty_search_description_and_descr(monkeypatch):
    """Test che gestisca regole con description o descr vuoti/None"""
    rules = [
        {"uuid": "u1", "description": None},
        {"uuid": "u2", "descr": ""},
        {"uuid": "u3", "description": "valid rule"}
    ]
    _swap_client(monkeypatch, search_rules_clean=lambda **k: rules)
    
    c = TestClient(api)
    r = c.get("/api/rules?search=valid")
    
    assert r.status_code == 200
    j = r.json()
    assert j["total"] == 1
    assert j["rows"][0]["uuid"] == "u3"


def test_list_rules_row_count_parameter(monkeypatch):
    """Test che row_count venga passato correttamente"""
    captured_params = {}
    def capture_params(**kwargs):
        captured_params.update(kwargs)
        return []
    
    _swap_client(monkeypatch, search_rules_clean=capture_params)
    
    c = TestClient(api)
    r = c.get("/api/rules?row_count=500")
    
    assert r.status_code == 200
    assert captured_params["row_count"] == 500