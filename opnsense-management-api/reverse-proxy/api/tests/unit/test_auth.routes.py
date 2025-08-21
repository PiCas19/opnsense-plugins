# tests/unit/test_auth_routes.py
from fastapi.testclient import TestClient
from src.app import api

def test_login_ok_and_refresh():
    c = TestClient(api)

    # login ok
    r = c.post("/api/auth/login", json={"username": "admin", "password": "changeme"})
    assert r.status_code == 200
    j = r.json()
    assert "access_token" in j and "refresh_token" in j
    assert j["token_type"] == "bearer"
    rt = j["refresh_token"]

    # refresh ok
    r2 = c.post("/api/auth/refresh", json={"refresh_token": rt})
    assert r2.status_code == 200
    j2 = r2.json()
    assert "access_token" in j2 and "refresh_token" in j2

def test_login_unauthorized():
    c = TestClient(api)
    r = c.post("/api/auth/login", json={"username": "admin", "password": "WRONG"})
    assert r.status_code == 401

def test_refresh_unauthorized():
    c = TestClient(api)
    r = c.post("/api/auth/refresh", json={"refresh_token": "totally-invalid"})
    assert r.status_code == 401