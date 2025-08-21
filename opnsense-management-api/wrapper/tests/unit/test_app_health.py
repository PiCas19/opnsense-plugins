
import pytest

def test_health_root(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["ok"] is True

def test_health_echo_config(client):
    r = client.get("/api/health/echo-config")
    if r.status_code == 404:
        pytest.skip("echo-config non abilitato")
    assert r.status_code == 200
