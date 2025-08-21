def test_health_root(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["ok"] is True

def test_health_echo_config(client):
    r = client.get("/api/health/echo-config")
    assert r.status_code == 200
    j = r.json()
    assert j["base_url"].endswith("/api")
