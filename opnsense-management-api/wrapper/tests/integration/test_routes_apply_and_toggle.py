from httpx import Response

BASE = "https://opn.local/api"

def test_toggle_with_apply(client, respx_mock_global):
    uuid = "u1"
    respx_mock_global.post(f"{BASE}/firewall/filter/toggleRule/{uuid}/1").mock(
        return_value=Response(200, json={"result": "ok"})
    )
    respx_mock_global.post(f"{BASE}/firewall/filter/apply").mock(
        return_value=Response(200, json={"status": "ok"})
    )
    r = client.post(f"/api/rules/{uuid}/toggle", json={"enabled": True, "apply": True})
    assert r.status_code == 200
    j = r.json()
    assert j["success"] is True
    assert j["applied"] is True

def test_create_rule(client, respx_mock_global):
    body = {
        "rule": {
            "enabled": "1", "interface": "wan", "direction": "in",
            "ipprotocol": "inet", "protocol": "tcp", "action": "pass",
            "description": "API Created Rule",
            "source_net": "any", "source_port": "",
            "destination_net": "any", "destination_port": "443",
            "log": "0", "quick": "1", "floating": "0"
        },
        "apply": False
    }
    respx_mock_global.post(f"{BASE}/firewall/filter/addRule").mock(
        return_value=Response(200, json={"uuid": "new-uuid"})
    )
    r = client.post("/api/rules", json=body)
    assert r.status_code == 200
    assert r.json()["success"] is True