import responses

BASE = "https://opn.local/api"

def test_toggle_with_apply(client, responses_mock):
    uuid = "u1"
    responses_mock.add(
        responses.POST,
        f"{BASE}/firewall/filter/toggleRule/{uuid}/1",
        json={"result": "ok"},
        status=200,
    )
    responses_mock.add(
        responses.POST,
        f"{BASE}/firewall/filter/apply",
        json={"status": "ok"},
        status=200,
    )
    r = client.post(f"/api/rules/{uuid}/toggle", json={"enabled": True, "apply": True})
    assert r.status_code == 200
    j = r.json()
    assert j["success"] is True
    assert j["applied"] is True

def test_create_rule(client, responses_mock):
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
    responses_mock.add(
        responses.POST,
        f"{BASE}/firewall/filter/addRule",
        json={"uuid": "new-uuid"},
        status=200,
    )
    r = client.post("/api/rules", json=body)
    assert r.status_code == 200
    assert r.json()["success"] is True
