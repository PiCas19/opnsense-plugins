from httpx import Response

BASE = "https://opn.local/api"

def test_list_rules_ok(client, respx_mock_global):
    respx_mock_global.post(f"{BASE}/firewall/filter/searchRule").mock(
        return_value=Response(200, json={"rows": [{"uuid":"u1","description":"r1"}], "total": 1})
    )
    r = client.get("/api/rules?search=")
    assert r.status_code == 200
    j = r.json()
    assert j["success"] is True
    assert j["total"] == 1
    assert j["rows"][0]["uuid"] == "u1"

def test_get_rule_404(client, respx_mock_global):
    uuid = "nope"
    # camel 404 + snake 404
    respx_mock_global.get(f"{BASE}/firewall/filter/getRule/{uuid}").mock(
        return_value=Response(404, json={"message":"nope"})
    )
    respx_mock_global.get(f"{BASE}/firewall/filter/get_rule/{uuid}").mock(
        return_value=Response(404, json={"message":"nope"})
    )
    r = client.get(f"/api/rules/{uuid}")
    assert r.status_code in (404, 502)  # dipende dal mapping; con la nostra route è 404/502