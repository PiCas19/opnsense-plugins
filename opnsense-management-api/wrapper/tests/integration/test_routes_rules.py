import responses

BASE = "https://opn.local/api"

def test_list_rules_ok(client, responses_mock):
    responses_mock.add(
        responses.POST,
        f"{BASE}/firewall/filter/searchRule",
        json={"rows": [{"uuid":"u1","description":"r1"}], "total": 1},
        status=200,
    )
    r = client.get("/api/rules?search=")
    assert r.status_code == 200
    j = r.json()
    assert j["success"] is True
    assert j["total"] == 1
    assert j["rows"][0]["uuid"] == "u1"

def test_get_rule_404(client, responses_mock):
    uuid = "nope"
    responses_mock.add(
        responses.GET,
        f"{BASE}/firewall/filter/getRule/{uuid}",
        json={"message":"nope"},
        status=404,
    )
    responses_mock.add(
        responses.GET,
        f"{BASE}/firewall/filter/get_rule/{uuid}",
        json={"message":"nope"},
        status=404,
    )
    r = client.get(f"/api/rules/{uuid}")
    assert r.status_code in (404, 502)
