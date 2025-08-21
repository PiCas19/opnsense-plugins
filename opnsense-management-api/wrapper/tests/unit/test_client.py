from httpx import Response
from src.opnsense.client import OpnSenseClient

BASE = "https://opn.local/api"

def test_search_rules_path_no_double_api(respx_mock_global):
    c = OpnSenseClient()
    route = respx_mock_global.post(f"{BASE}/firewall/filter/searchRule").mock(
        return_value=Response(200, json={"rows": [], "total": 0})
    )
    res = c.search_rules()
    assert res["total"] == 0
    assert route.called

def test_get_rule_fallback_to_snake(respx_mock_global):
    c = OpnSenseClient()
    uuid = "abc-123"
    respx_mock_global.get(f"{BASE}/firewall/filter/getRule/{uuid}").mock(
        return_value=Response(404, json={"message": "not found"})
    )
    respx_mock_global.get(f"{BASE}/firewall/filter/get_rule/{uuid}").mock(
        return_value=Response(200, json={"rule": {"uuid": uuid, "description": "ok"}})
    )
    rule = c.get_rule(uuid)
    assert rule["uuid"] == uuid

def test_toggle_and_apply(respx_mock_global):
    c = OpnSenseClient()
    uuid = "id-1"
    tgl = respx_mock_global.post(f"{BASE}/firewall/filter/toggleRule/{uuid}/0").mock(
        return_value=Response(200, json={"result": "ok"})
    )
    app = respx_mock_global.post(f"{BASE}/firewall/filter/apply").mock(
        return_value=Response(200, json={"status": "ok"})
    )
    assert c.toggle_rule(uuid, enabled=False)["result"] == "ok"
    assert c.apply()["status"] == "ok"
    assert tgl.called and app.called
