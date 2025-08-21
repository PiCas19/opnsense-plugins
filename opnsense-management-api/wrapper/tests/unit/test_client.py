from httpx import Response  # solo per costruire json/status se vuoi, ma non è obbligatorio
import responses

from src.opnsense.client import OpnSenseClient

BASE = "https://opn.local/api"

def test_search_rules_path_no_double_api(responses_mock):
    c = OpnSenseClient()
    responses_mock.add(
        responses.POST,
        f"{BASE}/firewall/filter/searchRule",
        json={"rows": [], "total": 0},
        status=200,
    )
    res = c.search_rules()
    assert res["total"] == 0

def test_get_rule_fallback_to_snake(responses_mock):
    c = OpnSenseClient()
    uuid = "abc-123"
    responses_mock.add(
        responses.GET,
        f"{BASE}/firewall/filter/getRule/{uuid}",
        json={"message": "not found"},
        status=404,
    )
    responses_mock.add(
        responses.GET,
        f"{BASE}/firewall/filter/get_rule/{uuid}",
        json={"rule": {"uuid": uuid, "description": "ok"}},
        status=200,
    )
    rule = c.get_rule(uuid)
    assert rule["uuid"] == uuid

def test_toggle_and_apply(responses_mock):
    c = OpnSenseClient()
    uuid = "id-1"
    responses_mock.add(
        responses.POST,
        f"{BASE}/firewall/filter/toggleRule/{uuid}/0",
        json={"result": "ok"},
        status=200,
    )
    responses_mock.add(
        responses.POST,
        f"{BASE}/firewall/filter/apply",
        json={"status": "ok"},
        status=200,
    )
    assert c.toggle_rule(uuid, enabled=False)["result"] == "ok"
    assert c.apply()["status"] == "ok"
