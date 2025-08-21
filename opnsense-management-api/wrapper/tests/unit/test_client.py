# tests/unit/test_client_full_coverage.py
import responses
from urllib.parse import quote

from src.opnsense.client import OpnSenseClient
from src.opnsense.errors import HttpError

BASE = "https://opn.local/api"


# ---------- _req: success JSON ----------
def test_search_rules_json_ok(responses_mock):
    c = OpnSenseClient()
    responses_mock.add(
        responses.POST,
        f"{BASE}/firewall/filter/searchRule",
        json={"rows": [], "total": 0},
        status=200,
    )
    out = c.search_rules()
    assert out["total"] == 0 and out["rows"] == []


# ---------- _req: success TEXT ----------
def test_apply_with_revision_returns_text(responses_mock):
    c = OpnSenseClient()
    rev = "r-1"
    responses_mock.add(
        responses.POST,
        f"{BASE}/firewall/filter/apply/{rev}",
        body="applied",
        content_type="text/plain",
        status=200,
    )
    out = c.apply(revision=rev)
    assert out == "applied"


# ---------- _req: success EMPTY BODY ----------
def test_savepoint_returns_empty_dict(responses_mock):
    c = OpnSenseClient()
    responses_mock.add(
        responses.POST,
        f"{BASE}/firewall/filter/savepoint",
        body="",
        status=200,
    )
    out = c.savepoint()
    assert out == {}  # ramo: if not r.text -> {}


# ---------- _req: error JSON ----------
def test_add_rule_error_json_raises_http_error(responses_mock):
    c = OpnSenseClient()
    responses_mock.add(
        responses.POST,
        f"{BASE}/firewall/filter/addRule",
        json={"err": "boom"},
        status=500,
    )
    try:
        c.add_rule({"description": "x"})
        assert False, "should raise"
    except HttpError as e:
        assert e.status == 500 and e.body == {"err": "boom"}


# ---------- _req: error TEXT ----------
def test_set_rule_error_text_raises_http_error(responses_mock):
    c = OpnSenseClient()
    uid = "u1"
    responses_mock.add(
        responses.POST,
        f"{BASE}/firewall/filter/setRule/{uid}",
        body="bad gateway",
        status=502,
    )
    try:
        c.set_rule(uid, {"description": "x"})
        assert False, "should raise"
    except HttpError as e:
        assert e.status == 502 and e.body == "bad gateway"


# ---------- get_rule: percorso diretto (camelCase) ----------
def test_get_rule_direct_ok(responses_mock):
    c = OpnSenseClient()
    uid = "abc-111"
    responses_mock.add(
        responses.GET,
        f"{BASE}/firewall/filter/getRule/{uid}",
        json={"rule": {"uuid": uid, "description": "ok"}},
        status=200,
    )
    rule = c.get_rule(uid)
    assert rule["uuid"] == uid and rule["description"] == "ok"


# ---------- get_rule: fallback snake_case ----------
def test_get_rule_fallback_snake(responses_mock):
    c = OpnSenseClient()
    uid = "abc-222"
    # camel -> 404 (HttpError)
    responses_mock.add(
        responses.GET,
        f"{BASE}/firewall/filter/getRule/{uid}",
        json={"message": "nope"},
        status=404,
    )
    # snake -> 200
    responses_mock.add(
        responses.GET,
        f"{BASE}/firewall/filter/get_rule/{uid}",
        json={"rule": {"uuid": uid, "description": "ok2"}},
        status=200,
    )
    rule = c.get_rule(uid)
    assert rule["uuid"] == uid and rule["description"] == "ok2"


# ---------- set_rule: encoding UUID ----------
def test_set_rule_encodes_uuid(responses_mock):
    c = OpnSenseClient()
    raw = "id with/space"
    enc = quote(raw, safe="")
    responses_mock.add(
        responses.POST,
        f"{BASE}/firewall/filter/setRule/{enc}",
        json={"result": "saved"},
        status=200,
    )
    out = c.set_rule(raw, {"k": "v"})
    assert out["result"] == "saved"


# ---------- del_rule: encoding UUID ----------
def test_del_rule_encodes_uuid(responses_mock):
    c = OpnSenseClient()
    raw = "weird/id#"
    enc = quote(raw, safe="")
    responses_mock.add(
        responses.POST,
        f"{BASE}/firewall/filter/delRule/{enc}",
        json={"deleted": True},
        status=200,
    )
    out = c.del_rule(raw)
    assert out["deleted"] is True


# ---------- toggle_rule: enabled None (toggle puro) ----------
def test_toggle_rule_suffix_empty_when_enabled_none(responses_mock):
    c = OpnSenseClient()
    uid = "t1"
    # senza /0 o /1
    responses_mock.add(
        responses.POST,
        f"{BASE}/firewall/filter/toggleRule/{uid}",
        json={"result": "ok", "mode": "toggle"},
        status=200,
    )
    out = c.toggle_rule(uid, enabled=None)
    assert out["result"] == "ok"


# ---------- toggle_rule: enabled True / False ----------
def test_toggle_rule_enabled_true_and_false(responses_mock):
    c = OpnSenseClient()
    uid = "t2"

    responses_mock.add(
        responses.POST,
        f"{BASE}/firewall/filter/toggleRule/{uid}/1",
        json={"result": "ok", "enabled": True},
        status=200,
    )
    responses_mock.add(
        responses.POST,
        f"{BASE}/firewall/filter/toggleRule/{uid}/0",
        json={"result": "ok", "enabled": False},
        status=200,
    )

    out_true = c.toggle_rule(uid, enabled=True)
    out_false = c.toggle_rule(uid, enabled=False)
    assert out_true["enabled"] is True and out_false["enabled"] is False


# ---------- apply senza revision (JSON) ----------
def test_apply_no_revision_json_ok(responses_mock):
    c = OpnSenseClient()
    responses_mock.add(
        responses.POST,
        f"{BASE}/firewall/filter/apply",
        json={"status": "ok"},
        status=200,
    )
    out = c.apply()
    assert out["status"] == "ok"