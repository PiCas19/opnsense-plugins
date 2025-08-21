# tests/unit/test_errors.py
import pytest
from src.opnsense.errors import HttpError


def test_http_error_attributes_and_str():
    e = HttpError(401, {"msg": "nope"}, "https://fw/api/rules")
    assert isinstance(e, Exception)
    assert e.status == 401
    assert e.body == {"msg": "nope"}
    assert e.url == "https://fw/api/rules"
    # message ereditato da Exception
    assert str(e) == "HTTP 401"


def test_http_error_repr_with_string_body():
    body = "plain text error"
    url = "http://example/api/thing?x=1"
    e = HttpError(503, body, url)
    rep = repr(e)
    # __repr__ preciso
    assert rep == "HttpError(status=503, url='http://example/api/thing?x=1', body='plain text error')"
    # e per sicurezza…
    assert "status=503" in rep and f"url='{url}'" in rep and "body='plain text error'" in rep


def test_raising_and_catching_http_error():
    with pytest.raises(HttpError) as ctx:
        raise HttpError(500, {"error": "boom"}, "http://x")
    err = ctx.value
    assert err.status == 500