import importlib
import sys
import jwt
import pytest

from src.config import settings


def _import_security():
    # (ri)importa in modo sicuro evitando moduli parziali in cache
    if "src.utils.security" in sys.modules:
        importlib.reload(sys.modules["src.utils.security"])
    import src.utils.security as sec
    return sec


def _bearer(token: str):
    # finto HTTPAuthorizationCredentials
    from types import SimpleNamespace as NS
    return NS(scheme="Bearer", credentials=token)


def test_access_ok_and_get_current_user_ok():
    sec = _import_security()
    tok = sec.create_access_token("alice")
    user = sec.get_current_user(_bearer(tok))
    assert user == "alice"


def test_missing_header_and_wrong_scheme():
    sec = _import_security()

    with pytest.raises(Exception) as e1:
        sec.get_current_user(None)
    assert getattr(e1.value, "status_code", 0) == 401

    with pytest.raises(Exception) as e2:
        sec.get_current_user(type("C", (), {"scheme": "Basic", "credentials": "x"})())
    assert getattr(e2.value, "status_code", 0) == 401


def test_access_token_expired_raises_token_expired():
    sec = _import_security()

    expired = jwt.encode(
        {"sub": "bob", "type": "access", "iat": 0, "exp": 1},
        settings.JWT_SECRET,
        algorithm="HS256",
    )
    with pytest.raises(Exception) as e:
        sec.get_current_user(_bearer(expired))
    assert getattr(e.value, "status_code", 0) == 401
    assert getattr(e.value, "detail", "") == "Token expired"


def test_access_token_completely_invalid_string():
    sec = _import_security()
    with pytest.raises(Exception) as e:
        sec.get_current_user(_bearer("not.a.jwt"))
    assert getattr(e.value, "status_code", 0) == 401
    assert getattr(e.value, "detail", "") == "Invalid token"


def test_refresh_token_ok_and_decode_refresh_ok():
    sec = _import_security()
    rt = sec.create_refresh_token("carol")
    payload = sec.decode_refresh(rt)
    assert payload["sub"] == "carol"
    assert payload["type"] == "refresh"


def test_decode_refresh_with_access_token_is_rejected():
    sec = _import_security()
    at = sec.create_access_token("dave")
    with pytest.raises(Exception) as e:
        sec.decode_refresh(at)
    assert getattr(e.value, "status_code", 0) == 401
    assert getattr(e.value, "detail", "") == "Invalid refresh token"


def test_get_current_user_with_refresh_token_is_rejected():
    sec = _import_security()
    rt = sec.create_refresh_token("erin")
    with pytest.raises(Exception) as e:
        sec.get_current_user(_bearer(rt))
    assert getattr(e.value, "status_code", 0) == 401
    assert getattr(e.value, "detail", "") == "Invalid token"


def test_refresh_fallback_to_access_secret(monkeypatch):
    # forza il fallback: senza JWT_REFRESH_SECRET si deve usare JWT_SECRET
    monkeypatch.setattr(settings, "JWT_REFRESH_SECRET", None)
    sec = _import_security()
    rt = sec.create_refresh_token("frank")
    payload = sec.decode_refresh(rt)
    assert payload["sub"] == "frank"
    assert payload["type"] == "refresh"