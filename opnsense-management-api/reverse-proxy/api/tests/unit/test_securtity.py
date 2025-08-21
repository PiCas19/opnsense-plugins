from types import SimpleNamespace as NS
import importlib
import sys
import jwt
import pytest
from src.config import settings

def _sec():
    # ricarica il modulo per evitare partial import e usare i settings correnti
    if "src.utils.security" in sys.modules:
        importlib.reload(sys.modules["src.utils.security"])
    else:
        importlib.import_module("src.utils.security")
    return sys.modules["src.utils.security"]

def _bearer(token: str):
    return NS(scheme="Bearer", credentials=token)

def _detail(exc) -> str:
    # HTTPException.detail può essere string o dict
    d = getattr(exc, "detail", "")
    return d if isinstance(d, str) else str(d)

def test_access_ok_and_get_current_user_ok():
    sec = _sec()
    tok = sec.create_access_token("alice")
    assert sec.get_current_user(_bearer(tok)) == "alice"

def test_missing_header_and_wrong_scheme():
    sec = _sec()
    with pytest.raises(Exception) as e1:
        sec.get_current_user(None)
    assert getattr(e1.value, "status_code", 0) == 401

    with pytest.raises(Exception) as e2:
        sec.get_current_user(NS(scheme="Basic", credentials="x"))
    assert getattr(e2.value, "status_code", 0) == 401

def test_access_token_expired_returns_401_with_expired_semantics():
    sec = _sec()
    expired = jwt.encode(
        {"sub": "bob", "type": "access", "iat": 0, "exp": 1},
        settings.JWT_SECRET,
        algorithm="HS256",
    )
    with pytest.raises(Exception) as e:
        sec.get_current_user(_bearer(expired))
    assert getattr(e.value, "status_code", 0) == 401
    # alcune versioni danno "Token expired", altre "Invalid token"
    assert any(w in _detail(e.value).lower() for w in ["expired", "invalid"])

def test_access_token_completely_invalid_string():
    sec = _sec()
    with pytest.raises(Exception) as e:
        sec.get_current_user(_bearer("not.a.jwt"))
    assert getattr(e.value, "status_code", 0) == 401
    assert "invalid" in _detail(e.value).lower()

def test_refresh_token_ok_and_decode_refresh_ok():
    sec = _sec()
    rt = sec.create_refresh_token("carol")
    payload = sec.decode_refresh(rt)
    assert payload["sub"] == "carol" and payload["type"] == "refresh"

def test_decode_refresh_with_access_token_is_rejected():
    sec = _sec()
    at = sec.create_access_token("dave")
    with pytest.raises(Exception) as e:
        sec.decode_refresh(at)
    assert getattr(e.value, "status_code", 0) == 401
    # messaggio può essere "Invalid refresh token" o "Invalid token"
    assert any(w in _detail(e.value).lower() for w in ["invalid refresh", "invalid"])

def test_get_current_user_with_refresh_token_is_rejected():
    sec = _sec()
    rt = sec.create_refresh_token("erin")
    with pytest.raises(Exception) as e:
        sec.get_current_user(_bearer(rt))
    assert getattr(e.value, "status_code", 0) == 401
    assert "invalid" in _detail(e.value).lower()

def test_refresh_fallback_to_access_secret(monkeypatch):
    # copriamo il ramo con fallback del secret
    sec = _sec()
    monkeypatch.setattr(settings, "JWT_REFRESH_SECRET", None)
    sec = _sec()  # ricarica per usare il nuovo setting
    rt = sec.create_refresh_token("frank")
    payload = sec.decode_refresh(rt)
    assert payload["sub"] == "frank" and payload["type"] == "refresh"