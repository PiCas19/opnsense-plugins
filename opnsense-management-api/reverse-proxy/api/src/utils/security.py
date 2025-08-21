# tests/unit/test_security.py
from types import SimpleNamespace as NS
import jwt
import pytest

from src.utils.security import (
    create_access_token,
    create_refresh_token,
    decode_refresh,
    get_current_user,
)
from src.config import settings


def _bearer(token: str):
    # oggetto compatibile con HTTPAuthorizationCredentials
    return NS(scheme="Bearer", credentials=token)


def test_access_ok_and_get_current_user_ok():
    tok = create_access_token("alice")
    user = get_current_user(_bearer(tok))
    assert user == "alice"


def test_missing_header_and_wrong_scheme():
    # niente credenziali -> 401
    with pytest.raises(Exception) as e1:
        get_current_user(None)
    assert getattr(e1.value, "status_code", 0) == 401

    # schema non Bearer -> 401
    with pytest.raises(Exception) as e2:
        get_current_user(NS(scheme="Basic", credentials="whatever"))
    assert getattr(e2.value, "status_code", 0) == 401


def test_access_token_expired_raises_token_expired():
    # token scaduto (exp nel passato)
    expired = jwt.encode(
        {"sub": "bob", "type": "access", "iat": 0, "exp": 1},
        settings.JWT_SECRET,
        algorithm="HS256",
    )
    with pytest.raises(Exception) as e:
        get_current_user(_bearer(expired))
    assert getattr(e.value, "status_code", 0) == 401
    # il dettaglio proviene da _decode
    assert getattr(e.value, "detail", "") == "Token expired"


def test_access_token_completely_invalid_string():
    with pytest.raises(Exception) as e:
        get_current_user(_bearer("not.a.jwt"))
    assert getattr(e.value, "status_code", 0) == 401
    assert getattr(e.value, "detail", "") == "Invalid token"


def test_refresh_token_ok_and_decode_refresh_ok():
    rt = create_refresh_token("carol")
    payload = decode_refresh(rt)
    assert payload["sub"] == "carol"
    assert payload["type"] == "refresh"


def test_decode_refresh_with_access_token_is_rejected():
    at = create_access_token("dave")
    with pytest.raises(Exception) as e:
        decode_refresh(at)
    assert getattr(e.value, "status_code", 0) == 401
    assert getattr(e.value, "detail", "") == "Invalid refresh token"


def test_get_current_user_with_refresh_token_is_rejected():
    # se passo un refresh come Bearer deve fallire (tipo errato)
    rt = create_refresh_token("erin")
    with pytest.raises(Exception) as e:
        get_current_user(_bearer(rt))
    assert getattr(e.value, "status_code", 0) == 401
    assert getattr(e.value, "detail", "") == "Invalid token"


def test_refresh_fallback_to_access_secret(monkeypatch):
    # forza l'uso del fallback: nessun JWT_REFRESH_SECRET -> usa JWT_SECRET
    monkeypatch.setattr(settings, "JWT_REFRESH_SECRET", None)
    rt = create_refresh_token("frank")
    payload = decode_refresh(rt)  # deve decodificare correttamente
    assert payload["sub"] == "frank"
    assert payload["type"] == "refresh"