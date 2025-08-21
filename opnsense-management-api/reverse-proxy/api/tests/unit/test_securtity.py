from datetime import datetime, timezone
import jwt
import pytest
import importlib, sys
from types import SimpleNamespace as NS
from src.config import settings

def _sec():
    if "src.utils.security" in sys.modules:
        importlib.reload(sys.modules["src.utils.security"])
    else:
        importlib.import_module("src.utils.security")
    return sys.modules["src.utils.security"]

def _bearer(tok): return NS(scheme="Bearer", credentials=tok)

def _detail(exc):
    d = getattr(exc, "detail", "")
    return d if isinstance(d, str) else str(d)

def test_decode_refresh_expired_raises_401_expired():
    """Copre il ramo ExpiredSignatureError dentro _decode chiamato da decode_refresh."""
    sec = _sec()
    secret = settings.JWT_REFRESH_SECRET or settings.JWT_SECRET
    # refresh token già scaduto (exp=1)
    expired_rt = jwt.encode(
        {"sub": "user", "type": "refresh", "iat": 0, "exp": 1},
        secret,
        algorithm="HS256",
    )
    with pytest.raises(Exception) as e:
        sec.decode_refresh(expired_rt)
    assert getattr(e.value, "status_code", 0) == 401
    assert "expired" in _detail(e.value).lower()

def test_refresh_uses_custom_secret_if_set(monkeypatch):
    """Quando JWT_REFRESH_SECRET è impostato, il refresh è firmato con quel secret (non con JWT_SECRET)."""
    monkeypatch.setattr(settings, "JWT_REFRESH_SECRET", "REFRESH_ONLY_SECRET")
    sec = _sec()  # ricarico per usare il nuovo secret
    rt = sec.create_refresh_token("zoe")

    # non decodificabile con l'access secret
    with pytest.raises(Exception):
        jwt.decode(rt, settings.JWT_SECRET, algorithms=["HS256"])

    # ma decodificabile con il refresh secret
    payload = jwt.decode(rt, "REFRESH_ONLY_SECRET", algorithms=["HS256"])
    assert payload["sub"] == "zoe" and payload["type"] == "refresh"

def test_get_current_user_rejects_token_with_wrong_custom_type():
    """Token con type diverso da 'access' deve cadere nel ramo 'Invalid token'."""
    sec = _sec()
    tok = jwt.encode(
        {"sub": "mike", "type": "service", "iat": 0, "exp": 9999999999},
        settings.JWT_SECRET,
        algorithm="HS256",
    )
    with pytest.raises(Exception) as e:
        sec.get_current_user(_bearer(tok))
    assert getattr(e.value, "status_code", 0) == 401
    assert "invalid" in _detail(e.value).lower()