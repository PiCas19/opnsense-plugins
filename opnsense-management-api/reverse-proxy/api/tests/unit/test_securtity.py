# tests/unit/test_security.py
from datetime import datetime, timedelta, timezone
import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials

from src.utils import security
from src.config import settings

def _past():
    return datetime.now(tz=timezone.utc) - timedelta(minutes=10)

def test_access_refresh_roundtrip_and_get_current_user():
    at = security.create_access_token("alice")
    rt = security.create_refresh_token("alice")
    assert isinstance(at, str) and isinstance(rt, str)

    payload_r = security.decode_refresh(rt)
    assert payload_r["sub"] == "alice"
    assert payload_r["type"] == "refresh"

    # get_current_user con Bearer access token
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=at)
    assert security.get_current_user(creds) == "alice"

def test_get_current_user_missing_header():
    with pytest.raises(HTTPException) as e:
        security.get_current_user(None)  # type: ignore[arg-type]
    assert e.value.status_code == 401

def test_get_current_user_invalid_type_uses_refresh_token():
    rt = security.create_refresh_token("bob")
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=rt)
    with pytest.raises(HTTPException) as e:
        security.get_current_user(creds)
    assert e.value.status_code == 401
    assert "Invalid token" in str(e.value.detail)

def test_decode_refresh_refuses_access_token():
    at = security.create_access_token("carol")
    with pytest.raises(HTTPException) as e:
        security.decode_refresh(at)
    assert e.value.status_code == 401

def test_expired_access_token(monkeypatch):
    # creo un token già scaduto: monkeypatch di _now()
    monkeypatch.setattr(security, "_now", lambda: _past())
    expired = security.create_access_token("dave")

    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=expired)
    with pytest.raises(HTTPException) as e:
        security.get_current_user(creds)
    assert e.value.status_code == 401
    assert "expired" in str(e.value.detail).lower()