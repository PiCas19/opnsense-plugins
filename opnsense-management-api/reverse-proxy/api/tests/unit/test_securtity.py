# tests/unit/test_security.py
from types import SimpleNamespace as NS
import jwt
import pytest

from src.utils.security import (
    create_access_token, create_refresh_token,
    decode_refresh, get_current_user
)
from src.config import settings

def test_access_token_and_current_user_ok():
    t = create_access_token("alice")
    user = get_current_user(NS(scheme="Bearer", credentials=t))
    assert user == "alice"

def test_missing_or_bad_scheme_unauthorized():
    with pytest.raises(Exception):
        get_current_user(None)                # manca header

    with pytest.raises(Exception):
        get_current_user(NS(scheme="Basic", credentials="x"))  # schema errato

def test_refresh_token_ok_and_invalid_type():
    rt = create_refresh_token("bob")
    payload = decode_refresh(rt)
    assert payload["sub"] == "bob" and payload["type"] == "refresh"

    # passare un access come refresh deve fallire
    at = create_access_token("bob")
    with pytest.raises(Exception):
        decode_refresh(at)

def test_access_token_expired_raises():
    expired = jwt.encode(
        {"sub":"zzz","type":"access","iat":0,"exp":1},
        settings.JWT_SECRET, algorithm="HS256"
    )
    with pytest.raises(Exception):
        get_current_user(NS(scheme="Bearer", credentials=expired))
