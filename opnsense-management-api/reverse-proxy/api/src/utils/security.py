from datetime import datetime, timedelta, timezone
import jwt
from fastapi import HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from src.config import settings

_security = HTTPBearer(auto_error=False)

def _now():
    return datetime.now(tz=timezone.utc)

def _encode(payload: dict, secret: str) -> str:
    return jwt.encode(payload, secret, algorithm="HS256")

def _decode(token: str, secret: str) -> dict:
    try:
        return jwt.decode(token, secret, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

# -------- tokens --------
def create_access_token(sub: str) -> str:
    now = _now()
    payload = {
        "sub": sub,
        "type": "access",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=settings.JWT_EXPIRE_MINUTES)).timestamp()),
    }
    return _encode(payload, settings.JWT_SECRET)

def create_refresh_token(sub: str) -> str:
    now = _now()
    payload = {
        "sub": sub,
        "type": "refresh",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(days=settings.JWT_REFRESH_EXPIRE_DAYS)).timestamp()),
    }
    secret = settings.JWT_REFRESH_SECRET or settings.JWT_SECRET
    return _encode(payload, secret)

def decode_refresh(token: str) -> dict:
    payload = _decode(token, settings.JWT_REFRESH_SECRET or settings.JWT_SECRET)
    if payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    return payload

def get_current_user(creds: HTTPAuthorizationCredentials = Depends(_security)) -> str:
    if not creds or creds.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
    payload = _decode(creds.credentials, settings.JWT_SECRET)
    if payload.get("type") != "access":
        raise HTTPException(status_code=401, detail="Invalid token")
    return payload.get("sub")
