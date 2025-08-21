from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from src.config import settings
from src.utils.security import (
    create_access_token,
    create_refresh_token,
    decode_refresh,
)

router = APIRouter(prefix="/api/auth", tags=["auth"])

class LoginBody(BaseModel):
    username: str
    password: str

class RefreshBody(BaseModel):
    refresh_token: str

@router.post("/login")
def login(body: LoginBody):
    if body.username == settings.DEMO_USERNAME and body.password == settings.DEMO_PASSWORD:
        access = create_access_token(sub=body.username)
        refresh = create_refresh_token(sub=body.username)
        return {
            "access_token": access,
            "refresh_token": refresh,
            "token_type": "bearer",
            "expires_in": settings.JWT_EXPIRE_MINUTES * 60,
        }
    raise HTTPException(status_code=401, detail="Invalid credentials")

@router.post("/refresh")
def refresh(body: RefreshBody):
    payload = decode_refresh(body.refresh_token)
    sub = payload["sub"]
    # semplice rotazione per la demo
    new_access = create_access_token(sub)
    new_refresh = create_refresh_token(sub)
    return {
        "access_token": new_access,
        "refresh_token": new_refresh,
        "token_type": "bearer",
        "expires_in": settings.JWT_EXPIRE_MINUTES * 60,
    }