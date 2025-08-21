from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from src.config import settings
from src.utils.security import create_access_token

router = APIRouter(prefix="/api/auth", tags=["auth"])

class LoginBody(BaseModel):
    username: str
    password: str

@router.post("/login")
def login(body: LoginBody):
    if body.username == settings.DEMO_USERNAME and body.password == settings.DEMO_PASSWORD:
        token = create_access_token(sub=body.username)
        return {"access_token": token, "token_type": "bearer"}
    raise HTTPException(status_code=401, detail="Invalid credentials")