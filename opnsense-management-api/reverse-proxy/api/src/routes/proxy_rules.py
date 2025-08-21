import httpx
from fastapi import APIRouter, Depends, HTTPException, Path, Query, Body
from pydantic import BaseModel
from src.config import settings
from src.utils.security import get_current_user

router = APIRouter(prefix="/api/rules", tags=["rules"])

def client():
    return httpx.Client(timeout=settings.WRAPPER_TIMEOUT, verify=settings.WRAPPER_VERIFY_SSL)

class ToggleBody(BaseModel):
    enabled: bool | None = None
    apply: bool = False

class CreateBody(BaseModel):
    rule: dict
    apply: bool = False

class UpdateBody(BaseModel):
    rule: dict

@router.get("")
def list_rules(search: str = Query(default=""), user: str = Depends(get_current_user)):
    url = f"{settings.WRAPPER_BASE_URL}/rules"
    with client() as c:
        r = c.get(url, params={"search": search})
    if r.status_code != 200:
        _raise_upstream(r)
    return r.json()

@router.get("/{uuid}")
def get_rule(uuid: str = Path(...), user: str = Depends(get_current_user)):
    url = f"{settings.WRAPPER_BASE_URL}/rules/{uuid}"
    with client() as c:
        r = c.get(url)
    if r.status_code != 200:
        _raise_upstream(r)
    return r.json()

@router.post("")
def create_rule(body: CreateBody, user: str = Depends(get_current_user)):
    url = f"{settings.WRAPPER_BASE_URL}/rules"
    with client() as c:
        r = c.post(url, json=body.dict())
    if r.status_code != 200:
        _raise_upstream(r)
    return r.json()

@router.post("/{uuid}/toggle")
def toggle_rule(uuid: str, body: ToggleBody, user: str = Depends(get_current_user)):
    url = f"{settings.WRAPPER_BASE_URL}/rules/{uuid}/toggle"
    with client() as c:
        r = c.post(url, json=body.dict())
    if r.status_code != 200:
        _raise_upstream(r)
    return r.json()

@router.put("/{uuid}")
def update_rule(uuid: str, body: UpdateBody, user: str = Depends(get_current_user)):
    url = f"{settings.WRAPPER_BASE_URL}/rules/{uuid}"
    with client() as c:
        r = c.put(url, json=body.dict())
    if r.status_code != 200:
        _raise_upstream(r)
    return r.json()

@router.delete("/{uuid}")
def delete_rule(uuid: str, user: str = Depends(get_current_user)):
    url = f"{settings.WRAPPER_BASE_URL}/rules/{uuid}"
    with client() as c:
        r = c.delete(url)
    if r.status_code != 200:
        _raise_upstream(r)
    return r.json()

@router.post("/apply")
def apply(user: str = Depends(get_current_user)):
    url = f"{settings.WRAPPER_BASE_URL}/rules/apply"
    with client() as c:
        r = c.post(url)
    if r.status_code != 200:
        _raise_upstream(r)
    return r.json()

def _raise_upstream(r: httpx.Response):
    try:
        body = r.json()
    except Exception:
        body = r.text
    status = 502 if 500 <= r.status_code <= 599 else r.status_code
    raise HTTPException(status_code=status, detail={"upstream": r.status_code, "body": body})