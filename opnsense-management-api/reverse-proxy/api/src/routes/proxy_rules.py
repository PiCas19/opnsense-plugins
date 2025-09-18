import httpx
from fastapi import APIRouter, Depends, HTTPException, Path, Query
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
def list_rules(
    interface: str = Query(description="MANDATORY. Interfaccia: lan/wan/dmz o multiple lan|dmz|wan"),
    search: str = Query(default="", description="Filtro su descrizione (case-insensitive)"),
    row_count: int = Query(default=2000, ge=1, le=10000, description="Quante righe max restituire"),
    user: str = Depends(get_current_user)
):
    """
    Ritorna le regole filtrate dal wrapper.
    Supporta filtro per interface multipla con sintassi lan|dmz|wan.
    Interface è obbligatorio, automation_only è sempre False.
    """
    url = f"{settings.WRAPPER_BASE_URL}/rules"
    
    # Costruisce i parametri per il wrapper
    params = {
        "interface": interface,
        "automation_only": False  # Sempre False come richiesto
    }
    
    if search:
        params["search"] = search
    if row_count != 2000:  # solo se diverso dal default
        params["row_count"] = row_count
    
    with client() as c:
        r = c.get(url, params=params)
        if r.status_code != 200:
            raise_upstream(r)
        return r.json()

@router.get("/{uuid}")
def get_rule(uuid: str = Path(...), user: str = Depends(get_current_user)):
    url = f"{settings.WRAPPER_BASE_URL}/rules/{uuid}"
    with client() as c:
        r = c.get(url)
        if r.status_code != 200:
            raise_upstream(r)
        return r.json()

@router.post("")
def create_rule(body: CreateBody, user: str = Depends(get_current_user)):
    url = f"{settings.WRAPPER_BASE_URL}/rules"
    with client() as c:
        r = c.post(url, json=body.dict())
        if r.status_code != 200:
            raise_upstream(r)
        return r.json()

@router.post("/{uuid}/toggle")
def toggle_rule(uuid: str, body: ToggleBody, user: str = Depends(get_current_user)):
    url = f"{settings.WRAPPER_BASE_URL}/rules/{uuid}/toggle"
    with client() as c:
        r = c.post(url, json=body.dict())
        if r.status_code != 200:
            raise_upstream(r)
        return r.json()

@router.put("/{uuid}")
def update_rule(uuid: str, body: UpdateBody, user: str = Depends(get_current_user)):
    url = f"{settings.WRAPPER_BASE_URL}/rules/{uuid}"
    with client() as c:
        r = c.put(url, json=body.dict())
        if r.status_code != 200:
            raise_upstream(r)
        return r.json()

@router.delete("/{uuid}")
def delete_rule(uuid: str, user: str = Depends(get_current_user)):
    url = f"{settings.WRAPPER_BASE_URL}/rules/{uuid}"
    with client() as c:
        r = c.delete(url)
        if r.status_code != 200:
            raise_upstream(r)
        return r.json()

@router.post("/apply")
def apply(user: str = Depends(get_current_user)):
    url = f"{settings.WRAPPER_BASE_URL}/rules/apply"
    with client() as c:
        r = c.post(url)
        if r.status_code != 200:
            raise_upstream(r)
        return r.json()

def raise_upstream(r: httpx.Response):
    try:
        body = r.json()
    except Exception:
        body = r.text
    status = 502 if 500 <= r.status_code <= 599 else r.status_code
    raise HTTPException(status_code=status, detail={"upstream": r.status_code, "body": body})