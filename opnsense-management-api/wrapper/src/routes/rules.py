from fastapi import APIRouter, Query, Path, HTTPException
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any

from src.opnsense.client import client
from src.opnsense.errors import HttpError

router = APIRouter(prefix="/api/rules", tags=["rules"])


class ToggleBody(BaseModel):
    enabled: Optional[bool] = Field(default=None)
    apply: bool = False


class UpdateBody(BaseModel):
    rule: Dict[str, Any]


class CreateBody(BaseModel):
    rule: Dict[str, Any]
    apply: bool = False


@router.get("")
def list_rules(
    search: str = Query(default="", description="Filtro su descrizione (case-insensitive)"),
    interface: Optional[str] = Query(default=None, description="Interfaccia: lan/wan/… (se non specificata prende tutte)"),
    automation_only: bool = Query(default=False, description="Solo regole in categoria 'automation'"),
    row_count: int = Query(default=2000, ge=1, le=10000, description="Quante righe max restituire"),
):
    """
    Ritorna *solo* le regole configurate (niente default deny / anti-lockout / RFC).
    - se `automation_only=True` filtra category='automation' o descr che contiene 'automation'
    - se `interface` è valorizzata, filtra per interfaccia, altrimenti prende tutte le interfacce
    - se `search` è valorizzata, filtra sulla descrizione lato API e lato client
    """
    try:
        # Se interface è None, passiamo None al client che dovrebbe gestirlo come "tutte le interfacce"
        rows = client.search_rules_clean(
            interface=interface,  # None = tutte le interfacce
            automation_only=automation_only,
            row_count=row_count,
        )

        # filtro di ricerca client-side su descrizione/description
        if search:
            s = search.lower()
            rows = [
                r for r in rows
                if s in (r.get("descr") or r.get("description") or "").lower()
            ]

        return {"success": True, "total": len(rows), "rows": rows}
    except HttpError as e:
        raise HTTPException(
            status_code=(502 if e.status >= 500 else e.status),
            detail={"upstream": e.status, "body": e.body},
        )


@router.get("/{uuid}")
def get_rule(uuid: str = Path(...)):
    try:
        rule = client.get_rule(uuid)
        if not rule:
            raise HTTPException(status_code=404, detail="Regola non trovata")
        return {"success": True, "rule": rule}
    except HttpError as e:
        raise HTTPException(
            status_code=(502 if e.status >= 500 else e.status),
            detail={"upstream": e.status, "body": e.body},
        )


@router.post("")
def create_rule(body: CreateBody):
    """
    Nota: se vuoi che compaia nella cartella GUI 'Automation', includi
    nel body.rule: {"category": "automation"} e un descr significativo.
    """
    try:
        res = client.add_rule(body.rule)
        if body.apply:
            client.apply()
        return {"success": True, "result": res, "applied": body.apply}
    except HttpError as e:
        raise HTTPException(
            status_code=(502 if e.status >= 500 else e.status),
            detail={"upstream": e.status, "body": e.body},
        )


@router.put("/{uuid}")
def update_rule(uuid: str, body: UpdateBody):
    try:
        res = client.set_rule(uuid, body.rule)
        return {"success": True, "result": res}
    except HttpError as e:
        raise HTTPException(
            status_code=(502 if e.status >= 500 else e.status),
            detail={"upstream": e.status, "body": e.body},
        )


@router.post("/{uuid}/toggle")
def toggle_rule(uuid: str, body: ToggleBody):
    try:
        res = client.toggle_rule(uuid, body.enabled)
        if body.apply:
            client.apply()
        return {"success": True, "result": res, "applied": body.apply}
    except HttpError as e:
        raise HTTPException(
            status_code=(502 if e.status >= 500 else e.status),
            detail={"upstream": e.status, "body": e.body},
        )


@router.delete("/{uuid}")
def delete_rule(uuid: str):
    try:
        res = client.del_rule(uuid)
        return {"success": True, "result": res}
    except HttpError as e:
        raise HTTPException(
            status_code=(502 if e.status >= 500 else e.status),
            detail={"upstream": e.status, "body": e.body},
        )


@router.post("/apply")
def apply_config():
    try:
        # Il client manda un body vuoto (-d ''), quindi niente 411
        res = client.apply()
        return {"success": True, "result": res}
    except HttpError as e:
        raise HTTPException(
            status_code=(502 if e.status >= 500 else e.status),
            detail={"upstream": e.status, "body": e.body},
        )