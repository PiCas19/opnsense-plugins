from fastapi import APIRouter, Query, Path, HTTPException
from pydantic import BaseModel, Field
from typing import Optional
from src.opnsense.client import client
from src.opnsense.errors import HttpError

router = APIRouter(prefix="/api/rules", tags=["rules"])

class ToggleBody(BaseModel):
    enabled: Optional[bool] = Field(default=None)
    apply: bool = False

class UpdateBody(BaseModel):
    rule: dict

class CreateBody(BaseModel):
    rule: dict
    apply: bool = False

@router.get("")
def list_rules(search: str = Query(default="", description="Filtro descrizione")):
    try:
        res = client.search_rules(search_phrase=search or "")
        return {"success": True, "total": res.get("total", 0), "rows": res.get("rows", [])}
    except HttpError as e:
        raise HTTPException(status_code=(502 if e.status >= 500 else e.status),
                            detail={"upstream": e.status, "body": e.body})

@router.get("/{uuid}")
def get_rule(uuid: str = Path(...)):
    try:
        rule = client.get_rule(uuid)
        if not rule:
            raise HTTPException(status_code=404, detail="Regola non trovata")
        return {"success": True, "rule": rule}
    except HttpError as e:
        raise HTTPException(status_code=(502 if e.status >= 500 else e.status),
                            detail={"upstream": e.status, "body": e.body})

@router.post("")
def create_rule(body: CreateBody):
    try:
        res = client.add_rule(body.rule)
        if body.apply:
            client.apply()
        return {"success": True, "result": res, "applied": body.apply}
    except HttpError as e:
        raise HTTPException(status_code=(502 if e.status >= 500 else e.status),
                            detail={"upstream": e.status, "body": e.body})

@router.post("/{uuid}/toggle")
def toggle_rule(uuid: str, body: ToggleBody):
    try:
        res = client.toggle_rule(uuid, body.enabled)
        if body.apply:
            client.apply()
        return {"success": True, "result": res, "applied": body.apply}
    except HttpError as e:
        raise HTTPException(status_code=(502 if e.status >= 500 else e.status),
                            detail={"upstream": e.status, "body": e.body})

@router.put("/{uuid}")
def update_rule(uuid: str, body: UpdateBody):
    try:
        res = client.set_rule(uuid, body.rule)
        return {"success": True, "result": res}
    except HttpError as e:
        raise HTTPException(status_code=(502 if e.status >= 500 else e.status),
                            detail={"upstream": e.status, "body": e.body})

@router.delete("/{uuid}")
def delete_rule(uuid: str):
    try:
        res = client.del_rule(uuid)
        return {"success": True, "result": res}
    except HttpError as e:
        raise HTTPException(status_code=(502 if e.status >= 500 else e.status),
                            detail={"upstream": e.status, "body": e.body})

@router.post("/apply")
def apply_config():
    try:
        res = client.apply()
        return {"success": True, "result": res}
    except HttpError as e:
        raise HTTPException(status_code=(502 if e.status >= 500 else e.status),
                            detail={"upstream": e.status, "body": e.body})
