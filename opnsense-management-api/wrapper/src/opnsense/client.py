from __future__ import annotations

from typing import Any, Optional
from urllib.parse import quote

import requests

from src import config
from src.opnsense.errors import HttpError
from src.utils.logger import logger


class OpnSenseClient:
    """Client minimale per gli endpoint firewall/filter di OPNsense."""

    def __init__(self):
        # OPNSENSE_URL deve includere /api
        self.base = config.OPNSENSE_URL.rstrip("/")
        self.auth = (config.OPNSENSE_KEY, config.OPNSENSE_SECRET)
        self.verify = config.OPNSENSE_VERIFY_SSL
        self.timeout = config.OPNSENSE_TIMEOUT

    # ------------- HTTP core -------------
    def _req(self, method: str, path: str, json: Optional[dict] = None) -> Any:
        url = f"{self.base}{path}"
        r = requests.request(
            method=method,
            url=url,
            auth=self.auth,
            json=json,
            verify=self.verify,
            timeout=self.timeout,
        )
        logger.debug("%s %s -> %s", method, path, r.status_code)

        if r.status_code >= 400:
            try:
                body = r.json()
            except Exception:
                body = r.text
            raise HttpError(r.status_code, body, url)

        if not r.text:
            return {}
        try:
            return r.json()
        except Exception:
            return r.text

    # ------------- firewall/filter -------------
    def search_rules(self, search_phrase: str = "", row_count: int = 2000) -> dict:
        """POST /api/firewall/filter/searchRule"""
        payload = {
            "current": 1,
            "rowCount": row_count,
            "sort": {"sequence": "asc"},
            "searchPhrase": search_phrase or "",
        }
        return self._req("POST", "/api/firewall/filter/searchRule", json=payload)

    def get_rule(self, uuid: str) -> Optional[dict]:
        """GET /api/firewall/filter/getRule/{uuid} con fallback a get_rule."""
        uid = quote(str(uuid).strip(), safe="")
        # tenta camelCase, poi snake_case (compatibile con la tua istanza)
        try:
            res = self._req("GET", f"/api/firewall/filter/getRule/{uid}")
            return res.get("rule") or res
        except HttpError as e1:
            logger.debug("getRule non disponibile, fallback a get_rule: %s", e1)
            res2 = self._req("GET", f"/api/firewall/filter/get_rule/{uid}")
            return res2.get("rule") or res2

    def add_rule(self, rule: dict) -> dict:
        """POST /api/firewall/filter/addRule  body: {'rule': {...}}"""
        return self._req("POST", "/api/firewall/filter/addRule", json={"rule": rule})

    def set_rule(self, uuid: str, rule: dict) -> dict:
        """POST /api/firewall/filter/setRule/{uuid}  body: {'rule': {...}}"""
        uid = quote(str(uuid).strip(), safe="")
        return self._req("POST", f"/api/firewall/filter/setRule/{uid}", json={"rule": rule})

    def del_rule(self, uuid: str) -> dict:
        """POST /api/firewall/filter/delRule/{uuid}"""
        uid = quote(str(uuid).strip(), safe="")
        return self._req("POST", f"/api/firewall/filter/delRule/{uid}", json={})

    def toggle_rule(self, uuid: str, enabled: Optional[bool] = None) -> dict:
        """POST /api/firewall/filter/toggleRule/{uuid}/{0|1}  (suffix vuoto = toggle puro)"""
        uid = quote(str(uuid).strip(), safe="")
        suffix = "" if enabled is None else ("/1" if enabled else "/0")
        return self._req("POST", f"/api/firewall/filter/toggleRule/{uid}{suffix}")

    def apply(self, revision: Optional[str] = None) -> dict:
        """POST /api/firewall/filter/apply[/revision]"""
        path = "/api/firewall/filter/apply" + (f"/{revision}" if revision else "")
        return self._req("POST", path)

    def savepoint(self) -> dict:
        """POST /api/firewall/filter/savepoint"""
        return self._req("POST", "/api/firewall/filter/savepoint")


# Singleton comodo da importare
client = OpnSenseClient()