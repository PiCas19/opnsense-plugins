# src/opnsense/client.py
from __future__ import annotations

from typing import Any, Optional, Dict, List
from urllib.parse import quote

import requests

from src import config
from src.opnsense.errors import HttpError
from src.utils.logger import logger


class OpnSenseClient:
    """Client minimale per gli endpoint firewall/filter di OPNsense."""

    def __init__(self):
        # OPNSENSE_URL deve includere /api (es: https://fw:8443/api)
        self.base = config.OPNSENSE_URL.rstrip("/")
        self.auth = (config.OPNSENSE_KEY, config.OPNSENSE_SECRET)
        self.verify = config.OPNSENSE_VERIFY_SSL
        self.timeout = config.OPNSENSE_TIMEOUT

    # ------------- HTTP core -------------
    def _req(
        self,
        method: str,
        path: str,
        *,
        json: Optional[dict] = None,
        data: Optional[dict | str] = None,
        headers: Optional[dict] = None,
    ) -> Any:
        if not path.startswith("/"):
            path = "/" + path
        url = f"{self.base}{path}"

        r = requests.request(
            method=method,
            url=url,
            auth=self.auth,
            json=json,
            data=data,
            headers=headers,
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
    def search_rules(
        self,
        search_phrase: str = "",
        row_count: int = 2000,
        filters: Optional[List[Dict[str, str]]] = None,
        sort_sequence_asc: bool = True,
    ) -> dict:
        """
        Tenta le varianti più compatibili di /firewall/filter/searchRule.
        1) POST form-encoded (camelCase)  <-- preferita
        2) POST form-encoded (snake_case)
        3) GET ?show_all=1 (diagnostica, include pseudo-rules)
        """
        # ---- 1) POST form-encoded camelCase
        form = {
            "current": 1,
            "rowCount": row_count,
            "searchPhrase": search_phrase or "",
        }
        if sort_sequence_asc:
            form["sort[sequence]"] = "asc"
        if filters:
            # filters = [{"column":"category","value":"automation"}, ...]
            for i, f in enumerate(filters):
                form[f"filters[{i}][column]"] = f.get("column", "")
                form[f"filters[{i}][value]"] = f.get("value", "")

        try:
            res = self._req(
                "POST",
                "/firewall/filter/searchRule",
                data=form,
                headers={"Accept": "application/json",
                         "Content-Type": "application/x-www-form-urlencoded"},
            )
            if res and isinstance(res, dict) and res.get("rows"):
                return res
        except HttpError as e:
            logger.debug("searchRule form-encoded (camelCase) fallita: %s", e)

        # ---- 2) POST form-encoded snake_case (alcune build)
        try:
            res2 = self._req(
                "POST",
                "/firewall/filter/search_rule",
                data=form,
                headers={"Accept": "application/json",
                         "Content-Type": "application/x-www-form-urlencoded"},
            )
            if res2 and isinstance(res2, dict) and res2.get("rows"):
                return res2
        except HttpError as e:
            logger.debug("search_rule form-encoded (snake_case) fallita: %s", e)

        # ---- 3) GET show_all=1 (di emergenza, include anche pseudo-rules)
        try:
            res3 = self._req(
                "GET",
                "/firewall/filter/searchRule?show_all=1",
                headers={"Accept": "application/json"},
            )
            # normalizza per coerenza
            if isinstance(res3, dict) and "rows" in res3:
                return res3
        except HttpError as e:
            logger.debug("searchRule GET show_all fallita: %s", e)

        return {"total": 0, "rowCount": 0, "current": 1, "rows": []}

    def search_rules_direct(
        self,
        *,
        interface: Optional[str] = None,
        show_all: bool = True
    ) -> dict:
        """
        Chiama direttamente l'endpoint OPNsense con parametri GET.
        Se interface è specificata, usa la sintassi lan|dmz|wan per multiple interfacce.
        """
        params = []
        if show_all:
            params.append("show_all=1")
        if interface:
            params.append(f"interface={interface}")
        
        query_string = "&".join(params)
        path = f"/firewall/filter/searchRule?{query_string}"
        
        logger.debug("Chiamata diretta API: %s", path)
        
        try:
            res = self._req(
                "GET",
                path,
                headers={"Accept": "application/json"},
            )
            return res if isinstance(res, dict) else {"rows": []}
        except HttpError as e:
            logger.debug("searchRule direct API fallita: %s", e)
            return {"rows": []}

    def search_rules_clean(
        self,
        *,
        interface: Optional[str] = None,
        automation_only: bool = False,
        row_count: int = 2000,
    ) -> List[dict]:
        """
        Ritorna SOLO le regole configurate (niente default/auto/pf_rules).
        Se automation_only=True filtra su category='automation' o descr che contiene 'automation'.
        Se interface è valorizzata, può essere una singola interfaccia o multiple separate da | (es: 'lan|dmz|wan').
        Se interface è None, restituisce regole di tutte le interfacce.
        """
        
        # Usa la chiamata diretta all'API OPNsense
        res = self.search_rules_direct(interface=interface, show_all=True)
        
        rows = res.get("rows", []) or []
        logger.debug("Regole trovate dalla ricerca diretta: %d", len(rows))
        
        # Filtra le regole generate automaticamente
        cleaned = []
        for r in rows:
            # campi che identificano regole generate/sistema
            if r.get("legacy") is True:
                continue
            if r.get("pf_rules") is True:
                continue
            if r.get("generated") is True:  # aggiunto controllo per generated
                continue
                
            descr = (r.get("description") or r.get("descr") or "").strip()
            
            # filtra le note di sistema conosciute
            sys_match = any(
                key in descr.lower()
                for key in [
                    "default deny",
                    "anti-lockout",
                    "ipv6 rfc",
                    "bogon",
                    "system rule",
                    "state violation",
                    "auto-generated",
                    "generated rule",
                ]
            )
            if sys_match:
                continue
                
            # Filtra regole senza descrizione (spesso generate automaticamente)
            if not descr:
                continue
                
            cleaned.append(r)

        logger.debug("Regole dopo pulizia (rimosse system/generated rules): %d", len(cleaned))

        if automation_only:
            before_automation = len(cleaned)
            cleaned = [
                r
                for r in cleaned
                if (r.get("category") == "automation")
                or ("automation" in (r.get("descr") or r.get("description") or "").lower())
            ]
            logger.debug("Regole dopo filtro automation_only: %d (erano %d)", len(cleaned), before_automation)

        # Debug: mostra un campione delle interfacce trovate
        if cleaned:
            interfaces_found = set()
            for r in cleaned[:10]:  # primi 10 per non intasare i log
                iface = r.get("interface", "N/A")
                interfaces_found.add(iface)
            logger.debug("Interfacce trovate (campione): %s", sorted(interfaces_found))

        return cleaned

    def get_rule(self, uuid: str) -> Optional[dict]:
        uid = quote(str(uuid).strip(), safe="")
        try:
            res = self._req("GET", f"/firewall/filter/getRule/{uid}")
            return res.get("rule") or res
        except HttpError as e1:
            logger.debug("getRule non disponibile, fallback a get_rule: %s", e1)
            res2 = self._req("GET", f"/firewall/filter/get_rule/{uid}")
            return res2.get("rule") or res2

    def add_rule(self, rule: dict) -> dict:
        # consiglio: passa sempre 'category': 'automation' se vuoi ritrovarle facilmente
        return self._req("POST", "/firewall/filter/addRule", json={"rule": rule})

    def set_rule(self, uuid: str, rule: dict) -> dict:
        uid = quote(str(uuid).strip(), safe="")
        return self._req("POST", f"/firewall/filter/setRule/{uid}", json={"rule": rule})

    def del_rule(self, uuid: str) -> dict:
        uid = quote(str(uuid).strip(), safe="")
        return self._req("POST", f"/firewall/filter/delRule/{uid}", json={})

    def toggle_rule(self, uuid: str, enabled: Optional[bool] = None) -> dict:
        uid = quote(str(uuid).strip(), safe="")
        suffix = "" if enabled is None else ("/1" if enabled else "/0")
        return self._req("POST", f"/firewall/filter/toggleRule/{uid}{suffix}")

    def apply(self, revision: Optional[str] = None) -> dict:
        path = "/firewall/filter/apply" + (f"/{revision}" if revision else "")
        # body vuoto per evitare 411 Length Required
        return self._req("POST", path, data="")

    def savepoint(self) -> dict:
        return self._req("POST", "/firewall/filter/savepoint", data="")


# Istanza globale del client
client = OpnSenseClient()