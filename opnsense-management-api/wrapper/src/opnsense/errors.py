from __future__ import annotations


class HttpError(Exception):
    """Errore HTTP proveniente dall'upstream OPNsense.

    Attributes:
        status: codice di stato HTTP upstream
        body:   corpo risposta (dict o string)
        url:    url completo chiamato
    """
    def __init__(self, status: int, body, url: str):
        super().__init__(f"HTTP {status}")
        self.status = status
        self.body = body
        self.url = url

    def __repr__(self) -> str:
        return f"HttpError(status={self.status}, url={self.url!r}, body={self.body!r})"