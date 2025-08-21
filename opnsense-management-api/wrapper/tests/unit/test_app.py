# tests/unit/test_app_endpoints.py
from fastapi.testclient import TestClient
from pathlib import Path

from src.app import api, SWAGGER_PATH


def test_root_endpoint_ok():
    client = TestClient(api)
    r = client.get("/")
    assert r.status_code == 200
    j = r.json()
    assert j["ok"] is True
    assert j["service"] == "opnsense-wrapper-python"
    # link utili mostrati in home
    assert j["docs"] == "/docs"
    assert j["swagger"] == "/swagger.yaml"


def test_swagger_yaml_served_with_correct_media_type():
    client = TestClient(api)

    # il file deve esistere nel repo
    assert isinstance(SWAGGER_PATH, Path) and SWAGGER_PATH.exists(), SWAGGER_PATH

    # scarico via endpoint
    r = client.get("/swagger.yaml")
    assert r.status_code == 200

    # content-type impostato dal FileResponse
    ctype = r.headers.get("content-type", "").lower()
    assert "yaml" in ctype or "text/plain" in ctype  # robusto tra runtime diversi

    # contenuto identico al file su disco
    on_disk = SWAGGER_PATH.read_bytes()
    assert r.content == on_disk
    assert len(r.content) > 0
