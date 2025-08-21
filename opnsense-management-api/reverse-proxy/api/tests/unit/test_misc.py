# tests/unit/test_misc.py
def test_logger_import_side_effects():
    # verifico che il modulo si importi senza errori e fornisca un logger
    from src.utils.logger import logger
    assert logger.name == "dmz"

def test_app_loaded_title_and_routes():
    from src.app import api
    assert "DMZ BFF" in api.title
    # routings principali presenti
    paths = {r.path for r in api.router.routes}
    assert any(p.startswith("/api/auth") for p in paths)
    assert any(p.startswith("/api/rules") for p in paths)