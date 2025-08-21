import logging
import os

# Livello da env, default INFO
LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

# Formato coerente per tutti i logger
FORMAT = "%(asctime)s %(levelname)s %(name)s - %(message)s"

# Configurazione base
logging.basicConfig(level=LEVEL, format=FORMAT)

# Allinea i logger di uvicorn/fastapi allo stesso formato/livello
for name in ("uvicorn", "uvicorn.error", "uvicorn.access", "fastapi"):
    logging.getLogger(name).setLevel(LEVEL)

logger = logging.getLogger("opnsense-wrapper")