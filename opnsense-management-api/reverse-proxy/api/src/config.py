# src/config.py
from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import field_validator


class Settings(BaseSettings):
    # ---------- DMZ app ----------
    DMZ_HOST: str = "0.0.0.0"
    DMZ_PORT: int = 8000
    LOG_LEVEL: str = "INFO"

    # ---------- Demo auth ----------
    DEMO_USERNAME: str = "admin"
    DEMO_PASSWORD: str = "changeme"

    # Access token
    JWT_SECRET: str = "change_me"
    JWT_EXPIRE_MINUTES: int = 60

    # Refresh token (se non impostato usa JWT_SECRET)
    JWT_REFRESH_SECRET: str | None = None
    JWT_REFRESH_EXPIRE_DAYS: int = 7

    # ---------- Upstream wrapper (FastAPI in LAN) ----------
    # Deve puntare alla base e includere /api (qui lo forziamo nel validator)
    WRAPPER_BASE_URL: str = "http://10.0.1.50:8080/api"
    WRAPPER_VERIFY_SSL: bool = False
    WRAPPER_TIMEOUT: int = 5

    # Carica automaticamente .env e ignora extra
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Normalizza l'URL e assicura il suffisso /api
    @field_validator("WRAPPER_BASE_URL")
    @classmethod
    def _ensure_api_suffix(cls, v: str) -> str:
        v = (v or "").strip().rstrip("/")
        if not v.endswith("/api"):
            v = v + "/api"
        return v


settings = Settings()