import os
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    DMZ_HOST: str = "0.0.0.0"
    DMZ_PORT: int = 8000
    LOG_LEVEL: str = "INFO"

    DEMO_USERNAME: str = "admin"
    DEMO_PASSWORD: str = "changeme"
    JWT_SECRET: str = "change_me"
    JWT_EXPIRE_MINUTES: int = 60

    WRAPPER_BASE_URL: str = "http://10.0.1.50:8080/api"
    WRAPPER_VERIFY_SSL: bool = False
    WRAPPER_TIMEOUT: int = 5


settings = Settings()