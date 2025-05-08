import os
from typing import Optional
from pydantic_settings import BaseSettings
from pydantic import EmailStr, PostgresDsn, validator


class Settings(BaseSettings):
    PROJECT_NAME: str = "Suricata Alert System"
    API_V1_STR: str = "/api/v1"
    DATABASE_URL: PostgresDsn
    SURICATA_EVE_PATH: str
    SURICATA_POLL_INTERVAL: int = 5  # seconds
    EPSS_API_URL: str = "https://api.first.org/data/v1/epss"
    EPSS_OFFLINE_CSV_PATH: Optional[str] = None
    EPSS_USE_OFFLINE: bool = False
    SMTP_HOST: str = "smtp.gmail.com"
    SMTP_PORT: int = 587
    SMTP_TLS: bool = True
    SMTP_USER: Optional[str] = None
    SMTP_PASSWORD: Optional[str] = None

    EMAILS_FROM_EMAIL: EmailStr
    EMAILS_TO_EMAIL: EmailStr
    LOG_LEVEL: str = "INFO"

    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()
