"""
Application Configuration and Settings.
Supports SQLite (zero-config default) and PostgreSQL via DATABASE_URL.
"""

import os
from pathlib import Path
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    APP_NAME: str = "Automated Web & API Vulnerability Scanner"
    APP_VERSION: str = "2.0.0"
    DEBUG: bool = False

    # Database: defaults to local SQLite, or PostgreSQL if DATABASE_URL is set
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./scanner.db")

    # Scanner defaults
    DEFAULT_TIMEOUT: int = 10
    DEFAULT_MAX_DEPTH: int = 3
    DEFAULT_MAX_ENDPOINTS: int = 60
    DEFAULT_CONCURRENCY: int = 10
    USER_AGENT: str = "Antigravity-SecScanner/2.0 (+https://antigravity-scanner.local)"

    # Paths
    BASE_DIR: Path = Path(__file__).resolve().parent.parent
    TEMPLATES_DIR: Path = BASE_DIR / "nuclei" / "templates"
    REPORTS_DIR: Path = BASE_DIR / "reports"

    # CORS
    CORS_ORIGINS: list = ["*"]

    class Config:
        env_file = ".env"
        extra = "allow"


settings = Settings()
