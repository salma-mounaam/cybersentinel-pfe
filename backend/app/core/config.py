from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List


class Settings(BaseSettings):
    APP_NAME: str = "CyberSentinel"
    VERSION: str = "2.0.0"
    DEBUG: bool = False
    SECRET_KEY: str = "changeme"

    # ============================================================
    # PostgreSQL
    # ============================================================
    POSTGRES_DB: str = "cybersentinel"
    POSTGRES_USER: str = "csadmin"
    POSTGRES_PASSWORD: str = "cspassword"
    POSTGRES_HOST: str = "postgres"
    POSTGRES_PORT: int = 5432

    # URL calculée automatiquement si non fournie dans .env
    DATABASE_URL: str | None = None

    # ============================================================
    # Redis / Celery
    # ============================================================
    REDIS_URL: str = "redis://redis:6379/0"
    CELERY_BROKER_URL: str = "redis://redis:6379/0"
    CELERY_RESULT_BACKEND: str = "redis://redis:6379/1"

    # ============================================================
    # CORS
    # ============================================================
    ALLOWED_ORIGINS: str = "http://localhost:3000"

    # ============================================================
    # ML
    # ============================================================
    ML_ANOMALY_THRESHOLD: float = 0.45
    ML_IF_WEIGHT: float = 0.35
    ML_AE_WEIGHT: float = 0.35
    ML_OCSVM_WEIGHT: float = 0.30

    # ============================================================
    # Risk Scoring
    # ============================================================
    SCORE_R_WEIGHT_A: float = 0.35
    SCORE_R_WEIGHT_V: float = 0.30
    SCORE_R_WEIGHT_E: float = 0.25
    SCORE_R_WEIGHT_C: float = 0.10

    # ============================================================
    # Suricata
    # ============================================================
    SURICATA_EVE_LOG: str = "/var/log/suricata/eve.json"

    # ============================================================
    # Agent ingestion / Fluent Bit
    # ============================================================
    AGENT_INGEST_TOKEN: str = "cs_1d48075f3ed91d0e84c7e00f977dd0ca0ab0c930"

    # ============================================================
    # DAST / Docker Compose
    # ============================================================
    CYBERSENTINEL_COMPOSE_FILE: str = "/app/docker-compose.yml"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    def __init__(self, **values):
        super().__init__(**values)

        if not self.DATABASE_URL:
            self.DATABASE_URL = (
                f"postgresql://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
                f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
            )


settings = Settings()