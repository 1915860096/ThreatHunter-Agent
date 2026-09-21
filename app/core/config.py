"""Application settings loaded from environment variables and `.env`."""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration for the ThreatHunter Agent service."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    app_name: str = "threathunter-agent"
    app_version: str = "0.1.0"
    database_url: str = (
        "postgresql+psycopg://threathunter:threathunter@localhost:5432/threathunter"
    )
    llm_provider: str = "deepseek"
    llm_model: str = "deepseek-chat"
    llm_api_key: str | None = None


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide settings instance."""
    return Settings()
