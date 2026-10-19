from pydantic_settings import BaseSettings, SettingsConfigDict
from pathlib import Path


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="MA_")

    app_name: str = "Atomic Prevention"
    app_version: str = "0.1.0"
    debug: bool = False

    database_url: str = "sqlite+aiosqlite:///./atomic_prevention.db"

    data_dir: Path = Path("./data")
    mitre_cache_dir: Path = Path("./data/mitre_cache")

    cors_origins: list[str] = ["http://localhost:3000"]

settings = Settings()
