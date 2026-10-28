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

    # Optional integrations. Values are supplied through the MA_* environment
    # variables and are never written into an exported playbook.
    claude_enabled: bool = False
    anthropic_api_key: str = ""
    anthropic_model: str = "claude-sonnet-4-5"
    anthropic_version: str = "2023-06-01"
    anthropic_max_tokens: int = 6000

    gitlab_url: str = "https://gitlab.invinsense.dev"
    gitlab_enabled: bool = False
    gitlab_token: str = ""
    gitlab_default_project: str = "infopercept/xdr/uec/uec"
    gitlab_auto_create_issues: bool = False
    gitlab_auto_issue_mode: str = "finding"  # consolidated | finding

    uec_base_url: str = "https://platform-dev.invinsense.dev/xdr/uec"
    uec_tenant: str = "default"
    uec_enabled: bool = False
    uec_token: str = ""
    uec_username: str = ""
    uec_password: str = ""
    uec_correlation_enabled: bool = True
    uec_match_grace_seconds: int = 180
    uec_timeout_seconds: float = 15.0

settings = Settings()
