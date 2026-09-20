from functools import lru_cache

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_env: str = "dev"
    database_url: str = "postgresql+asyncpg://acsr:acsr@localhost:5433/acsr"
    redis_url: str = "redis://localhost:6380/0"
    github_webhook_secret: SecretStr = SecretStr("")
    github_token: SecretStr = SecretStr("")
    llm_provider: str = "groq"
    anthropic_api_key: SecretStr = SecretStr("")
    llm_model: str = "openai/gpt-oss-120b"
    groq_api_key: SecretStr = SecretStr("")
    groq_base_url: str = "https://api.groq.com/openai/v1"
    llm_tokens_per_minute: int = 7000
    llm_reasoning_effort: str = "low"
    llm_max_retries: int = 5
    llm_timeout_s: float = 90.0
    # USD per 1M tokens (input, output); used for cost reporting only
    llm_price_in: float = 0.15
    llm_price_out: float = 0.60
    github_api_url: str = "https://api.github.com"
    git_base_url: str = "https://github.com"
    enable_codeql: bool = True
    enable_discovery: bool = True
    admin_api_token: SecretStr = SecretStr(
        ""
    )  # empty disables the dashboard/approval API (fail closed)
    cors_origins: str = "http://localhost:5173"
    enable_remediation: bool = (
        False  # generate + verify patches after a scan (PRs still need human approval)
    )
    remediation_max_targets: int = 5
    github_offline: bool = (
        False  # never call GitHub: reports are stored, not posted (demo / dry-run)
    )
    metrics_port: int = 0  # worker Prometheus endpoint; 0 disables
    use_mcp: bool = True  # route scanners and GitHub writes through the MCP server
    scanner_timeout_s: int = 600
    scan_job_timeout_s: int = 1800
    post_pr_comments: bool = True
    allow_github_write: bool = False  # write tools stay off until remediation is authorized
    scan_token_budget: int = 200_000


@lru_cache
def get_settings() -> Settings:
    return Settings()
