"""Application configuration.

All configuration is sourced from environment variables (optionally loaded from a
`.env` file during development). No secrets or environment-specific values are
hardcoded in the codebase.
"""

from __future__ import annotations

from enum import Enum
from functools import lru_cache

from pydantic import Field, computed_field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Environment(str, Enum):
    """Deployment environment the application is running in."""

    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


class Settings(BaseSettings):
    """Strongly-typed application settings loaded from the environment."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
        populate_by_name=True,
    )

    # ---- General ----
    environment: Environment = Environment.DEVELOPMENT
    log_level: str = "INFO"
    log_json: bool = False

    project_name: str = "DevOps AI Auditor"
    api_v1_prefix: str = "/api/v1"

    # ---- Backend API ----
    backend_host: str = "0.0.0.0"
    backend_port: int = 8000
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"

    # ---- Security / hardening ----
    # When set, every /api/v1 request (except health) must present this key via
    # the `X-API-Key` header. Empty means the API is open (development default).
    api_key: str = Field(default="", repr=False)
    # In-process request rate limiting (per client IP). Defaults are generous;
    # tune down for public exposure. Uploads get a separate, stricter budget.
    rate_limit_enabled: bool = True
    rate_limit_requests: int = 600
    rate_limit_window_seconds: int = 60
    rate_limit_upload_requests: int = 30
    # Trust X-Forwarded-For for the client IP (only enable behind a trusted proxy).
    trust_forwarded_for: bool = False

    # ---- PostgreSQL ----
    postgres_host: str = "localhost"
    postgres_port: int = 5432
    postgres_user: str = "auditor"
    postgres_password: str = Field(default="", repr=False)
    postgres_db: str = "auditor"

    # ---- Redis ----
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_db: int = 0
    redis_password: str = Field(default="", repr=False)

    # ---- Database override ----
    # When set (env DATABASE_URL), this takes precedence over the composed
    # PostgreSQL URL. Useful for tests (e.g. sqlite+aiosqlite) and managed DBs.
    database_url_override: str = Field(default="", alias="DATABASE_URL")

    # ---- Ingestion / uploads ----
    # Maximum accepted upload size for a repository archive.
    max_upload_size_mb: int = 100
    # Comma-separated list of accepted archive extensions.
    allowed_upload_extensions: str = ".zip"
    # Hard caps applied during safe extraction to defend against archive bombs.
    max_repository_files: int = 20_000
    max_uncompressed_size_mb: int = 1024
    max_compression_ratio: int = 200
    # Root directory for isolated, per-scan extraction workspaces. Empty means a
    # dedicated subdirectory under the system temp directory is used.
    workspace_root: str = ""

    # ---- Ingestion / git ----
    # Enable cloning repositories directly from a URL (POST /scans/git).
    git_ingestion_enabled: bool = True
    # Maximum seconds a clone may run before it is aborted.
    git_clone_timeout: int = 120
    # Optional comma-separated host allowlist (e.g. "github.com,gitlab.com").
    # Empty means any http(s) host is accepted.
    git_allowed_hosts: str = ""
    # Permit cloning from local paths / file:// URLs. Off by default for SSRF and
    # local-file hygiene; primarily enabled by the test suite.
    git_allow_local_clones: bool = False

    # ---- Scanners / external tools ----
    # Hadolint and Trivy are used only when their binaries are on PATH. Trivy is
    # additionally gated by this flag because base-image scanning needs network
    # access and can be slow.
    docker_enable_hadolint: bool = True
    docker_enable_trivy: bool = False
    # Kubernetes external tools (used only when the binary is present on PATH).
    k8s_enable_kubeconform: bool = True
    k8s_enable_kubelinter: bool = True
    k8s_enable_trivy: bool = False
    # Terraform external tools (used only when the binary is present on PATH).
    tf_enable_terraform: bool = True
    tf_enable_tflint: bool = True
    tf_enable_checkov: bool = True
    tf_enable_trivy: bool = False
    # CI/CD external tools (used only when the binary is present on PATH).
    cicd_enable_actionlint: bool = True
    # Secret scanning. Gitleaks is used only when present; git-history scanning is
    # off unless explicitly enabled by the user.
    secrets_enable_gitleaks: bool = True
    secrets_scan_history: bool = False

    # ---- AI reasoning layer (LLM) ----
    # Provider: "none" (deterministic fallback), "openai", or "anthropic".
    llm_provider: str = "none"
    llm_model: str = "gpt-4o-mini"
    llm_api_key: str = Field(default="", repr=False)
    llm_base_url: str = ""
    llm_temperature: float = 0.0
    llm_max_retries: int = 2
    llm_timeout: int = 60
    # Timeout (seconds) for any external scanner invocation.
    external_tool_timeout: int = 120

    @computed_field  # type: ignore[prop-decorator]
    @property
    def cors_origins_list(self) -> list[str]:
        """CORS origins parsed into a clean list."""
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    @property
    def cors_allow_wildcard(self) -> bool:
        """True if CORS is configured to allow any origin ('*')."""
        return "*" in self.cors_origins_list

    @property
    def auth_enabled(self) -> bool:
        """True if API-key authentication is enforced."""
        return bool(self.api_key)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def database_url(self) -> str:
        """Async SQLAlchemy connection URL.

        Returns the explicit override when provided, otherwise composes an
        asyncpg PostgreSQL URL from the individual settings.
        """
        if self.database_url_override:
            return self.database_url_override
        return (
            f"postgresql+asyncpg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def max_upload_size_bytes(self) -> int:
        return self.max_upload_size_mb * 1024 * 1024

    @property
    def max_uncompressed_size_bytes(self) -> int:
        return self.max_uncompressed_size_mb * 1024 * 1024

    @property
    def allowed_upload_extensions_set(self) -> set[str]:
        return {
            ext.strip().lower()
            for ext in self.allowed_upload_extensions.split(",")
            if ext.strip()
        }

    @property
    def git_allowed_hosts_set(self) -> set[str]:
        """Lower-cased set of allowed clone hosts (empty = allow any host)."""
        return {
            host.strip().lower()
            for host in self.git_allowed_hosts.split(",")
            if host.strip()
        }

    @computed_field  # type: ignore[prop-decorator]
    @property
    def redis_url(self) -> str:
        """Connection URL for Redis (used by cache and the Celery broker)."""
        auth = f":{self.redis_password}@" if self.redis_password else ""
        return f"redis://{auth}{self.redis_host}:{self.redis_port}/{self.redis_db}"

    @property
    def is_production(self) -> bool:
        return self.environment == Environment.PRODUCTION


@lru_cache
def get_settings() -> Settings:
    """Return a cached Settings instance.

    Cached so configuration is parsed once per process. Tests can clear the cache
    via `get_settings.cache_clear()`.
    """
    return Settings()
