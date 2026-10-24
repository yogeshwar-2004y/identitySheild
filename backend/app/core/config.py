"""Runtime configuration, loaded from environment variables only (no secrets in code)."""
from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=None, extra="ignore")

    app_env: str = "lab"
    database_url: str
    migration_database_url: str | None = None
    redis_url: str

    keycloak_internal_url: str = "http://keycloak:8080"
    keycloak_public_url: str = "http://localhost:8080"
    kc_admin_username: str = "kcadmin"
    kc_admin_password: str = ""
    api_internal_url: str = "http://api:8000"
    public_url: str = "http://localhost:5173"
    oidc_client_id: str = "identityshield-web"

    cookie_secure: bool = True
    jwt_secret: str = Field(min_length=32)
    jwt_issuer: str = "identityshield-api"
    encryption_key: str
    ingest_hmac_secret: str
    platform_api_key: str

    lab_mode: bool = False
    lab_api_key: str = ""
    demo_password: str = ""

    # Defaults; every tenant can override them in tenants.settings.
    access_token_ttl_seconds: int = 300
    idle_timeout_minutes: int = 15
    absolute_timeout_hours: int = 8
    max_concurrent_sessions: int = 3

    rate_limit_auth_per_minute: int = 60
    rate_limit_api_per_minute: int = 600

    @property
    def refresh_cookie_name(self) -> str:
        # The __Host- prefix requires Secure, Path=/ and no Domain attribute.
        return "__Host-is_rt" if self.cookie_secure else "is_rt"

    @property
    def csrf_cookie_name(self) -> str:
        return "__Host-is_csrf" if self.cookie_secure else "is_csrf"


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
