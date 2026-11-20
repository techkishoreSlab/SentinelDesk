"""Application settings loaded from the environment and validated at startup.

Secret values are held in ``SecretStr`` and are never included in validation
messages, logs or the integration status report.
"""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, ValidationInfo, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

REPO_ENV_FILE = Path(__file__).resolve().parents[3] / ".env"
PLACEHOLDER_MARKERS = ("replace-with", "change_me", "changeme")
_ORIGIN_RE = re.compile(r"^https?://[A-Za-z0-9.\-]+(:\d{1,5})?$")
_OPTIONAL_FIELDS = (
    "migration_database_url",
    "app_db_password",
    "job_signing_private_key_path",
    "job_signing_public_key_path",
    "gemini_api_key",
    "gemini_model",
    "entra_tenant_id",
    "entra_client_id",
    "entra_client_secret",
    "entra_redirect_uri",
    "graph_sender",
    "graph_scopes",
    "threat_intel_provider",
    "threat_intel_api_key",
)


def _is_placeholder(value: str) -> bool:
    lowered = value.lower()
    return any(marker in lowered for marker in PLACEHOLDER_MARKERS)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=REPO_ENV_FILE,
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    app_env: Literal["development", "test", "production"] = "development"
    app_name: str = Field(default="SentinelDesk", max_length=64)
    api_base_url: str = "http://localhost:8000"
    web_base_url: str = "http://localhost:5173"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    session_secret: SecretStr
    cors_allowed_origins: str = "http://localhost:5173"
    max_request_bytes: int = Field(default=1_048_576, ge=1024, le=10_485_760)

    # Runtime connection uses the least-privilege `sentinel_app` role; migrations use the owner.
    database_url: SecretStr
    migration_database_url: SecretStr | None = None
    app_db_password: SecretStr | None = None
    db_pool_size: int = Field(default=5, ge=1, le=50)
    db_max_overflow: int = Field(default=5, ge=0, le=50)

    local_auth_enabled: bool = True
    session_idle_minutes: int = Field(default=30, ge=5, le=240)
    session_absolute_hours: int = Field(default=8, ge=1, le=24)
    login_max_failures: int = Field(default=5, ge=3, le=20)
    login_lockout_minutes: int = Field(default=15, ge=1, le=120)
    entra_jit_provisioning: bool = True

    job_signing_private_key_path: Path | None = None
    job_signing_public_key_path: Path | None = None

    gemini_api_key: SecretStr | None = None
    gemini_model: str | None = Field(default=None, max_length=80)
    gemini_timeout_seconds: float = Field(default=30.0, ge=1.0, le=120.0)
    gemini_max_output_tokens: int = Field(default=256, ge=64, le=1024)

    entra_tenant_id: str | None = None
    entra_client_id: str | None = None
    entra_client_secret: SecretStr | None = None
    entra_redirect_uri: str | None = None

    graph_sender: str | None = None
    graph_scopes: str | None = None

    threat_intel_provider: Literal["virustotal"] | None = None
    threat_intel_api_key: SecretStr | None = None
    # Decision D3: mandatory threat check fails closed on INDETERMINATE.
    threat_intel_mandatory: bool = True
    threat_intel_cache_ttl_seconds: int = Field(default=3600, ge=60, le=86_400)
    # Comma-separated SHA-256 digests (organisation-controlled). Denied wins over pinned.
    threat_intel_denied_digests: str = ""
    threat_intel_pinned_digests: str = ""

    device_enrollment_ttl_minutes: int = Field(default=10, ge=1, le=60)
    job_ttl_minutes: int = Field(default=15, ge=1, le=120)
    heartbeat_interval_seconds: int = Field(default=60, ge=10, le=3600)
    device_credential_ttl_days: int = Field(default=30, ge=1, le=365)
    # A device with no heartbeat within this window is treated as stale for compatibility.
    device_stale_after_seconds: int = Field(default=900, ge=60, le=86_400)
    # Host path (or container mount) where admin-ingested .pkg files are staged for the agent.
    package_store_dir: str = Field(default="/Users/Shared/SentinelDesk/packages")
    # Catalogue ingest uploads (pkg). Separate from general JSON API body limit when used.
    catalogue_upload_max_bytes: int = Field(
        default=200 * 1024 * 1024, ge=1_048_576, le=512 * 1024 * 1024
    )

    @field_validator(*_OPTIONAL_FIELDS, mode="before")
    @classmethod
    def _blank_is_none(cls, value: object) -> object:
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @field_validator("session_secret")
    @classmethod
    def _validate_session_secret(cls, value: SecretStr) -> SecretStr:
        raw = value.get_secret_value()
        if len(raw) < 32:
            raise ValueError("SESSION_SECRET must be at least 32 characters")
        if _is_placeholder(raw):
            raise ValueError("SESSION_SECRET still contains the placeholder value")
        return value

    @field_validator("database_url", "migration_database_url")
    @classmethod
    def _validate_database_url(cls, value: SecretStr | None) -> SecretStr | None:
        if value is None:
            return None
        parts = urlsplit(value.get_secret_value())
        if parts.scheme != "postgresql+asyncpg":
            raise ValueError("DATABASE_URL must use the postgresql+asyncpg scheme")
        if not parts.hostname or not parts.path.strip("/"):
            raise ValueError("DATABASE_URL must include a host and database name")
        if parts.password and _is_placeholder(parts.password):
            raise ValueError("DATABASE_URL still contains the placeholder password")
        return value

    @field_validator("api_base_url", "web_base_url")
    @classmethod
    def _validate_base_url(cls, value: str) -> str:
        if not _ORIGIN_RE.match(value.rstrip("/")):
            raise ValueError("base URLs must be http(s)://host[:port] without a path")
        return value.rstrip("/")

    @field_validator("cors_allowed_origins")
    @classmethod
    def _validate_cors(cls, value: str) -> str:
        origins = [o.strip() for o in value.split(",") if o.strip()]
        if not origins:
            raise ValueError("CORS_ALLOWED_ORIGINS must list at least one origin")
        for origin in origins:
            if not _ORIGIN_RE.match(origin):
                raise ValueError("CORS origins must be explicit http(s)://host[:port] values")
        return ",".join(origins)

    @field_validator("job_signing_private_key_path", "job_signing_public_key_path")
    @classmethod
    def _validate_key_path(cls, value: Path | None, info: ValidationInfo) -> Path | None:
        if value is not None and not value.is_file():
            raise ValueError(f"{(info.field_name or '').upper()} does not point to a file")
        return value

    @model_validator(mode="after")
    def _validate_groups(self) -> Settings:
        entra = [self.entra_tenant_id, self.entra_client_id, self.entra_client_secret]
        if any(entra) and not all(entra):
            raise ValueError(
                "ENTRA_TENANT_ID, ENTRA_CLIENT_ID and ENTRA_CLIENT_SECRET must be set together"
            )
        if (self.graph_sender or self.graph_scopes) and not self.entra_configured:
            raise ValueError("GRAPH_* settings require the Entra ID settings")
        if bool(self.gemini_api_key) != bool(self.gemini_model):
            raise ValueError("GEMINI_API_KEY and GEMINI_MODEL must be set together")
        if bool(self.job_signing_private_key_path) != bool(self.job_signing_public_key_path):
            raise ValueError("Both JOB_SIGNING_*_KEY_PATH values must be set together")
        if self.threat_intel_api_key and not self.threat_intel_provider:
            raise ValueError("THREAT_INTEL_API_KEY requires THREAT_INTEL_PROVIDER")
        if self.app_env == "production":
            self._validate_production()
        return self

    def _validate_production(self) -> None:
        if "local_auth_enabled" not in self.model_fields_set:
            raise ValueError("LOCAL_AUTH_ENABLED must be set explicitly in production")
        if not self.api_base_url.startswith("https://"):
            raise ValueError("API_BASE_URL must use https in production")
        if any(not o.startswith("https://") for o in self.cors_origins):
            raise ValueError("CORS origins must use https in production")
        if not self.job_signing_private_key_path:
            raise ValueError("Job signing keys are required in production")

    @property
    def cors_origins(self) -> list[str]:
        return self.cors_allowed_origins.split(",")

    @property
    def migration_url(self) -> str:
        return (self.migration_database_url or self.database_url).get_secret_value()

    @property
    def entra_issuer(self) -> str:
        return f"https://login.microsoftonline.com/{self.entra_tenant_id}/v2.0"

    @property
    def effective_entra_redirect_uri(self) -> str:
        return self.entra_redirect_uri or f"{self.web_base_url}/api/v1/auth/callback"

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"

    @property
    def entra_configured(self) -> bool:
        return bool(self.entra_tenant_id and self.entra_client_id and self.entra_client_secret)

    def integration_status(self) -> dict[str, str]:
        """Configured/not-configured flags only; never secret values."""

        def flag(ok: bool) -> str:
            return "configured" if ok else "not_configured"

        return {
            "gemini": flag(bool(self.gemini_api_key and self.gemini_model)),
            "entra_id": flag(self.entra_configured),
            "outlook_graph": flag(self.entra_configured and bool(self.graph_sender)),
            "threat_intel": flag(bool(self.threat_intel_provider and self.threat_intel_api_key)),
            "job_signing": flag(bool(self.job_signing_private_key_path)),
        }


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
