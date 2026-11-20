from __future__ import annotations

import secrets
from pathlib import Path

import pytest
from pydantic import ValidationError

from tests.conftest import make_settings


def test_valid_settings_load() -> None:
    s = make_settings()
    assert s.app_env == "test"
    assert s.cors_origins == ["http://localhost:5173"]


@pytest.mark.parametrize(
    "secret",
    ["short", "replace-with-random-development-secret-xxxxxxxxxx", "x" * 31],
)
def test_weak_or_placeholder_session_secret_rejected(secret: str) -> None:
    with pytest.raises(ValidationError):
        make_settings(session_secret=secret)


def test_validation_error_does_not_echo_secret_value() -> None:
    secret = "replace-with-" + secrets.token_hex(20)
    with pytest.raises(ValidationError) as exc:
        make_settings(session_secret=secret)
    assert secret not in str(exc.value)


@pytest.mark.parametrize(
    "url",
    [
        "postgresql://u:p@localhost/db",
        "sqlite+aiosqlite:///x.db",
        "postgresql+asyncpg://u:p@localhost/",
        "postgresql+asyncpg://u:replace-with-pw@localhost/db",
    ],
)
def test_invalid_database_url_rejected(url: str) -> None:
    with pytest.raises(ValidationError):
        make_settings(database_url=url)


@pytest.mark.parametrize("origins", ["*", "http://localhost:5173/path", "", "ftp://x.com"])
def test_cors_wildcards_and_paths_rejected(origins: str) -> None:
    with pytest.raises(ValidationError):
        make_settings(cors_allowed_origins=origins)


def test_partial_entra_config_rejected() -> None:
    with pytest.raises(ValidationError):
        make_settings(entra_tenant_id="tenant", entra_client_id="client")


def test_graph_requires_entra() -> None:
    with pytest.raises(ValidationError):
        make_settings(graph_sender="it@example.com")


def test_gemini_key_requires_model() -> None:
    with pytest.raises(ValidationError):
        make_settings(gemini_api_key="k" * 30)


def test_blank_optional_values_are_none() -> None:
    s = make_settings(gemini_api_key="", gemini_model="", threat_intel_provider="")
    assert s.gemini_api_key is None
    assert s.threat_intel_provider is None


def test_missing_key_file_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValidationError):
        make_settings(
            job_signing_private_key_path=tmp_path / "missing.pem",
            job_signing_public_key_path=tmp_path / "missing.pub",
        )


def test_production_requires_https_and_signing_keys() -> None:
    with pytest.raises(ValidationError):
        make_settings(app_env="production")
    with pytest.raises(ValidationError):
        make_settings(
            app_env="production",
            api_base_url="https://api.example.com",
            cors_allowed_origins="https://app.example.com",
        )


def test_integration_status_reports_flags_only() -> None:
    key = "AIza" + secrets.token_hex(16)
    s = make_settings(gemini_api_key=key, gemini_model="model-x")
    status = s.integration_status()
    assert status["gemini"] == "configured"
    assert status["threat_intel"] == "not_configured"
    assert status["outlook_graph"] == "not_configured"
    assert key not in repr(status)
    assert key not in repr(s)
