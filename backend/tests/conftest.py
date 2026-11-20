from __future__ import annotations

import os
import secrets
from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource

from app.core.config import Settings
from app.db.session import Database
from app.main import create_app

TEST_DATABASE_URL = os.environ.get(
    "TEST_DATABASE_URL", "postgresql+asyncpg://sentinel:test@localhost:5432/sentinel"
)


class IsolatedSettings(Settings):
    """Built only from explicit values, so a developer's .env or shell never leaks into tests."""

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        return (init_settings,)


def make_settings(**overrides: Any) -> Settings:
    values: dict[str, Any] = {
        "app_env": "test",
        "session_secret": secrets.token_urlsafe(48),
        "database_url": TEST_DATABASE_URL,
        "cors_allowed_origins": "http://localhost:5173",
        "max_request_bytes": 4096,
    }
    values.update(overrides)
    return IsolatedSettings(**values)


class FakeDatabase(Database):
    """Stands in for PostgreSQL in unit tests; integration tests use the real database."""

    def __init__(self, healthy: bool) -> None:
        self.healthy = healthy

    async def ping(self, timeout_seconds: float = 2.0) -> bool:
        return self.healthy

    async def dispose(self) -> None:
        return None


@pytest.fixture
def settings() -> Settings:
    return make_settings()


async def _client(settings: Settings, db: Database) -> AsyncIterator[httpx.AsyncClient]:
    app = create_app(settings, db)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client


@pytest.fixture
async def client(settings: Settings) -> AsyncIterator[httpx.AsyncClient]:
    async for c in _client(settings, FakeDatabase(healthy=True)):
        yield c


@pytest.fixture
async def unhealthy_client(settings: Settings) -> AsyncIterator[httpx.AsyncClient]:
    async for c in _client(settings, FakeDatabase(healthy=False)):
        yield c
