"""Integration harness: a disposable `*_test` database, migrated to head, cleaned per test.

Required environment (the Makefile target derives these from .env):
  TEST_DATABASE_URL            runtime role (sentinel_app) on the test database
  TEST_MIGRATION_DATABASE_URL  owner role on the test database (create/drop, migrate, cleanup)
  APP_DB_PASSWORD              runtime role password, used by migration 0003
"""

from __future__ import annotations

import os
import subprocess
import sys
import uuid
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass
from pathlib import Path

import httpx
import pytest
from sqlalchemy import select, text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from app.auth.passwords import hash_password
from app.auth.tokens import new_token
from app.core.config import Settings
from app.db.enums import IdentityProvider, RoleName
from app.db.session import Database
from app.main import create_app
from app.users.models import LocalCredential, Role, User, UserRole
from tests.conftest import make_settings

BACKEND_DIR = Path(__file__).resolve().parents[2]
WEB_ORIGIN = "http://localhost:5173"
KEEP_TABLES = {"roles", "alembic_version"}


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    for item in items:
        if Path(str(item.fspath)).is_relative_to(Path(__file__).parent):
            item.add_marker(pytest.mark.integration)


def _env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        pytest.skip(f"{name} not set; run `make backend-integration`")
    return value


@pytest.fixture(scope="session")
def test_db_urls() -> Iterator[tuple[str, str]]:
    app_url, owner_url = _env("TEST_DATABASE_URL"), _env("TEST_MIGRATION_DATABASE_URL")
    db_name = make_url(owner_url).database or ""
    if not db_name.endswith("_test") or make_url(app_url).database != db_name:
        pytest.exit("refusing to run: test database name must end in _test and match", 2)
    yield app_url, owner_url


@pytest.fixture(scope="session")
async def migrated_database(test_db_urls: tuple[str, str]) -> AsyncIterator[tuple[str, str]]:
    app_url, owner_url = test_db_urls
    db_name = make_url(owner_url).database
    admin = create_async_engine(
        make_url(owner_url).set(database="postgres"), isolation_level="AUTOCOMMIT"
    )
    async with admin.connect() as conn:
        await conn.execute(text(f'DROP DATABASE IF EXISTS "{db_name}" WITH (FORCE)'))
        await conn.execute(text(f'CREATE DATABASE "{db_name}"'))
    await admin.dispose()
    env = {
        **os.environ,
        "DATABASE_URL": app_url,
        "MIGRATION_DATABASE_URL": owner_url,
        "APP_DB_PASSWORD": _env("APP_DB_PASSWORD"),
    }
    proc = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=BACKEND_DIR,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        pytest.exit(f"test database migration failed:\n{proc.stderr[-2000:]}", 2)
    yield app_url, owner_url


@pytest.fixture(scope="session")
async def owner_engine(migrated_database: tuple[str, str]) -> AsyncIterator[AsyncEngine]:
    engine = create_async_engine(migrated_database[1])
    yield engine
    await engine.dispose()


@pytest.fixture(autouse=True)
async def _clean_tables(owner_engine: AsyncEngine) -> AsyncIterator[None]:
    yield
    async with owner_engine.begin() as conn:
        tables = (
            await conn.execute(text("SELECT tablename FROM pg_tables WHERE schemaname = 'public'"))
        ).scalars()
        names = [t for t in tables if t not in KEEP_TABLES]
        # replica mode disables the append-only audit triggers for this cleanup transaction only.
        await conn.execute(text("SET LOCAL session_replication_role = replica"))
        await conn.execute(
            text(f"TRUNCATE {', '.join(f'"{n}"' for n in names)} RESTART IDENTITY CASCADE")
        )


@pytest.fixture
def settings(migrated_database: tuple[str, str]) -> Settings:
    return make_settings(
        database_url=migrated_database[0],
        cors_allowed_origins=WEB_ORIGIN,
        web_base_url=WEB_ORIGIN,
        max_request_bytes=1_048_576,
    )


@pytest.fixture
async def app_db(settings: Settings) -> AsyncIterator[Database]:
    db = Database(settings)
    yield db
    await db.dispose()


@pytest.fixture
async def client(settings: Settings, app_db: Database) -> AsyncIterator[httpx.AsyncClient]:
    app = create_app(settings, app_db)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    ) as c:
        yield c


@dataclass(frozen=True)
class SeededUser:
    id: uuid.UUID
    email: str
    password: str


@pytest.fixture
def make_user(app_db: Database):  # type: ignore[no-untyped-def]
    async def _make(email: str, roles: list[RoleName], *, active: bool = True) -> SeededUser:
        password = new_token(18)
        async with app_db.sessionmaker() as s:
            user = User(
                email=email,
                display_name=email.split("@")[0],
                identity_provider=IdentityProvider.LOCAL,
                is_active=active,
            )
            s.add(user)
            await s.flush()
            s.add(LocalCredential(user_id=user.id, password_hash=hash_password(password)))
            for role in roles:
                role_id = await s.scalar(select(Role.id).where(Role.name == role))
                s.add(UserRole(user_id=user.id, role_id=role_id))
            await s.commit()
            return SeededUser(user.id, email, password)

    return _make


async def login(client: httpx.AsyncClient, user: SeededUser) -> httpx.Response:
    resp = await client.post(
        "/api/v1/auth/login",
        json={"email": user.email, "password": user.password},
        headers={"Origin": WEB_ORIGIN},
    )
    assert resp.status_code == 200, resp.text
    return resp


def csrf_headers(client: httpx.AsyncClient) -> dict[str, str]:
    return {"Origin": WEB_ORIGIN, "X-CSRF-Token": client.cookies["sd_csrf"]}
