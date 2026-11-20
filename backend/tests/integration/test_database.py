"""Schema, least-privilege role and append-only audit guarantees on real PostgreSQL."""

from __future__ import annotations

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine

from app.audit import service as audit
from app.db.enums import ActorType, AuditResult
from app.db.session import Database
from tests.conftest import make_settings


async def test_ready_against_real_postgres(client: httpx.AsyncClient) -> None:
    resp = await client.get("/health/ready")
    assert resp.status_code == 200, resp.text


async def test_migrations_at_head_with_roles_seeded(owner_engine: AsyncEngine) -> None:
    async with owner_engine.connect() as conn:
        version = (await conn.execute(text("SELECT version_num FROM alembic_version"))).scalar()
        roles = (await conn.execute(text("SELECT name FROM roles ORDER BY name"))).scalars().all()
        ext = (
            await conn.execute(text("SELECT 1 FROM pg_extension WHERE extname = 'pgcrypto'"))
        ).scalar()
    assert version == "0004"
    assert ext == 1
    assert roles == [
        "APPROVER",
        "AUDITOR",
        "EMPLOYEE",
        "PLATFORM_ADMIN",
        "SECURITY_ADMIN",
        "SOFTWARE_ADMIN",
    ]


async def test_runtime_role_is_not_privileged(app_db: Database) -> None:
    async with app_db.engine.connect() as conn:
        row = (
            await conn.execute(
                text(
                    "SELECT current_user, rolsuper, rolcreaterole, rolcreatedb, rolbypassrls "
                    "FROM pg_roles WHERE rolname = current_user"
                )
            )
        ).one()
    assert tuple(row) == ("sentinel_app", False, False, False, False)


async def _one_event(app_db: Database) -> None:
    async with app_db.sessionmaker() as s:
        await audit.record(
            s,
            action="TEST_EVENT",
            resource_type="test",
            result=AuditResult.SUCCESS,
            actor_type=ActorType.SYSTEM,
        )
        await s.commit()


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE audit_events SET action = 'TAMPERED'",
        "DELETE FROM audit_events",
        "TRUNCATE audit_events",
        "INSERT INTO roles (name, description) VALUES ('ROOT', 'x')",
        "UPDATE roles SET name = 'X' WHERE name = 'EMPLOYEE'",
    ],
)
async def test_runtime_role_cannot_tamper(app_db: Database, statement: str) -> None:
    await _one_event(app_db)
    async with app_db.engine.connect() as conn:
        with pytest.raises(DBAPIError, match="permission denied"):
            await conn.execute(text(statement))


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE audit_events SET action = 'TAMPERED'",
        "DELETE FROM audit_events",
        "TRUNCATE audit_events",
    ],
)
async def test_owner_blocked_by_append_only_trigger(
    app_db: Database, owner_engine: AsyncEngine, statement: str
) -> None:
    await _one_event(app_db)
    async with owner_engine.connect() as conn:
        with pytest.raises(DBAPIError, match="append-only"):
            await conn.execute(text(statement))


async def test_chain_verifies_and_detects_tampering(
    app_db: Database, owner_engine: AsyncEngine
) -> None:
    for _ in range(3):
        await _one_event(app_db)
    async with app_db.sessionmaker() as s:
        ok = await audit.verify_chain(s)
    assert (ok.valid, ok.events_checked) == (True, 3)

    # Simulate a privileged attacker who disables triggers and edits a row.
    async with owner_engine.begin() as conn:
        await conn.execute(text("SET LOCAL session_replication_role = replica"))
        await conn.execute(text("UPDATE audit_events SET action = 'TAMPERED' WHERE seq = 2"))
    async with app_db.sessionmaker() as s:
        bad = await audit.verify_chain(s)
    assert (bad.valid, bad.first_invalid_seq) == (False, 2)


async def test_concurrent_appends_keep_chain_linear(app_db: Database) -> None:
    import asyncio

    await asyncio.gather(*(_one_event(app_db) for _ in range(10)))
    async with app_db.sessionmaker() as s:
        result = await audit.verify_chain(s)
    assert (result.valid, result.events_checked) == (True, 10)


async def test_unreachable_database_reports_not_ready() -> None:
    db = Database(make_settings(database_url="postgresql+asyncpg://u:p@127.0.0.1:1/nodb"))
    try:
        assert await db.ping(timeout_seconds=2) is False
    finally:
        await db.dispose()
