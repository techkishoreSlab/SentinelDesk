"""Signed job claim / started / result (Phase 8)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import select

from app.db.enums import RoleName
from app.db.session import Database
from app.jobs.signing import verify_envelope
from app.security.seed import seed_security
from tests.conftest import make_settings
from tests.integration.conftest import SeededUser, csrf_headers, login
from tests.integration.test_agent_api import bearer, enroll, new_token


def _write_keypair(tmp_path: Path) -> tuple[Path, Path]:
    private = Ed25519PrivateKey.generate()
    priv = tmp_path / "job_signing_private.pem"
    pub = tmp_path / "job_signing_public.pem"
    priv.write_bytes(
        private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    pub.write_bytes(
        private.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return priv, pub


@pytest.fixture
def settings(migrated_database: tuple[str, str], tmp_path: Path):
    priv, pub = _write_keypair(tmp_path)
    return make_settings(
        database_url=migrated_database[0],
        cors_allowed_origins="http://localhost:5173",
        web_base_url="http://localhost:5173",
        max_request_bytes=1_048_576,
        job_signing_private_key_path=priv,
        job_signing_public_key_path=pub,
    )


@pytest.fixture
async def agent(client: httpx.AsyncClient) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=client._transport, base_url="http://testserver")


@pytest.fixture
async def people(client: httpx.AsyncClient, make_user) -> dict[str, SeededUser]:
    admin = await make_user("plat-jobs@sentinel.test", [RoleName.EMPLOYEE, RoleName.PLATFORM_ADMIN])
    employee = await make_user("emp-jobs@sentinel.test", [RoleName.EMPLOYEE])
    approver = await make_user(
        "approver-jobs@sentinel.test", [RoleName.EMPLOYEE, RoleName.APPROVER]
    )
    await login(client, admin)
    return {"admin": admin, "employee": employee, "approver": approver}


@pytest.fixture
async def seeded(app_db: Database) -> None:
    async with app_db.sessionmaker() as session:
        from app.auth.passwords import hash_password
        from app.auth.tokens import new_token as tok
        from app.db.enums import IdentityProvider
        from app.users.models import LocalCredential, Role, User, UserRole

        existing = await session.scalar(
            select(User).where(User.email == "security.admin@sentinel.test")
        )
        if existing is None:
            user = User(
                email="security.admin@sentinel.test",
                display_name="Security Admin",
                identity_provider=IdentityProvider.LOCAL,
                is_active=True,
            )
            session.add(user)
            await session.flush()
            session.add(LocalCredential(user_id=user.id, password_hash=hash_password(tok(18))))
            role_id = await session.scalar(
                select(Role.id).where(Role.name == RoleName.SECURITY_ADMIN.value)
            )
            emp = await session.scalar(select(Role.id).where(Role.name == RoleName.EMPLOYEE.value))
            session.add(UserRole(user_id=user.id, role_id=role_id))
            session.add(UserRole(user_id=user.id, role_id=emp))
            await session.commit()
        await seed_security(session)


@pytest.mark.asyncio
async def test_claim_signed_job_started_and_result(
    client: httpx.AsyncClient,
    agent: httpx.AsyncClient,
    people: dict[str, SeededUser],
    seeded: None,
    settings: Any,
) -> None:
    token = await new_token(client, people["employee"])
    creds = await enroll(agent, token)
    device_id = creds["device_id"]
    secret = creds["device_credential"]

    await login(client, people["employee"])
    created = await client.post(
        "/api/v1/software/requests",
        headers=csrf_headers(client),
        json={
            "device_id": device_id,
            "user_prompt": "Install git",
            "idempotency_key": "idem-jobs-git",
        },
    )
    assert created.status_code == 200, created.text
    assert created.json()["status"] == "AWAITING_APPROVAL"
    request_id = created.json()["id"]
    version = created.json()["request_version"]

    await login(client, people["approver"])
    decided = await client.post(
        f"/api/v1/admin/approvals/{request_id}/decision",
        headers=csrf_headers(client),
        json={"decision": "APPROVED", "expected_version": version},
    )
    assert decided.status_code == 200, decided.text
    assert decided.json()["status"] == "QUEUED"

    claimed = await agent.get("/api/v1/agent/jobs/next", headers=bearer(secret))
    assert claimed.status_code == 200, claimed.text
    body = claimed.json()
    assert body["software_slug"] == "git"
    assert "envelope" in body and "signature" in body
    assert verify_envelope(settings, body["envelope"], body["signature"])
    job_id = body["envelope"]["job_id"]

    empty = await agent.get("/api/v1/agent/jobs/next", headers=bearer(secret))
    assert empty.status_code == 204

    started = await agent.post(
        f"/api/v1/agent/jobs/{job_id}/started",
        headers=bearer(secret),
        json={"protocol_version": 1},
    )
    assert started.status_code == 204, started.text

    result = await agent.post(
        f"/api/v1/agent/jobs/{job_id}/result",
        headers=bearer(secret),
        json={
            "protocol_version": 1,
            "result_code": "PRIVILEGED_SERVICE_UNAVAILABLE",
            "result_summary": "phase 8 gate: LaunchDaemon not installed",
            "exit_code": None,
            "installed_version": None,
            "verification_status": "NOT_ATTEMPTED",
            "details": {},
        },
    )
    assert result.status_code == 200, result.text
    assert result.json()["status"] == "FAILED"
    assert result.json()["result_code"] == "PRIVILEGED_SERVICE_UNAVAILABLE"

    again = await agent.post(
        f"/api/v1/agent/jobs/{job_id}/result",
        headers=bearer(secret),
        json={
            "protocol_version": 1,
            "result_code": "PRIVILEGED_SERVICE_UNAVAILABLE",
            "result_summary": "replay",
            "verification_status": "NOT_ATTEMPTED",
            "details": {},
        },
    )
    assert again.status_code == 200
    assert again.json()["status"] == "FAILED"


@pytest.mark.asyncio
async def test_job_progress_download_then_conflict_when_terminal(
    client: httpx.AsyncClient,
    agent: httpx.AsyncClient,
    people: dict[str, SeededUser],
    seeded: None,
    settings: Any,
) -> None:
    token = await new_token(client, people["employee"])
    creds = await enroll(agent, token)
    device_id = creds["device_id"]
    secret = creds["device_credential"]

    await login(client, people["employee"])
    created = await client.post(
        "/api/v1/software/requests",
        headers=csrf_headers(client),
        json={
            "device_id": device_id,
            "user_prompt": "Install git",
            "idempotency_key": "idem-jobs-progress",
        },
    )
    assert created.status_code == 200, created.text
    request_id = created.json()["id"]
    version = created.json()["request_version"]

    await login(client, people["approver"])
    decided = await client.post(
        f"/api/v1/admin/approvals/{request_id}/decision",
        headers=csrf_headers(client),
        json={"decision": "APPROVED", "expected_version": version},
    )
    assert decided.status_code == 200, decided.text

    claimed = await agent.get("/api/v1/agent/jobs/next", headers=bearer(secret))
    assert claimed.status_code == 200, claimed.text
    assert verify_envelope(settings, claimed.json()["envelope"], claimed.json()["signature"])
    job_id = claimed.json()["envelope"]["job_id"]

    started = await agent.post(
        f"/api/v1/agent/jobs/{job_id}/started",
        headers=bearer(secret),
        json={"protocol_version": 1},
    )
    assert started.status_code == 204, started.text

    progress = await agent.post(
        f"/api/v1/agent/jobs/{job_id}/progress",
        headers=bearer(secret),
        json={
            "protocol_version": 1,
            "phase": "DOWNLOADING",
            "bytes_done": 50_000_000,
            "bytes_total": 100_000_000,
        },
    )
    assert progress.status_code == 200, progress.text
    assert progress.json()["phase"] == "DOWNLOADING"
    assert progress.json()["bytes_done"] == 50_000_000

    # Monotonic clamp: regression must not lower bytes_done.
    clamped = await agent.post(
        f"/api/v1/agent/jobs/{job_id}/progress",
        headers=bearer(secret),
        json={
            "protocol_version": 1,
            "phase": "DOWNLOADING",
            "bytes_done": 10_000_000,
            "bytes_total": 100_000_000,
        },
    )
    assert clamped.status_code == 200, clamped.text
    assert clamped.json()["bytes_done"] == 50_000_000

    await login(client, people["employee"])
    detail = await client.get(f"/api/v1/software/requests/{request_id}")
    assert detail.status_code == 200, detail.text
    body = detail.json()
    assert body["progress_phase"] == "DOWNLOADING"
    assert body["progress_bytes_done"] == 50_000_000
    assert body["progress_bytes_total"] == 100_000_000

    result = await agent.post(
        f"/api/v1/agent/jobs/{job_id}/result",
        headers=bearer(secret),
        json={
            "protocol_version": 1,
            "result_code": "PRIVILEGED_SERVICE_UNAVAILABLE",
            "result_summary": "phase 8 gate",
            "verification_status": "NOT_ATTEMPTED",
            "details": {},
        },
    )
    assert result.status_code == 200, result.text

    rejected = await agent.post(
        f"/api/v1/agent/jobs/{job_id}/progress",
        headers=bearer(secret),
        json={
            "protocol_version": 1,
            "phase": "INSTALLING",
        },
    )
    assert rejected.status_code == 409


@pytest.mark.asyncio
async def test_jobs_next_204_when_empty(
    client: httpx.AsyncClient,
    agent: httpx.AsyncClient,
    people: dict[str, SeededUser],
) -> None:
    token = await new_token(client, people["employee"])
    creds = await enroll(agent, token)
    r = await agent.get("/api/v1/agent/jobs/next", headers=bearer(creds["device_credential"]))
    assert r.status_code == 204
