"""Preview orchestrator: fallback + mocked Gemini → catalogue → policy (no persistence)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import httpx
import pytest
from sqlalchemy import select

from app.ai.gemini import StaticIntentExtractor
from app.ai.intent import SoftwareIntent
from app.db.enums import DeviceStatus, RoleName
from app.db.session import Database
from app.devices.models import Device, DeviceFacts
from app.orchestration.orchestrator import run_preview
from app.security.seed import seed_security
from app.security.threat import CompositeThreatIntel
from tests.conftest import make_settings
from tests.integration.conftest import SeededUser, csrf_headers, login


@pytest.fixture
async def people(client: httpx.AsyncClient, make_user) -> dict[str, SeededUser]:
    employee = await make_user("emp-preview@sentinel.test", [RoleName.EMPLOYEE])
    await login(client, employee)
    return {"employee": employee}


@pytest.fixture
async def seeded(app_db: Database) -> None:
    async with app_db.sessionmaker() as session:
        from app.auth.passwords import hash_password
        from app.auth.tokens import new_token
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
            session.add(
                LocalCredential(user_id=user.id, password_hash=hash_password(new_token(18)))
            )
            role_id = await session.scalar(
                select(Role.id).where(Role.name == RoleName.SECURITY_ADMIN.value)
            )
            emp = await session.scalar(select(Role.id).where(Role.name == RoleName.EMPLOYEE.value))
            session.add(UserRole(user_id=user.id, role_id=role_id))
            session.add(UserRole(user_id=user.id, role_id=emp))
            await session.commit()
        await seed_security(session)


async def _device(app_db: Database, owner_id: uuid.UUID) -> uuid.UUID:
    async with app_db.sessionmaker() as session:
        device = Device(
            owner_user_id=owner_id,
            device_name="Preview Mac",
            os_family="macos",
            os_version="26.5",
            architecture="x86_64",
            agent_version="0.1.0",
            device_status=DeviceStatus.ACTIVE.value,
            last_seen_at=datetime.now(UTC),
            enrolled_at=datetime.now(UTC),
        )
        session.add(device)
        await session.flush()
        session.add(
            DeviceFacts(
                device_id=device.id,
                cpu_arch="x86_64",
                cpu_cores=8,
                memory_total_bytes=16 * 1024**3,
                disk_free_bytes=80 * 1024**3,
                os_build="25F71",
                installed_software_summary={"count": 0, "items": []},
            )
        )
        await session.commit()
        return device.id


@pytest.mark.asyncio
async def test_preview_fallback_git_requires_approval(
    client: httpx.AsyncClient,
    app_db: Database,
    people: dict[str, SeededUser],
    seeded: None,
) -> None:
    device_id = await _device(app_db, people["employee"].id)
    resp = await client.post(
        "/api/v1/software/preview",
        headers=csrf_headers(client),
        json={"device_id": str(device_id), "raw_request": "Install git"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "REQUIRE_APPROVAL"
    assert body["intent"]["source"] == "fallback"
    assert body["match"]["software_slug"] == "git"
    assert body["policy"]["threat_verdict"] == "CLEAN"
    assert body["tool_trace"] == [
        "extract_intent",
        "resolve_catalogue_alias",
        "pick_catalogue_version",
        "evaluate_policy",
        "explain_decision",
    ]
    assert "approval" in body["explanation"].casefold()


@pytest.mark.asyncio
async def test_preview_fallback_vscode_auto_approve(
    client: httpx.AsyncClient,
    app_db: Database,
    people: dict[str, SeededUser],
    seeded: None,
) -> None:
    device_id = await _device(app_db, people["employee"].id)
    resp = await client.post(
        "/api/v1/software/preview",
        headers=csrf_headers(client),
        json={"device_id": str(device_id), "raw_request": "Please install VS Code"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "AUTO_APPROVE"
    assert body["match"]["software_slug"] == "visual-studio-code"
    assert body["gemini_configured"] is False


@pytest.mark.asyncio
async def test_preview_not_found_and_banned(
    client: httpx.AsyncClient,
    app_db: Database,
    people: dict[str, SeededUser],
    seeded: None,
) -> None:
    device_id = await _device(app_db, people["employee"].id)
    missing = await client.post(
        "/api/v1/software/preview",
        headers=csrf_headers(client),
        json={"device_id": str(device_id), "raw_request": "Install Photoshop"},
    )
    assert missing.status_code == 200
    assert missing.json()["status"] == "NOT_FOUND"

    banned = await client.post(
        "/api/v1/software/preview",
        headers=csrf_headers(client),
        json={
            "device_id": str(device_id),
            "raw_request": "Install Restricted Remote Access Tool",
        },
    )
    assert banned.status_code == 200
    assert banned.json()["status"] == "BLOCKED"


@pytest.mark.asyncio
async def test_preview_with_static_gemini_then_timeout_fallback(
    app_db: Database,
    people: dict[str, SeededUser],
    seeded: None,
    migrated_database: tuple[str, str],
) -> None:
    device_id = await _device(app_db, people["employee"].id)
    settings = make_settings(
        database_url=migrated_database[0],
        cors_allowed_origins="http://localhost:5173",
        web_base_url="http://localhost:5173",
        max_request_bytes=1_048_576,
        gemini_api_key="k" * 32,
        gemini_model="gemini-test",
    )
    async with httpx.AsyncClient() as http:
        threat = CompositeThreatIntel(settings, http)
        async with app_db.sessionmaker() as session:
            extractor = StaticIntentExtractor(
                SoftwareIntent(
                    intent="INSTALL_SOFTWARE",
                    software_query="Visual Studio Code",
                    confidence=0.95,
                ),
                explanation="VS Code is eligible for automatic approval.",
            )
            result = await run_preview(
                session,
                settings,
                threat,
                owner_user_id=people["employee"].id,
                device_id=device_id,
                raw_request="get me that code editor from microsoft please",
                http_client=http,
                extractor=extractor,
            )
            await session.commit()
    assert result.status == "AUTO_APPROVE"
    assert result.intent.source == "gemini"
    assert result.explanation == "VS Code is eligible for automatic approval."

    # Timeout → deterministic fallback still works for exact demo phrasing.
    async with httpx.AsyncClient() as http:
        threat = CompositeThreatIntel(settings, http)
        async with app_db.sessionmaker() as session:
            failing = StaticIntentExtractor(
                SoftwareIntent(intent="INSTALL_SOFTWARE", software_query="x"),
                fail_code="TIMEOUT",
            )
            result = await run_preview(
                session,
                settings,
                threat,
                owner_user_id=people["employee"].id,
                device_id=device_id,
                raw_request="Install git",
                http_client=http,
                extractor=failing,
            )
            await session.commit()
    assert result.intent.source == "fallback"
    assert result.status == "REQUIRE_APPROVAL"


@pytest.mark.asyncio
async def test_preview_rejects_foreign_device(
    client: httpx.AsyncClient,
    app_db: Database,
    people: dict[str, SeededUser],
    make_user,
    seeded: None,
) -> None:
    other = await make_user("other-preview@sentinel.test", [RoleName.EMPLOYEE])
    device_id = await _device(app_db, other.id)
    resp = await client.post(
        "/api/v1/software/preview",
        headers=csrf_headers(client),
        json={"device_id": str(device_id), "raw_request": "Install git"},
    )
    assert resp.status_code == 404
