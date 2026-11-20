"""Policy engine: bans, threat fail-closed, auto-approve and approval-required paths."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
from sqlalchemy import select

from app.catalogue.models import CatalogueVersion
from app.catalogue.seed import demo_digest
from app.db.enums import DeviceStatus, RoleName
from app.db.session import Database
from app.devices.models import Device, DeviceFacts
from app.security.seed import seed_security
from tests.integration.conftest import SeededUser, csrf_headers, login


@pytest.fixture
async def people(client: httpx.AsyncClient, make_user) -> dict[str, SeededUser]:
    employee = await make_user("emp-sec@sentinel.test", [RoleName.EMPLOYEE])
    security = await make_user(
        "sec-admin@sentinel.test", [RoleName.EMPLOYEE, RoleName.SECURITY_ADMIN]
    )
    await login(client, employee)
    return {"employee": employee, "security": security}


@pytest.fixture
async def seeded(app_db: Database, people: dict[str, SeededUser]) -> None:
    # seed_security needs a security.admin@ or platform.admin@ user — create the canonical email.
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


async def _device(
    app_db: Database, owner_id: uuid.UUID, installed: list[dict[str, str]] | None = None
) -> uuid.UUID:
    async with app_db.sessionmaker() as session:
        device = Device(
            owner_user_id=owner_id,
            device_name="Policy Mac",
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
                installed_software_summary={
                    "count": len(installed or []),
                    "items": installed or [],
                },
            )
        )
        await session.commit()
        return device.id


async def _version_id(app_db: Database, package_identifier: str) -> uuid.UUID:
    async with app_db.sessionmaker() as session:
        row = await session.scalar(
            select(CatalogueVersion).where(
                CatalogueVersion.package_identifier == package_identifier,
                CatalogueVersion.architecture == "x86_64",
            )
        )
        assert row is not None
        return row.id


async def _evaluate(
    client: httpx.AsyncClient, device_id: uuid.UUID, version_id: uuid.UUID
) -> dict[str, Any]:
    resp = await client.post(
        "/api/v1/security/evaluate",
        json={"device_id": str(device_id), "catalogue_version_id": str(version_id)},
        headers=csrf_headers(client),
    )
    assert resp.status_code == 200, resp.text
    body: dict[str, Any] = resp.json()
    return body


async def test_banned_remote_access_hard_blocks(
    client: httpx.AsyncClient, people, seeded, app_db: Database
) -> None:
    device_id = await _device(app_db, people["employee"].id)
    version_id = await _version_id(app_db, "com.sentineldesk.demo.RestrictedRemoteAccess")
    body = await _evaluate(client, device_id, version_id)
    assert body["outcome"] == "BLOCKED"
    assert body["ban_rule_id"] is not None
    assert "blocked by your organisation" in body["public_message"].lower()


async def test_malware_sample_blocked(
    client: httpx.AsyncClient, people, seeded, app_db: Database
) -> None:
    device_id = await _device(app_db, people["employee"].id)
    version_id = await _version_id(app_db, "com.sentineldesk.demo.MalwareSample")
    body = await _evaluate(client, device_id, version_id)
    assert body["outcome"] == "BLOCKED"


async def test_git_requires_approval(
    client: httpx.AsyncClient, people, seeded, app_db: Database
) -> None:
    device_id = await _device(app_db, people["employee"].id)
    version_id = await _version_id(app_db, "com.git.Git")
    body = await _evaluate(client, device_id, version_id)
    assert body["outcome"] == "REQUIRE_APPROVAL"
    assert body["threat_verdict"] == "CLEAN"
    assert body["policy_decision"] == "REQUIRE_APPROVAL"


async def test_vscode_auto_approve_when_not_installed(
    client: httpx.AsyncClient, people, seeded, app_db: Database
) -> None:
    device_id = await _device(app_db, people["employee"].id, installed=[])
    version_id = await _version_id(app_db, "com.microsoft.VSCode")
    body = await _evaluate(client, device_id, version_id)
    assert body["outcome"] == "AUTO_APPROVE"
    assert body["auto_approve_eligible"] is True
    assert body["threat_provider"] == "internal_digest_list"


async def test_vscode_already_installed(
    client: httpx.AsyncClient, people, seeded, app_db: Database
) -> None:
    device_id = await _device(
        app_db,
        people["employee"].id,
        installed=[
            {"identifier": "com.microsoft.VSCode", "version": "1.138.0", "source": "app_bundle"}
        ],
    )
    version_id = await _version_id(app_db, "com.microsoft.VSCode")
    body = await _evaluate(client, device_id, version_id)
    assert body["outcome"] == "ALREADY_INSTALLED"


async def test_windows_package_incompatible(
    client: httpx.AsyncClient, people, seeded, app_db: Database
) -> None:
    device_id = await _device(app_db, people["employee"].id)
    version_id = await _version_id(app_db, "Contoso.Notepad")
    body = await _evaluate(client, device_id, version_id)
    assert body["outcome"] == "INCOMPATIBLE"
    assert body["reason_code"] == "OS_UNSUPPORTED"


async def test_unpinned_digest_fail_closed(
    client: httpx.AsyncClient, people, seeded, app_db: Database, settings
) -> None:
    """A complete ACTIVE package whose digest is not pinned and VT is off → unavailable."""
    await login(client, people["security"])
    # Create via admin catalogue would need SOFTWARE_ADMIN; insert directly.
    from app.catalogue.models import CatalogueSoftware
    from app.db.enums import (
        Architecture,
        InstallerType,
        LifecycleStatus,
        OsFamily,
        RiskLevel,
        SourceType,
        VerificationMethod,
    )

    async with app_db.sessionmaker() as session:
        software = CatalogueSoftware(
            slug="unpinned-demo",
            display_name="Unpinned Demo",
            description="Digest not on pin list",
            publisher="Demo",
            category="utilities",
            lifecycle_status=LifecycleStatus.ACTIVE.value,
            risk_level=RiskLevel.LOW.value,
        )
        session.add(software)
        await session.flush()
        version = CatalogueVersion(
            software_id=software.id,
            version="1.0.0",
            os_family=OsFamily.MACOS.value,
            architecture=Architecture.X86_64.value,
            minimum_os_version="13.0",
            minimum_memory_bytes=1024,
            minimum_disk_bytes=1024,
            installer_type=InstallerType.MACOS_PKG.value,
            source_type=SourceType.INTERNAL_ARTIFACT_STORE.value,
            source_reference="artifact://demo/unpinned/1.0.0",
            package_identifier="com.demo.Unpinned",
            verification_method=VerificationMethod.MACOS_APP_BUNDLE.value,
            sha256="ee" * 32,
            signature_publisher="Demo",
            signature_required=True,
            package_size_bytes=1024,
            release_status=LifecycleStatus.ACTIVE.value,
        )
        session.add(version)
        await session.commit()
        version_id = version.id

    await login(client, people["employee"])
    device_id = await _device(app_db, people["employee"].id)
    body = await _evaluate(client, device_id, version_id)
    assert body["outcome"] == "SECURITY_CHECK_UNAVAILABLE"
    assert body["threat_verdict"] == "INDETERMINATE"


async def test_security_admin_lists_bans(client: httpx.AsyncClient, people, seeded) -> None:
    await login(client, people["employee"])
    denied = await client.get("/api/v1/admin/security/banned")
    assert denied.status_code == 403

    await login(client, people["security"])
    ok = await client.get("/api/v1/admin/security/banned")
    assert ok.status_code == 200, ok.text
    values = {row["match_value"] for row in ok.json()}
    assert "restricted-remote-access" in values
    assert demo_digest("demo-malware-sample-1.0.0") in values

    status = await client.get("/api/v1/admin/security/threat-status")
    assert status.status_code == 200
    assert status.json()["mandatory"] is True
    assert status.json()["external_configured"] is False
