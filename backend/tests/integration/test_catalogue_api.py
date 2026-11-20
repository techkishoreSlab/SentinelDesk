"""Catalogue search, admin CRUD and device compatibility against real PostgreSQL."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from sqlalchemy import select

from app.catalogue.models import CatalogueVersion
from app.catalogue.seed import demo_digest, seed_catalogue
from app.db.enums import DeviceStatus, RoleName
from app.db.session import Database
from app.devices.models import Device, DeviceFacts
from tests.integration.conftest import SeededUser, csrf_headers, login


@pytest.fixture
async def people(client: httpx.AsyncClient, make_user) -> dict[str, SeededUser]:
    employee = await make_user("emp-cat@sentinel.test", [RoleName.EMPLOYEE])
    software = await make_user(
        "swadmin-cat@sentinel.test", [RoleName.EMPLOYEE, RoleName.SOFTWARE_ADMIN]
    )
    other = await make_user("other-cat@sentinel.test", [RoleName.EMPLOYEE])
    await login(client, employee)
    return {"employee": employee, "software": software, "other": other}


@pytest.fixture
async def seeded(app_db: Database) -> None:
    async with app_db.sessionmaker() as session:
        await seed_catalogue(session)


async def _enroll_device(
    app_db: Database,
    owner_id: uuid.UUID,
    *,
    os_family: str = "macos",
    architecture: str = "x86_64",
    os_version: str = "26.5",
    installed: list[dict[str, str]] | None = None,
    last_seen: datetime | None = None,
    status: str = DeviceStatus.ACTIVE.value,
) -> uuid.UUID:
    async with app_db.sessionmaker() as session:
        device = Device(
            owner_user_id=owner_id,
            device_name="Test Mac",
            os_family=os_family,
            os_version=os_version,
            architecture=architecture,
            agent_version="0.1.0",
            device_status=status,
            last_seen_at=last_seen or datetime.now(UTC),
            enrolled_at=datetime.now(UTC),
        )
        session.add(device)
        await session.flush()
        session.add(
            DeviceFacts(
                device_id=device.id,
                cpu_arch=architecture,
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


async def test_search_exact_aliases_and_unknown(client: httpx.AsyncClient, people, seeded) -> None:
    for query in ("Visual Studio Code", "vscode", "VS-Code"):
        resp = await client.get("/api/v1/catalogue/search", params={"q": query})
        assert resp.status_code == 200, resp.text
        hits = resp.json()
        assert len(hits) == 1
        assert hits[0]["software"]["slug"] == "visual-studio-code"
        assert any(v["os_family"] == "macos" for v in hits[0]["active_versions"])

    missing = await client.get("/api/v1/catalogue/search", params={"q": "Unknown Editor XYZ"})
    assert missing.status_code == 200
    assert missing.json() == []

    # Incomplete / pending software must not appear in the employee search.
    pending = await client.get("/api/v1/catalogue/search", params={"q": "demo incomplete editor"})
    assert pending.json() == []


async def test_compatibility_os_mismatch_and_already_installed(
    client: httpx.AsyncClient, people, seeded, app_db: Database
) -> None:
    device_id = await _enroll_device(
        app_db,
        people["employee"].id,
        installed=[
            {"identifier": "com.microsoft.VSCode", "version": "1.138.0", "source": "app_bundle"}
        ],
    )
    async with app_db.sessionmaker() as session:
        win = await session.scalar(
            select(CatalogueVersion).where(
                CatalogueVersion.os_family == "windows",
                CatalogueVersion.architecture == "x86_64",
            )
        )
        mac = await session.scalar(
            select(CatalogueVersion).where(
                CatalogueVersion.package_identifier == "com.microsoft.VSCode",
                CatalogueVersion.architecture == "x86_64",
            )
        )
        assert win is not None and mac is not None
        win_id, mac_id = win.id, mac.id

    bad = await client.post(
        "/api/v1/catalogue/compatibility",
        json={"device_id": str(device_id), "catalogue_version_id": str(win_id)},
        headers=csrf_headers(client),
    )
    assert bad.status_code == 200, bad.text
    assert bad.json()["compatible"] is False
    assert bad.json()["reason_code"] == "OS_UNSUPPORTED"

    installed = await client.post(
        "/api/v1/catalogue/compatibility",
        json={"device_id": str(device_id), "catalogue_version_id": str(mac_id)},
        headers=csrf_headers(client),
    )
    assert installed.json()["reason_code"] == "ALREADY_INSTALLED"


async def test_compatibility_stale_and_idor(
    client: httpx.AsyncClient, people, seeded, app_db: Database
) -> None:
    stale_id = await _enroll_device(
        app_db,
        people["employee"].id,
        last_seen=datetime.now(UTC) - timedelta(hours=2),
        installed=[],
    )
    other_id = await _enroll_device(app_db, people["other"].id)
    async with app_db.sessionmaker() as session:
        git = await session.scalar(
            select(CatalogueVersion).where(CatalogueVersion.package_identifier == "com.git.Git")
        )
        assert git is not None
        git_id = git.id

    stale = await client.post(
        "/api/v1/catalogue/compatibility",
        json={"device_id": str(stale_id), "catalogue_version_id": str(git_id)},
        headers=csrf_headers(client),
    )
    assert stale.json()["reason_code"] == "DEVICE_STALE"

    foreign = await client.post(
        "/api/v1/catalogue/compatibility",
        json={"device_id": str(other_id), "catalogue_version_id": str(git_id)},
        headers=csrf_headers(client),
    )
    assert foreign.status_code == 404


async def test_admin_create_activate_and_reject_incomplete(
    client: httpx.AsyncClient, people, app_db: Database
) -> None:
    await login(client, people["employee"])
    denied = await client.post(
        "/api/v1/admin/catalogue/software",
        json={
            "slug": "denied-app",
            "display_name": "Denied",
            "publisher": "X",
            "category": "utilities",
        },
        headers=csrf_headers(client),
    )
    assert denied.status_code == 403

    await login(client, people["software"])
    created = await client.post(
        "/api/v1/admin/catalogue/software",
        json={
            "slug": "demo-widget",
            "display_name": "Demo Widget",
            "description": "Created in test",
            "publisher": "SentinelDesk Demo",
            "category": "utilities",
            "risk_level": "LOW",
            "aliases": ["demo widget", "widget"],
        },
        headers=csrf_headers(client),
    )
    assert created.status_code == 201, created.text
    software_id = created.json()["id"]
    assert created.json()["lifecycle_status"] == "PENDING_REVIEW"

    # Activate the software record, then refuse an ACTIVE version with missing digest.
    life = await client.post(
        f"/api/v1/admin/catalogue/software/{software_id}/lifecycle",
        params={"status": "ACTIVE"},
        headers=csrf_headers(client),
    )
    assert life.status_code == 200, life.text

    incomplete = await client.post(
        "/api/v1/admin/catalogue/versions",
        json={
            "software_id": software_id,
            "version": "1.0.0",
            "os_family": "macos",
            "architecture": "x86_64",
            "installer_type": "MACOS_PKG",
            "source_type": "INTERNAL_ARTIFACT_STORE",
            "release_status": "ACTIVE",
            "signature_required": True,
        },
        headers=csrf_headers(client),
    )
    assert incomplete.status_code == 409
    assert incomplete.json()["error"]["code"] == "PACKAGE_METADATA_INCOMPLETE"

    url_rejected = await client.post(
        "/api/v1/admin/catalogue/versions",
        json={
            "software_id": software_id,
            "version": "1.0.0",
            "os_family": "macos",
            "architecture": "x86_64",
            "minimum_os_version": "13.0",
            "minimum_memory_bytes": 1024,
            "minimum_disk_bytes": 1024,
            "installer_type": "MACOS_PKG",
            "source_type": "INTERNAL_ARTIFACT_STORE",
            "source_reference": "https://evil.example/pkg",
            "package_identifier": "com.demo.Widget",
            "verification_method": "MACOS_APP_BUNDLE",
            "sha256": demo_digest("widget"),
            "signature_publisher": "Demo",
            "release_status": "PENDING_REVIEW",
        },
        headers=csrf_headers(client),
    )
    assert url_rejected.status_code == 422

    ok = await client.post(
        "/api/v1/admin/catalogue/versions",
        json={
            "software_id": software_id,
            "version": "1.0.0",
            "os_family": "macos",
            "architecture": "x86_64",
            "minimum_os_version": "13.0",
            "minimum_memory_bytes": 1024,
            "minimum_disk_bytes": 1024,
            "installer_type": "MACOS_PKG",
            "source_type": "INTERNAL_ARTIFACT_STORE",
            "source_reference": "artifact://demo/widget/1.0.0",
            "package_identifier": "com.demo.Widget",
            "verification_method": "MACOS_APP_BUNDLE",
            "sha256": demo_digest("widget"),
            "signature_publisher": "Demo",
            "signature_required": True,
            "package_size_bytes": 1024,
            "release_status": "ACTIVE",
        },
        headers=csrf_headers(client),
    )
    assert ok.status_code == 201, ok.text
    assert ok.json()["metadata_complete"] is True

    await login(client, people["employee"])
    found = await client.get("/api/v1/catalogue/search", params={"q": "demo widget"})
    assert found.status_code == 200
    assert found.json()[0]["software"]["slug"] == "demo-widget"


async def test_compatible_git_on_fresh_device(
    client: httpx.AsyncClient, people, seeded, app_db: Database
) -> None:
    device_id = await _enroll_device(app_db, people["employee"].id)
    async with app_db.sessionmaker() as session:
        git = await session.scalar(
            select(CatalogueVersion).where(CatalogueVersion.package_identifier == "com.git.Git")
        )
        assert git is not None
        git_id = git.id
    resp = await client.post(
        "/api/v1/catalogue/compatibility",
        json={"device_id": str(device_id), "catalogue_version_id": str(git_id)},
        headers=csrf_headers(client),
    )
    body: dict[str, Any] = resp.json()
    assert body["compatible"] is True
    assert body["reason_code"] == "COMPATIBLE"
    assert body["software_slug"] == "git"
