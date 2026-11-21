"""Archive catalogue add path, capability gating and artifact download (integration)."""

from __future__ import annotations

import hashlib
import io
import uuid
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest

from app.catalogue.models import CatalogueSoftware, CatalogueVersion
from app.db.enums import DeviceStatus, IdentityProvider, JobStatus, RoleName
from app.db.session import Database
from app.devices.models import Device, DeviceFacts
from app.jobs.service import build_envelope
from app.requests.models import InstallationJob, SoftwareRequest
from app.users.models import User
from tests.conftest import make_settings
from tests.integration.conftest import SeededUser, csrf_headers, login
from tests.integration.test_agent_api import bearer, enroll, new_token


@pytest.fixture
def settings(migrated_database: tuple[str, str], tmp_path: Path):
    return make_settings(
        database_url=migrated_database[0],
        cors_allowed_origins="http://localhost:5173",
        web_base_url="http://localhost:5173",
        max_request_bytes=8 * 1024 * 1024,
        package_store_dir=str(tmp_path / "packages"),
    )


@pytest.fixture
async def people(client: httpx.AsyncClient, make_user) -> dict[str, SeededUser]:
    employee = await make_user("emp-arch@sentinel.test", [RoleName.EMPLOYEE])
    software = await make_user(
        "swadmin-arch@sentinel.test", [RoleName.EMPLOYEE, RoleName.SOFTWARE_ADMIN]
    )
    admin = await make_user("plat-arch@sentinel.test", [RoleName.EMPLOYEE, RoleName.PLATFORM_ADMIN])
    await login(client, software)
    return {"employee": employee, "software": software, "admin": admin}


@pytest.fixture
async def agent(client: httpx.AsyncClient) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=client._transport, base_url="http://testserver")


def _unsigned_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(
            "Tool.app/Contents/Info.plist",
            b"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleIdentifier</key><string>com.example.tool</string>
  <key>CFBundleShortVersionString</key><string>1.0</string>
  <key>CFBundleExecutable</key><string>Tool</string>
</dict></plist>""",
        )
        zf.writestr("Tool.app/Contents/MacOS/Tool", b"\x00" * 64)
    return buf.getvalue()


async def test_presets_and_inspect_reject_unsigned_upload(
    client: httpx.AsyncClient, people
) -> None:
    presets = await client.get("/api/v1/admin/catalogue/presets")
    assert presets.status_code == 200, presets.text
    ids = {row["id"] for row in presets.json()}
    assert {"slack", "visual-studio-code", "zoom"} <= ids
    assert all("team_id" in row and "in_catalogue" in row for row in presets.json())

    ssrf = await client.post(
        "/api/v1/admin/catalogue/inspect",
        json={"source_url": "https://127.0.0.1/evil.dmg"},
        headers=csrf_headers(client),
    )
    assert ssrf.status_code == 422, ssrf.text
    assert ssrf.json()["error"]["code"] == "PACKAGE_REJECTED"

    rejected = await client.post(
        "/api/v1/admin/catalogue/inspect/upload?filename=Tool.zip",
        content=_unsigned_zip(),
        headers={**csrf_headers(client), "Content-Type": "application/octet-stream"},
    )
    assert rejected.status_code == 422, rejected.text
    body = rejected.json()["error"]
    assert body["code"] == "PACKAGE_REJECTED"
    assert body["details"]["reason"] in {
        "UNSIGNED_APP",
        "ARCH_UNREADABLE",
        "APP_EXECUTABLE_MISSING",
    }
    assert "hint" in body["details"]


async def test_installer_unsupported_for_pkg_only_device(
    client: httpx.AsyncClient, people, app_db: Database
) -> None:
    create = await client.post(
        "/api/v1/admin/catalogue/software",
        json={
            "slug": "slack-demo",
            "display_name": "Slack Demo",
            "description": "archive gating",
            "publisher": "Slack Technologies, LLC",
            "category": "communication",
            "risk_level": "LOW",
            "aliases": ["slack-demo"],
        },
        headers=csrf_headers(client),
    )
    assert create.status_code == 201, create.text
    software_id = create.json()["id"]
    await client.post(
        f"/api/v1/admin/catalogue/software/{software_id}/lifecycle",
        params={"status": "ACTIVE"},
        headers=csrf_headers(client),
    )
    version = await client.post(
        "/api/v1/admin/catalogue/versions",
        json={
            "software_id": software_id,
            "version": "4.47.69",
            "os_family": "macos",
            "architecture": "universal",
            "minimum_os_version": "12.0",
            "minimum_memory_bytes": 512 * 1024 * 1024,
            "minimum_disk_bytes": 1024 * 1024 * 1024,
            "installer_type": "MACOS_DMG_APP",
            "source_type": "INTERNAL_ARTIFACT_STORE",
            "source_reference": "artifact://sha256/" + "a" * 64 + ".dmg",
            "package_identifier": "com.tinyspeck.slackmacgap",
            "verification_method": "MACOS_APP_BUNDLE",
            "sha256": "a" * 64,
            "signature_publisher": "Slack Technologies, LLC",
            "signature_required": True,
            "package_size_bytes": 10,
            "expected_team_id": "BQR82RBBHL",
            "payload_path": "Slack.app",
            "release_status": "ACTIVE",
        },
        headers=csrf_headers(client),
    )
    assert version.status_code == 201, version.text
    version_id = version.json()["id"]

    async with app_db.sessionmaker() as session:
        device = Device(
            owner_user_id=people["employee"].id,
            device_name="Pkg Only Mac",
            os_family="macos",
            os_version="15.1",
            architecture="arm64",
            agent_version="0.1.0",
            device_status=DeviceStatus.ACTIVE.value,
            last_seen_at=datetime.now(UTC),
            enrolled_at=datetime.now(UTC),
            supported_installers=["MACOS_PKG"],
        )
        session.add(device)
        await session.flush()
        session.add(
            DeviceFacts(
                device_id=device.id,
                cpu_arch="arm64",
                cpu_cores=8,
                memory_total_bytes=16 * 1024**3,
                disk_free_bytes=80 * 1024**3,
                os_build="24A",
                installed_software_summary={"count": 0, "items": []},
            )
        )
        await session.commit()
        device_id = str(device.id)

    await login(client, people["employee"])
    compat = await client.post(
        "/api/v1/catalogue/compatibility",
        json={"device_id": device_id, "catalogue_version_id": version_id},
        headers=csrf_headers(client),
    )
    assert compat.status_code == 200, compat.text
    assert compat.json()["reason_code"] == "INSTALLER_UNSUPPORTED"
    assert compat.json()["compatible"] is False


async def test_pkg_envelope_omits_archive_fields(app_db: Database) -> None:
    now = datetime.now(UTC)
    async with app_db.sessionmaker() as session:
        user = User(
            email="env-owner@sentinel.test",
            display_name="Env",
            identity_provider=IdentityProvider.LOCAL,
            is_active=True,
        )
        session.add(user)
        await session.flush()
        software = CatalogueSoftware(
            slug="env-pkg",
            display_name="Env Pkg",
            description="x",
            publisher="Example",
            category="utilities",
            lifecycle_status="ACTIVE",
            risk_level="LOW",
        )
        session.add(software)
        await session.flush()
        version = CatalogueVersion(
            software_id=software.id,
            version="1.0.0",
            os_family="macos",
            architecture="universal",
            minimum_os_version="12.0",
            minimum_memory_bytes=1,
            minimum_disk_bytes=1,
            installer_type="MACOS_PKG",
            source_type="INTERNAL_ARTIFACT_STORE",
            source_reference="artifact://sha256/" + "b" * 64 + ".pkg",
            package_identifier="com.example.env",
            verification_method="MACOS_PKG_RECEIPT",
            sha256="b" * 64,
            signature_publisher="Example",
            signature_required=True,
            package_size_bytes=10,
            release_status="ACTIVE",
            expected_team_id=None,
            payload_path=None,
        )
        session.add(version)
        await session.flush()
        device = Device(
            owner_user_id=user.id,
            device_name="Env Mac",
            os_family="macos",
            os_version="15.1",
            architecture="arm64",
            agent_version="0.1.0",
            device_status=DeviceStatus.ACTIVE.value,
            last_seen_at=now,
            enrolled_at=now,
        )
        session.add(device)
        await session.flush()
        request = SoftwareRequest(
            requester_id=user.id,
            device_id=device.id,
            raw_request="install env",
            status="QUEUED",
            catalogue_version_id=version.id,
            software_id=software.id,
            policy_revision=1,
            version=1,
            idempotency_key=f"env-{uuid.uuid4().hex}",
        )
        session.add(request)
        await session.flush()
        job = InstallationJob(
            request_id=request.id,
            device_id=device.id,
            catalogue_version_id=version.id,
            status=JobStatus.QUEUED.value,
            job_nonce=uuid.uuid4().hex,
            expires_at=now + timedelta(hours=1),
            job_payload_hash="0" * 64,
        )
        session.add(job)
        await session.flush()
        envelope = build_envelope(job=job, request=request, version=version, binding_hash="h" * 64)
        await session.commit()

    assert "expected_team_id" not in envelope
    assert "payload_path" not in envelope
    assert envelope["installer_type"] == "MACOS_PKG"


async def test_artifact_endpoint_404_and_403(
    client: httpx.AsyncClient,
    agent: httpx.AsyncClient,
    people,
    app_db: Database,
    settings,
) -> None:
    store = Path(settings.package_store_dir)
    store.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256(b"artifact-bytes").hexdigest()
    (store / f"{digest}.dmg").write_bytes(b"artifact-bytes")

    await login(client, people["admin"])
    token = await new_token(client, people["employee"])
    enrolled = await enroll(agent, token)
    headers = bearer(enrolled["device_credential"])

    missing = await agent.get(f"/api/v1/agent/packages/{'0' * 64}", headers=headers)
    assert missing.status_code == 404

    forbidden = await agent.get(f"/api/v1/agent/packages/{digest}", headers=headers)
    assert forbidden.status_code == 403

    async with app_db.sessionmaker() as session:
        device = await session.get(Device, uuid.UUID(enrolled["device_id"]))
        assert device is not None
        software = CatalogueSoftware(
            slug="art-demo",
            display_name="Art",
            description="x",
            publisher="Example",
            category="utilities",
            lifecycle_status="ACTIVE",
            risk_level="LOW",
        )
        session.add(software)
        await session.flush()
        version = CatalogueVersion(
            software_id=software.id,
            version="1.0.0",
            os_family="macos",
            architecture="universal",
            minimum_os_version="12.0",
            minimum_memory_bytes=1,
            minimum_disk_bytes=1,
            installer_type="MACOS_DMG_APP",
            source_type="INTERNAL_ARTIFACT_STORE",
            source_reference=f"artifact://sha256/{digest}.dmg",
            package_identifier="com.example.art",
            verification_method="MACOS_APP_BUNDLE",
            sha256=digest,
            signature_publisher="Example",
            signature_required=True,
            package_size_bytes=14,
            release_status="ACTIVE",
            expected_team_id="BQR82RBBHL",
            payload_path="Art.app",
        )
        session.add(version)
        await session.flush()
        now = datetime.now(UTC)
        request = SoftwareRequest(
            requester_id=people["employee"].id,
            device_id=device.id,
            raw_request="install art",
            status="DISPATCHED",
            catalogue_version_id=version.id,
            software_id=software.id,
            policy_revision=1,
            version=1,
            idempotency_key=f"art-{uuid.uuid4().hex}",
        )
        session.add(request)
        await session.flush()
        session.add(
            InstallationJob(
                request_id=request.id,
                device_id=device.id,
                catalogue_version_id=version.id,
                status=JobStatus.DISPATCHED.value,
                job_nonce=uuid.uuid4().hex,
                expires_at=now + timedelta(hours=1),
                job_payload_hash="0" * 64,
                claimed_at=now,
            )
        )
        await session.commit()

    ok = await agent.get(f"/api/v1/agent/packages/{digest}", headers=headers)
    assert ok.status_code == 200, ok.text
    assert ok.content == b"artifact-bytes"
    assert ok.headers.get("x-content-sha256") == digest
