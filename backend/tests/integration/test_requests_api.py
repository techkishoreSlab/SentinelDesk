"""Request create / idempotency / approval / self-approval (Phase 7)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import httpx
import pytest
from sqlalchemy import select

from app.db.enums import DeviceStatus, RoleName
from app.db.session import Database
from app.devices.models import Device, DeviceFacts
from app.security.seed import seed_security
from tests.integration.conftest import SeededUser, csrf_headers, login


@pytest.fixture
async def people(client: httpx.AsyncClient, make_user) -> dict[str, SeededUser]:
    employee = await make_user("emp-req@sentinel.test", [RoleName.EMPLOYEE])
    approver = await make_user("approver-req@sentinel.test", [RoleName.EMPLOYEE, RoleName.APPROVER])
    await login(client, employee)
    return {"employee": employee, "approver": approver}


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
            device_name="Request Mac",
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
async def test_submit_git_awaits_approval_and_idempotent(
    client: httpx.AsyncClient,
    app_db: Database,
    people: dict[str, SeededUser],
    seeded: None,
) -> None:
    device_id = await _device(app_db, people["employee"].id)
    key = "idem-git-1"
    body = {
        "device_id": str(device_id),
        "user_prompt": "Install git",
        "idempotency_key": key,
    }
    first = await client.post("/api/v1/software/requests", headers=csrf_headers(client), json=body)
    assert first.status_code == 200, first.text
    payload = first.json()
    assert payload["status"] == "AWAITING_APPROVAL"
    assert payload["software_slug"] == "git"
    assert payload["replayed"] is False

    second = await client.post("/api/v1/software/requests", headers=csrf_headers(client), json=body)
    assert second.status_code == 200
    assert second.json()["id"] == payload["id"]
    assert second.json()["replayed"] is True


@pytest.mark.asyncio
async def test_approver_can_approve_and_self_approval_forbidden(
    client: httpx.AsyncClient,
    app_db: Database,
    people: dict[str, SeededUser],
    seeded: None,
) -> None:
    device_id = await _device(app_db, people["employee"].id)
    created = await client.post(
        "/api/v1/software/requests",
        headers=csrf_headers(client),
        json={
            "device_id": str(device_id),
            "user_prompt": "Install git",
            "idempotency_key": "idem-git-approve",
        },
    )
    assert created.status_code == 200, created.text
    request_id = created.json()["id"]
    version = created.json()["request_version"]

    # Employee lacks approval:decide → 403 from RBAC.
    denied = await client.post(
        f"/api/v1/admin/approvals/{request_id}/decision",
        headers=csrf_headers(client),
        json={"decision": "APPROVED", "expected_version": version},
    )
    assert denied.status_code == 403

    # Approver cannot approve their own request.
    await login(client, people["approver"])
    own_device = await _device(app_db, people["approver"].id)
    own = await client.post(
        "/api/v1/software/requests",
        headers=csrf_headers(client),
        json={
            "device_id": str(own_device),
            "user_prompt": "Install git",
            "idempotency_key": "idem-self-approve",
        },
    )
    assert own.status_code == 200, own.text
    self_denied = await client.post(
        f"/api/v1/admin/approvals/{own.json()['id']}/decision",
        headers=csrf_headers(client),
        json={"decision": "APPROVED", "expected_version": own.json()["request_version"]},
    )
    assert self_denied.status_code == 403
    assert self_denied.json()["error"]["code"] == "SELF_APPROVAL_FORBIDDEN"

    queue = await client.get("/api/v1/admin/approvals", headers=csrf_headers(client))
    assert queue.status_code == 200
    assert any(i["request_id"] == request_id for i in queue.json())

    ok = await client.post(
        f"/api/v1/admin/approvals/{request_id}/decision",
        headers=csrf_headers(client),
        json={"decision": "APPROVED", "expected_version": version, "comment": "ok for demo"},
    )
    assert ok.status_code == 200, ok.text
    assert ok.json()["status"] == "QUEUED"
    assert ok.json()["decision"] == "APPROVED"

    again = await client.post(
        f"/api/v1/admin/approvals/{request_id}/decision",
        headers=csrf_headers(client),
        json={"decision": "REJECTED", "expected_version": version + 1},
    )
    assert again.status_code == 409


@pytest.mark.asyncio
async def test_vscode_auto_approves_to_queued(
    client: httpx.AsyncClient,
    app_db: Database,
    people: dict[str, SeededUser],
    seeded: None,
) -> None:
    device_id = await _device(app_db, people["employee"].id)
    resp = await client.post(
        "/api/v1/software/requests",
        headers=csrf_headers(client),
        json={
            "device_id": str(device_id),
            "user_prompt": "Install VS Code",
            "idempotency_key": "idem-vscode-auto",
        },
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "QUEUED"
    assert resp.json()["software_slug"] == "visual-studio-code"
