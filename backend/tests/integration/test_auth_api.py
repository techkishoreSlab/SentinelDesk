"""Local login, sessions, CSRF, lockout, RBAC, IDOR, role administration and audit API."""

from __future__ import annotations

import uuid

import httpx
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncEngine

from app.audit.models import AuditEvent
from app.auth.rbac import Permission
from app.db.enums import RoleName
from app.db.session import Database
from app.devices.models import Device
from tests.integration.conftest import WEB_ORIGIN, csrf_headers, login


async def _actions(app_db: Database) -> list[tuple[str, str, str | None]]:
    async with app_db.sessionmaker() as s:
        rows = await s.execute(
            select(AuditEvent.action, AuditEvent.result, AuditEvent.reason_code).order_by(
                AuditEvent.seq
            )
        )
        return [tuple(r) for r in rows.all()]  # type: ignore[misc]


# --- login and sessions --------------------------------------------------------------------


async def test_login_sets_hardened_cookies_and_me_works(
    client: httpx.AsyncClient, make_user, app_db: Database
) -> None:
    user = await make_user("alice@sentinel.test", [RoleName.EMPLOYEE])
    resp = await login(client, user)
    assert resp.json()["roles"] == ["EMPLOYEE"]
    cookies = resp.headers.get_list("set-cookie")
    session_cookie = next(c for c in cookies if c.startswith("sd_session="))
    assert "HttpOnly" in session_cookie and "SameSite=lax" in session_cookie
    csrf_cookie = next(c for c in cookies if c.startswith("sd_csrf="))
    assert "HttpOnly" not in csrf_cookie

    me = await client.get("/api/v1/me")
    assert me.status_code == 200
    assert me.json()["email"] == "alice@sentinel.test"
    assert Permission.REQUEST_CREATE.value in me.json()["permissions"]
    assert Permission.ROLE_ASSIGN.value not in me.json()["permissions"]
    assert ("LOGIN_SUCCEEDED", "SUCCESS", None) in await _actions(app_db)


async def test_wrong_password_and_unknown_user_are_indistinguishable(
    client: httpx.AsyncClient, make_user, app_db: Database
) -> None:
    await make_user("bob@sentinel.test", [RoleName.EMPLOYEE])
    bad_pw = await client.post(
        "/api/v1/auth/login",
        json={"email": "bob@sentinel.test", "password": "wrong-password-123"},
        headers={"Origin": WEB_ORIGIN},
    )
    unknown = await client.post(
        "/api/v1/auth/login",
        json={"email": "nobody@sentinel.test", "password": "wrong-password-123"},
        headers={"Origin": WEB_ORIGIN},
    )
    assert bad_pw.status_code == unknown.status_code == 401
    for r in (bad_pw, unknown):
        body = r.json()["error"]
        assert body["code"] == "INVALID_CREDENTIALS"
        assert "sd_session" not in r.headers.get("set-cookie", "")
    assert bad_pw.json()["error"]["message"] == unknown.json()["error"]["message"]
    failures = [a for a in await _actions(app_db) if a[0] == "LOGIN_FAILED"]
    assert failures == [("LOGIN_FAILED", "DENIED", "INVALID_CREDENTIALS")] * 2


async def test_disabled_user_cannot_log_in(client: httpx.AsyncClient, make_user) -> None:
    user = await make_user("gone@sentinel.test", [RoleName.EMPLOYEE], active=False)
    resp = await client.post(
        "/api/v1/auth/login",
        json={"email": user.email, "password": user.password},
        headers={"Origin": WEB_ORIGIN},
    )
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "INVALID_CREDENTIALS"


async def test_login_requires_trusted_origin(client: httpx.AsyncClient, make_user) -> None:
    user = await make_user("carol@sentinel.test", [RoleName.EMPLOYEE])
    body = {"email": user.email, "password": user.password}
    missing = await client.post("/api/v1/auth/login", json=body)
    evil = await client.post(
        "/api/v1/auth/login", json=body, headers={"Origin": "https://evil.example"}
    )
    assert missing.status_code == evil.status_code == 403
    assert evil.json()["error"]["code"] == "CSRF_FAILED"


async def test_lockout_after_repeated_failures(
    client: httpx.AsyncClient, make_user, app_db: Database
) -> None:
    user = await make_user("dave@sentinel.test", [RoleName.EMPLOYEE])
    for _ in range(5):
        r = await client.post(
            "/api/v1/auth/login",
            json={"email": user.email, "password": "definitely-wrong-1"},
            headers={"Origin": WEB_ORIGIN},
        )
        assert r.status_code == 401
    locked = await client.post(
        "/api/v1/auth/login",
        json={"email": user.email, "password": user.password},
        headers={"Origin": WEB_ORIGIN},
    )
    assert locked.status_code == 429
    assert locked.json()["error"]["code"] == "RATE_LIMITED"
    assert ("LOGIN_FAILED", "DENIED", "RATE_LIMITED") in await _actions(app_db)


async def test_logout_requires_csrf_and_revokes_session(
    client: httpx.AsyncClient, make_user
) -> None:
    user = await make_user("erin@sentinel.test", [RoleName.EMPLOYEE])
    await login(client, user)
    stolen = client.cookies["sd_session"]

    no_token = await client.post("/api/v1/auth/logout", headers={"Origin": WEB_ORIGIN})
    assert no_token.status_code == 403
    wrong = await client.post(
        "/api/v1/auth/logout", headers={"Origin": WEB_ORIGIN, "X-CSRF-Token": "forged"}
    )
    assert wrong.status_code == 403
    bad_origin = await client.post(
        "/api/v1/auth/logout",
        headers={"Origin": "https://evil.example", "X-CSRF-Token": client.cookies["sd_csrf"]},
    )
    assert bad_origin.status_code == 403

    ok = await client.post("/api/v1/auth/logout", headers=csrf_headers(client))
    assert ok.status_code == 204
    client.cookies.clear()
    client.cookies.set("sd_session", stolen)
    replay = await client.get("/api/v1/me")
    assert replay.status_code == 401


async def test_expired_session_rejected(
    client: httpx.AsyncClient, make_user, owner_engine: AsyncEngine
) -> None:
    user = await make_user("frank@sentinel.test", [RoleName.EMPLOYEE])
    await login(client, user)
    async with owner_engine.begin() as conn:
        await conn.execute(text("UPDATE sessions SET idle_expires_at = now() - interval '1 s'"))
    assert (await client.get("/api/v1/me")).status_code == 401


async def test_deactivated_user_session_stops_working(
    client: httpx.AsyncClient, make_user, owner_engine: AsyncEngine
) -> None:
    user = await make_user("gina@sentinel.test", [RoleName.EMPLOYEE])
    await login(client, user)
    async with owner_engine.begin() as conn:
        await conn.execute(text("UPDATE users SET is_active = false"))
    assert (await client.get("/api/v1/me")).status_code == 401


async def test_unauthenticated_requests_rejected(client: httpx.AsyncClient) -> None:
    for path in ("/api/v1/me", "/api/v1/devices", "/api/v1/admin/users", "/api/v1/admin/audit"):
        resp = await client.get(path)
        assert resp.status_code == 401, path
        assert resp.json()["error"]["code"] == "UNAUTHENTICATED"


async def test_providers_and_entra_not_configured(client: httpx.AsyncClient) -> None:
    assert (await client.get("/api/v1/auth/providers")).json() == {"local": True, "entra": False}
    resp = await client.get("/api/v1/auth/entra/login")
    assert resp.status_code == 503
    assert resp.json()["error"]["code"] == "INTEGRATION_NOT_CONFIGURED"


# --- RBAC and IDOR -------------------------------------------------------------------------


async def test_employee_forbidden_from_admin_and_denial_audited(
    client: httpx.AsyncClient, make_user, app_db: Database
) -> None:
    user = await make_user("henry@sentinel.test", [RoleName.EMPLOYEE])
    await login(client, user)
    for path in ("/api/v1/admin/users", "/api/v1/admin/audit", "/api/v1/admin/integrations/status"):
        resp = await client.get(path)
        assert resp.status_code == 403, path
        assert resp.json()["error"]["code"] == "FORBIDDEN"
    denials = [a for a in await _actions(app_db) if a[0] == "ACCESS_DENIED"]
    assert len(denials) == 3
    assert all(d[2] == "MISSING_PERMISSION" for d in denials)


async def test_auditor_reads_audit_but_cannot_change_roles(
    client: httpx.AsyncClient, make_user
) -> None:
    auditor = await make_user("ivy@sentinel.test", [RoleName.AUDITOR])
    target = await make_user("jack@sentinel.test", [RoleName.EMPLOYEE])
    await login(client, auditor)
    page = await client.get("/api/v1/admin/audit?limit=1")
    assert page.status_code == 200
    assert len(page.json()["items"]) == 1
    assert page.json()["next_before_seq"] is not None
    assert (await client.get("/api/v1/admin/audit/verify")).json()["valid"] is True
    denied = await client.post(
        f"/api/v1/admin/users/{target.id}/roles",
        json={"role": "APPROVER"},
        headers=csrf_headers(client),
    )
    assert denied.status_code == 403
    assert (await client.get("/api/v1/devices")).status_code == 403


async def test_devices_are_scoped_to_owner(
    client: httpx.AsyncClient, make_user, app_db: Database
) -> None:
    owner = await make_user("kate@sentinel.test", [RoleName.EMPLOYEE])
    other = await make_user("liam@sentinel.test", [RoleName.EMPLOYEE])
    async with app_db.sessionmaker() as s:
        mine = Device(
            owner_user_id=owner.id,
            device_name="kate-mac",
            os_family="macos",
            os_version="26.5",
            architecture="x86_64",
            agent_version="0.1.0",
            device_status="ACTIVE",
        )
        theirs = Device(
            owner_user_id=other.id,
            device_name="liam-mac",
            os_family="macos",
            os_version="26.5",
            architecture="arm64",
            agent_version="0.1.0",
            device_status="ACTIVE",
        )
        s.add_all([mine, theirs])
        await s.commit()
        mine_id, theirs_id = mine.id, theirs.id

    await login(client, owner)
    listed = await client.get("/api/v1/devices")
    assert [d["id"] for d in listed.json()] == [str(mine_id)]
    assert (await client.get(f"/api/v1/devices/{mine_id}")).status_code == 200
    probe = await client.get(f"/api/v1/devices/{theirs_id}")
    assert probe.status_code == 404
    assert (await client.get(f"/api/v1/devices/{uuid.uuid4()}")).status_code == 404
    assert (await client.get("/api/v1/devices/not-a-uuid")).status_code == 422


# --- role administration -------------------------------------------------------------------


async def test_platform_admin_assigns_and_removes_roles_with_audit(
    client: httpx.AsyncClient, make_user, app_db: Database
) -> None:
    admin = await make_user("admin@sentinel.test", [RoleName.EMPLOYEE, RoleName.PLATFORM_ADMIN])
    target = await make_user("mia@sentinel.test", [RoleName.EMPLOYEE])
    await login(client, admin)

    users = await client.get("/api/v1/admin/users")
    assert users.status_code == 200 and users.json()["total"] == 2

    added = await client.post(
        f"/api/v1/admin/users/{target.id}/roles",
        json={"role": "APPROVER"},
        headers=csrf_headers(client),
    )
    assert added.status_code == 200
    assert added.json()["roles"] == ["APPROVER", "EMPLOYEE"]
    again = await client.post(
        f"/api/v1/admin/users/{target.id}/roles",
        json={"role": "APPROVER"},
        headers=csrf_headers(client),
    )
    assert again.status_code == 200

    removed = await client.delete(
        f"/api/v1/admin/users/{target.id}/roles/APPROVER", headers=csrf_headers(client)
    )
    assert removed.json()["roles"] == ["EMPLOYEE"]
    actions = [a[0] for a in await _actions(app_db)]
    assert actions.count("ROLE_ASSIGN") == 1  # idempotent re-assign is not re-audited
    assert actions.count("ROLE_REMOVE") == 1


async def test_role_change_guards(client: httpx.AsyncClient, make_user, app_db: Database) -> None:
    admin = await make_user("root@sentinel.test", [RoleName.PLATFORM_ADMIN])
    target = await make_user("noah@sentinel.test", [RoleName.EMPLOYEE])
    await login(client, admin)

    self_change = await client.delete(
        f"/api/v1/admin/users/{admin.id}/roles/PLATFORM_ADMIN", headers=csrf_headers(client)
    )
    assert self_change.status_code == 403
    assert self_change.json()["error"]["code"] == "SELF_ROLE_CHANGE_FORBIDDEN"
    assert ("ROLE_REMOVE", "DENIED", "SELF_ROLE_CHANGE_FORBIDDEN") in await _actions(app_db)

    no_csrf = await client.post(
        f"/api/v1/admin/users/{target.id}/roles",
        json={"role": "APPROVER"},
        headers={"Origin": WEB_ORIGIN},
    )
    assert no_csrf.status_code == 403
    bogus_role = await client.post(
        f"/api/v1/admin/users/{target.id}/roles",
        json={"role": "SUPERUSER"},
        headers=csrf_headers(client),
    )
    assert bogus_role.status_code == 422
    extra_field = await client.post(
        f"/api/v1/admin/users/{target.id}/roles",
        json={"role": "APPROVER", "user_id": str(admin.id)},
        headers=csrf_headers(client),
    )
    assert extra_field.status_code == 422
    missing = await client.post(
        f"/api/v1/admin/users/{uuid.uuid4()}/roles",
        json={"role": "APPROVER"},
        headers=csrf_headers(client),
    )
    assert missing.status_code == 404


async def test_integration_status_has_no_secret_values(
    client: httpx.AsyncClient, make_user
) -> None:
    admin = await make_user("ops@sentinel.test", [RoleName.PLATFORM_ADMIN])
    await login(client, admin)
    resp = await client.get("/api/v1/admin/integrations/status")
    assert resp.status_code == 200
    assert set(resp.json().values()) <= {"configured", "not_configured"}
