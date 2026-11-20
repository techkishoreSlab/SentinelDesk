"""Admin ops metrics and retention purge (Phase 9)."""

from __future__ import annotations

import httpx
import pytest

from app.db.enums import RoleName
from tests.integration.conftest import SeededUser, csrf_headers, login


@pytest.fixture
async def admin(client: httpx.AsyncClient, make_user) -> SeededUser:
    user = await make_user(
        "ops-admin@sentinel.test",
        [RoleName.EMPLOYEE, RoleName.PLATFORM_ADMIN, RoleName.SECURITY_ADMIN],
    )
    await login(client, user)
    return user


@pytest.mark.asyncio
async def test_metrics_requires_auth_and_returns_shape(
    client: httpx.AsyncClient,
    admin: SeededUser,
) -> None:
    bare = httpx.AsyncClient(transport=client._transport, base_url="http://testserver")
    denied = await bare.get("/api/v1/admin/ops/metrics")
    assert denied.status_code in {401, 403}

    ok = await client.get("/api/v1/admin/ops/metrics", headers=csrf_headers(client))
    assert ok.status_code == 200, ok.text
    body = ok.json()
    assert "requests_by_status" in body
    assert "jobs_by_status" in body
    assert "install_outcomes" in body
    assert "job_queue_depth" in body
    assert body["devices_total"] >= 0
    assert "notification_delivery_issues" in body


@pytest.mark.asyncio
async def test_purge_expired_ok(
    client: httpx.AsyncClient,
    admin: SeededUser,
) -> None:
    purged = await client.post("/api/v1/admin/ops/purge-expired", headers=csrf_headers(client))
    assert purged.status_code == 200, purged.text
    body = purged.json()["purged"]
    for key in (
        "sessions",
        "oidc_login_states",
        "auth_throttle",
        "enrollment_tokens",
        "installation_jobs_expired",
        "requests_expired",
    ):
        assert key in body
        assert isinstance(body[key], int)
