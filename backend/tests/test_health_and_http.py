from __future__ import annotations

import uuid
from collections.abc import AsyncIterator

import httpx


async def test_live(client: httpx.AsyncClient) -> None:
    resp = await client.get("/health/live")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


async def test_ready_ok(client: httpx.AsyncClient) -> None:
    resp = await client.get("/health/ready")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ready", "checks": {"database": "ok"}}


async def test_ready_reports_unavailable_database(unhealthy_client: httpx.AsyncClient) -> None:
    resp = await unhealthy_client.get("/health/ready")
    assert resp.status_code == 503
    body = resp.json()["error"]
    assert body["code"] == "SERVICE_UNAVAILABLE"
    assert body["details"] == {"checks": {"database": "unavailable"}}


async def test_correlation_id_generated_and_echoed(client: httpx.AsyncClient) -> None:
    resp = await client.get("/health/live")
    uuid.UUID(resp.headers["x-correlation-id"])

    supplied = str(uuid.uuid4())
    resp = await client.get("/health/live", headers={"X-Correlation-ID": supplied})
    assert resp.headers["x-correlation-id"] == supplied


async def test_non_uuid_correlation_id_replaced(client: httpx.AsyncClient) -> None:
    resp = await client.get("/health/live", headers={"X-Correlation-ID": "<script>x</script>"})
    assert resp.headers["x-correlation-id"] != "<script>x</script>"
    uuid.UUID(resp.headers["x-correlation-id"])


async def test_not_found_uses_standard_error_format(client: httpx.AsyncClient) -> None:
    resp = await client.get("/does-not-exist")
    assert resp.status_code == 404
    err = resp.json()["error"]
    assert err["code"] == "NOT_FOUND"
    assert err["correlation_id"] == resp.headers["x-correlation-id"]
    assert set(err) == {"code", "message", "correlation_id"}


async def test_security_headers_present(client: httpx.AsyncClient) -> None:
    resp = await client.get("/health/live")
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert resp.headers["x-frame-options"] == "DENY"
    assert "default-src 'none'" in resp.headers["content-security-policy"]
    assert resp.headers["cache-control"] == "no-store"


async def test_declared_oversized_body_rejected(client: httpx.AsyncClient) -> None:
    resp = await client.post("/health/live", content=b"x" * 5000)
    assert resp.status_code == 413
    assert resp.json()["error"]["code"] == "PAYLOAD_TOO_LARGE"


async def test_streamed_oversized_body_rejected_without_content_length() -> None:
    from fastapi import Body

    from app.main import create_app
    from tests.conftest import FakeDatabase, make_settings

    app = create_app(make_settings(), FakeDatabase(healthy=True))

    @app.post("/echo")
    async def echo(payload: dict[str, str] = Body(...)) -> dict[str, int]:  # noqa: B008
        return {"keys": len(payload)}

    async def chunks() -> AsyncIterator[bytes]:
        yield b'{"a": "'
        for _ in range(10):
            yield b"y" * 1000
        yield b'"}'

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        resp = await c.post("/echo", content=chunks(), headers={"content-type": "application/json"})
    assert "content-length" not in resp.request.headers
    assert resp.status_code == 413
    assert resp.json()["error"]["code"] == "PAYLOAD_TOO_LARGE"


async def test_cors_allows_only_configured_origin(client: httpx.AsyncClient) -> None:
    headers = {"Origin": "http://localhost:5173", "Access-Control-Request-Method": "GET"}
    ok = await client.options("/health/live", headers=headers)
    assert ok.headers.get("access-control-allow-origin") == "http://localhost:5173"

    headers["Origin"] = "http://evil.example"
    bad = await client.options("/health/live", headers=headers)
    assert "access-control-allow-origin" not in bad.headers


async def test_docs_disabled_in_production() -> None:
    import secrets
    from pathlib import Path

    from app.main import create_app
    from tests.conftest import FakeDatabase, make_settings

    key = Path(__file__)
    settings = make_settings(
        app_env="production",
        api_base_url="https://api.example.com",
        cors_allowed_origins="https://app.example.com",
        job_signing_private_key_path=key,
        job_signing_public_key_path=key,
        session_secret=secrets.token_urlsafe(48),
        local_auth_enabled=False,
    )
    app = create_app(settings, FakeDatabase(healthy=True))
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        assert (await c.get("/docs")).status_code == 404
        assert (await c.get("/openapi.json")).status_code == 404
        assert "strict-transport-security" in (await c.get("/health/live")).headers
