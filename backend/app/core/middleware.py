"""ASGI middleware: correlation IDs, security headers and request size limits."""

from __future__ import annotations

import logging
import time
import uuid

from fastapi import HTTPException
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.errors import error_response
from app.core.logging import correlation_id_var

logger = logging.getLogger("sentineldesk.http")

CORRELATION_HEADER = b"x-correlation-id"


def _valid_uuid(value: str) -> bool:
    try:
        uuid.UUID(value)
    except ValueError:
        return False
    return True


class CorrelationIdMiddleware:
    """Accept a client-supplied UUID correlation ID or generate one; echo it back."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        supplied = dict(scope["headers"]).get(CORRELATION_HEADER, b"").decode("latin-1")
        correlation_id = supplied if _valid_uuid(supplied) else str(uuid.uuid4())
        token = correlation_id_var.set(correlation_id)
        started = time.perf_counter()
        status_holder: dict[str, int] = {}

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                status_holder["status"] = message["status"]
                headers = list(message.get("headers", []))
                headers.append((CORRELATION_HEADER, correlation_id.encode()))
                message["headers"] = headers
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            logger.info(
                "http_request",
                extra={
                    "method": scope.get("method"),
                    "path": scope.get("path"),
                    "status": status_holder.get("status"),
                    "duration_ms": round((time.perf_counter() - started) * 1000, 2),
                },
            )
            correlation_id_var.reset(token)


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp, hsts: bool) -> None:
        self.app = app
        self.headers = [
            (b"x-content-type-options", b"nosniff"),
            (b"x-frame-options", b"DENY"),
            (b"referrer-policy", b"no-referrer"),
            (b"cross-origin-opener-policy", b"same-origin"),
            (b"permissions-policy", b"camera=(), microphone=(), geolocation=()"),
            (b"cache-control", b"no-store"),
        ]
        self.default_csp = b"default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
        # Swagger UI loads its assets from a CDN; only applies when docs are enabled.
        self.docs_csp = (
            b"default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            b"style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            b"img-src 'self' data: https://fastapi.tiangolo.com; frame-ancestors 'none'"
        )
        if hsts:
            self.headers.append((b"strict-transport-security", b"max-age=31536000"))

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path: str = scope.get("path", "")
        csp = self.docs_csp if path in ("/docs", "/redoc") else self.default_csp

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                headers.extend(self.headers)
                headers.append((b"content-security-policy", csp))
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_wrapper)


class BodySizeLimitMiddleware:
    """Reject bodies over the limit using Content-Length and the actual streamed size."""

    def __init__(self, app: ASGIApp, max_bytes: int, upload_max_bytes: int | None = None) -> None:
        self.app = app
        self.max_bytes = max_bytes
        self.upload_max_bytes = upload_max_bytes or max_bytes

    def _limit_for(self, scope: Scope) -> int:
        path = scope.get("path", "")
        if path.endswith(("/admin/catalogue/ingest", "/admin/catalogue/inspect/upload")):
            return self.upload_max_bytes
        return self.max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        limit = self._limit_for(scope)
        declared = dict(scope["headers"]).get(b"content-length")
        if declared is not None:
            try:
                too_large = int(declared) > limit
            except ValueError:
                too_large = True
            if too_large:
                await error_response("PAYLOAD_TOO_LARGE", 413)(scope, receive, send)
                return

        received = 0

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    # HTTPException survives FastAPI's body-parsing error wrapper.
                    raise HTTPException(status_code=413)
            return message

        await self.app(scope, limited_receive, send)
