"""FastAPI application factory."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.api import health
from app.api.v1 import (
    admin_approvals,
    admin_audit,
    admin_catalogue,
    admin_devices,
    admin_integrations,
    admin_ops,
    admin_security,
    admin_users,
    agent,
    catalogue,
    devices,
    security_eval,
    software_preview,
    software_requests,
)
from app.auth import router as auth_router
from app.auth.entra import JwksCache
from app.core.config import Settings, get_settings
from app.core.errors import register_error_handlers
from app.core.logging import configure_logging
from app.core.middleware import (
    BodySizeLimitMiddleware,
    CorrelationIdMiddleware,
    SecurityHeadersMiddleware,
)
from app.db.session import Database

logger = logging.getLogger("sentineldesk.app")


def create_app(
    settings: Settings | None = None,
    database: Database | None = None,
    http_client: httpx.AsyncClient | None = None,
) -> FastAPI:
    settings = settings or get_settings()
    configure_logging("backend", settings.app_env, settings.log_level)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        logger.info(
            "startup",
            extra={"version": __version__, "integrations": settings.integration_status()},
        )
        yield
        await app.state.http_client.aclose()
        await app.state.db.dispose()

    docs_enabled = not settings.is_production
    app = FastAPI(
        title=settings.app_name,
        version=__version__,
        lifespan=lifespan,
        docs_url="/docs" if docs_enabled else None,
        redoc_url=None,
        openapi_url="/openapi.json" if docs_enabled else None,
    )
    app.state.settings = settings
    app.state.db = database or Database(settings)
    # Outbound calls (Entra, later Gemini/Graph/threat intel) share one client with timeouts
    # and no redirects; tests inject a mock transport here.
    app.state.http_client = http_client or httpx.AsyncClient(
        timeout=httpx.Timeout(10.0), follow_redirects=False
    )
    app.state.entra_jwks = JwksCache()

    register_error_handlers(app)
    # Starlette runs the last-added middleware first.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "DELETE"],
        allow_headers=["Content-Type", "X-CSRF-Token", "X-Correlation-ID", "Idempotency-Key"],
        expose_headers=["X-Correlation-ID"],
        max_age=600,
    )
    app.add_middleware(
        BodySizeLimitMiddleware,
        max_bytes=settings.max_request_bytes,
        upload_max_bytes=settings.catalogue_upload_max_bytes,
    )
    app.add_middleware(SecurityHeadersMiddleware, hsts=settings.is_production)
    app.add_middleware(CorrelationIdMiddleware)

    app.include_router(health.router)
    app.include_router(auth_router.router)
    app.include_router(devices.router)
    app.include_router(catalogue.router)
    app.include_router(security_eval.router)
    app.include_router(software_preview.router)
    app.include_router(software_requests.router)
    app.include_router(admin_approvals.router)
    app.include_router(admin_users.router)
    app.include_router(admin_audit.router)
    app.include_router(admin_integrations.router)
    app.include_router(admin_ops.router)
    app.include_router(admin_devices.router)
    app.include_router(admin_catalogue.router)
    app.include_router(admin_security.router)
    app.include_router(agent.router)
    return app
