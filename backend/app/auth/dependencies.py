"""Authentication and authorization dependencies.

Every protected route resolves the principal from the server-side session and loads roles
from the database; nothing the client sends is trusted for authorization.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from fastapi import Depends, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import service as audit
from app.auth.rbac import Permission, permissions_for
from app.auth.sessions import resolve_session, revoke_session, session_cookie_name
from app.auth.tokens import token_matches
from app.core.config import Settings
from app.core.errors import AppError
from app.db.enums import ActorType, AuditResult
from app.db.session import get_session
from app.users.models import Role, User, UserRole

UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


@dataclass(frozen=True)
class Principal:
    user_id: uuid.UUID
    email: str
    display_name: str
    identity_provider: str
    roles: frozenset[str]
    permissions: frozenset[Permission]
    session_id: uuid.UUID


def get_settings_from(request: Request) -> Settings:
    settings: Settings = request.app.state.settings
    return settings


def client_ip(request: Request) -> str | None:
    # X-Forwarded-For is deliberately ignored until a trusted proxy is configured.
    return request.client.host if request.client else None


def check_origin(request: Request, settings: Settings) -> None:
    origin = request.headers.get("origin")
    if origin is None or origin not in settings.cors_origins:
        raise AppError("CSRF_FAILED", 403)


async def load_role_names(db: AsyncSession, user_id: uuid.UUID) -> frozenset[str]:
    rows = await db.scalars(
        select(Role.name)
        .join(UserRole, UserRole.role_id == Role.id)
        .where(UserRole.user_id == user_id)
    )
    return frozenset(rows.all())


async def get_principal(
    request: Request,
    db: AsyncSession = Depends(get_session),  # noqa: B008
) -> Principal:
    settings = get_settings_from(request)
    token = request.cookies.get(session_cookie_name(settings))
    if not token or len(token) > 128:
        raise AppError("UNAUTHENTICATED", 401)
    session_row = await resolve_session(db, settings, token)
    if session_row is None:
        raise AppError("UNAUTHENTICATED", 401)
    if request.method in UNSAFE_METHODS:
        check_origin(request, settings)
        csrf = request.headers.get("x-csrf-token", "")
        if not csrf or len(csrf) > 128 or not token_matches(csrf, session_row.csrf_token_hash):
            raise AppError("CSRF_FAILED", 403)
    user = await db.get(User, session_row.user_id)
    if user is None or not user.is_active:
        await revoke_session(db, session_row.id)
        await db.commit()
        raise AppError("UNAUTHENTICATED", 401)
    roles = await load_role_names(db, user.id)
    await db.commit()
    return Principal(
        user_id=user.id,
        email=user.email,
        display_name=user.display_name,
        identity_provider=user.identity_provider,
        roles=roles,
        permissions=permissions_for(roles),
        session_id=session_row.id,
    )


def require(*permissions: Permission) -> Callable[..., Awaitable[Principal]]:
    """Dependency factory: the principal must hold every listed permission. Denials are audited."""
    return _require(permissions, any_of=False)


def require_any(*permissions: Permission) -> Callable[..., Awaitable[Principal]]:
    """Dependency factory: the principal must hold at least one listed permission."""
    return _require(permissions, any_of=True)


def _require(
    permissions: tuple[Permission, ...], *, any_of: bool
) -> Callable[..., Awaitable[Principal]]:
    async def dependency(
        request: Request,
        principal: Principal = Depends(get_principal),  # noqa: B008
        db: AsyncSession = Depends(get_session),  # noqa: B008
    ) -> Principal:
        missing = [p for p in permissions if p not in principal.permissions]
        if any_of and len(missing) < len(permissions):
            missing = []
        if missing:
            await audit.record(
                db,
                action="ACCESS_DENIED",
                resource_type="api",
                resource_id=request.url.path[:64],
                result=AuditResult.DENIED,
                actor_type=ActorType.USER,
                actor_id=principal.user_id,
                reason_code="MISSING_PERMISSION",
                source_ip=client_ip(request),
                metadata={"permission": missing[0].value, "method": request.method},
            )
            await db.commit()
            raise AppError("FORBIDDEN", 403)
        return principal

    return dependency
