"""Server-side sessions with HttpOnly cookies and double-submit CSRF tokens (spec §12.5)."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from fastapi import Response
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.tokens import hash_token, new_token
from app.core.config import Settings
from app.users.models import Session

_TOUCH_INTERVAL = timedelta(seconds=60)


def session_cookie_name(settings: Settings) -> str:
    # The __Host- prefix requires Secure, Path=/ and no Domain, so it is only used over HTTPS.
    return "__Host-sd_session" if settings.is_production else "sd_session"


def csrf_cookie_name(settings: Settings) -> str:
    return "__Host-sd_csrf" if settings.is_production else "sd_csrf"


@dataclass(frozen=True)
class IssuedSession:
    session: Session
    token: str
    csrf_token: str


async def create_session(
    db: AsyncSession,
    settings: Settings,
    *,
    user_id: uuid.UUID,
    identity_provider: str,
    source_ip: str | None,
    user_agent: str | None,
) -> IssuedSession:
    now = datetime.now(UTC)
    token, csrf = new_token(), new_token()
    row = Session(
        user_id=user_id,
        token_hash=hash_token(token),
        csrf_token_hash=hash_token(csrf),
        identity_provider=identity_provider,
        created_at=now,
        last_seen_at=now,
        idle_expires_at=now + timedelta(minutes=settings.session_idle_minutes),
        absolute_expires_at=now + timedelta(hours=settings.session_absolute_hours),
        source_ip=source_ip,
        user_agent=(user_agent or "")[:200] or None,
    )
    db.add(row)
    await db.flush()
    return IssuedSession(row, token, csrf)


async def resolve_session(db: AsyncSession, settings: Settings, token: str) -> Session | None:
    row = await db.scalar(select(Session).where(Session.token_hash == hash_token(token)))
    now = datetime.now(UTC)
    if (
        row is None
        or row.revoked_at is not None
        or row.idle_expires_at <= now
        or row.absolute_expires_at <= now
    ):
        return None
    if now - row.last_seen_at >= _TOUCH_INTERVAL:
        row.last_seen_at = now
        row.idle_expires_at = min(
            now + timedelta(minutes=settings.session_idle_minutes), row.absolute_expires_at
        )
    return row


async def revoke_session(db: AsyncSession, session_id: uuid.UUID) -> None:
    await db.execute(
        update(Session)
        .where(Session.id == session_id, Session.revoked_at.is_(None))
        .values(revoked_at=datetime.now(UTC))
    )


def set_session_cookies(response: Response, settings: Settings, issued: IssuedSession) -> None:
    max_age = settings.session_absolute_hours * 3600
    secure = settings.is_production
    response.set_cookie(
        session_cookie_name(settings),
        issued.token,
        max_age=max_age,
        httponly=True,
        secure=secure,
        samesite="lax",
        path="/",
    )
    # Readable by the web app so it can echo it in the X-CSRF-Token header.
    response.set_cookie(
        csrf_cookie_name(settings),
        issued.csrf_token,
        max_age=max_age,
        httponly=False,
        secure=secure,
        samesite="strict",
        path="/",
    )


def clear_session_cookies(response: Response, settings: Settings) -> None:
    for name in (session_cookie_name(settings), csrf_cookie_name(settings)):
        response.delete_cookie(name, path="/", secure=settings.is_production)
