"""Failed-login throttling with lockout, keyed by pseudonymized account and by client IP.

Keys exist for unknown accounts too, so lockout behaviour does not reveal whether an
account exists.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import case, delete, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.tokens import pseudonymize
from app.core.config import Settings
from app.users.models import AuthThrottle

IP_MULTIPLIER = 4


def account_key(email: str) -> str:
    return f"acct:{pseudonymize(email)}"


def ip_key(ip: str | None) -> str:
    return f"ip:{ip or 'unknown'}"


async def is_locked(db: AsyncSession, keys: list[str]) -> bool:
    now = datetime.now(UTC)
    locked = await db.scalar(
        select(AuthThrottle.key).where(AuthThrottle.key.in_(keys), AuthThrottle.locked_until > now)
    )
    return locked is not None


async def record_failure(db: AsyncSession, settings: Settings, key: str, threshold: int) -> None:
    now = datetime.now(UTC)
    window = timedelta(minutes=settings.login_lockout_minutes)
    window_expired = AuthThrottle.window_started_at < now - window
    base = insert(AuthThrottle).values(key=key, failure_count=1, window_started_at=now)
    stmt = base.on_conflict_do_update(
        index_elements=[AuthThrottle.key],
        set_={
            "failure_count": case((window_expired, 1), else_=AuthThrottle.failure_count + 1),
            "window_started_at": case((window_expired, now), else_=AuthThrottle.window_started_at),
        },
    ).returning(AuthThrottle.failure_count)
    count = (await db.execute(stmt)).scalar_one()
    if count >= threshold:
        row = await db.get(AuthThrottle, key, populate_existing=True)
        if row is not None:
            row.locked_until = now + window
            row.failure_count = 0
            row.window_started_at = now


async def record_login_failure(
    db: AsyncSession, settings: Settings, email: str, ip: str | None
) -> None:
    await record_failure(db, settings, account_key(email), settings.login_max_failures)
    await record_failure(db, settings, ip_key(ip), settings.login_max_failures * IP_MULTIPLIER)


async def reset_account(db: AsyncSession, email: str) -> None:
    await db.execute(delete(AuthThrottle).where(AuthThrottle.key == account_key(email)))
