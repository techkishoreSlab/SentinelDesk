"""Expire/purge stale operational rows (spec §5.3, §11.7; K12)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import CursorResult, and_, delete, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.enums import JobStatus, RequestStatus
from app.devices.models import EnrollmentToken
from app.requests.models import InstallationJob, SoftwareRequest
from app.users.models import AuthThrottle, OidcLoginState, Session


def _rowcount(result: CursorResult[Any]) -> int:
    return int(result.rowcount or 0)


async def purge_expired(db: AsyncSession, *, now: datetime | None = None) -> dict[str, int]:
    """Delete expired auth/session rows and mark overdue jobs EXPIRED.

    Does not delete audit_events (append-only). Safe to run repeatedly.
    """
    clock = now or datetime.now(UTC)
    counts: dict[str, int] = {}

    sessions = await db.execute(
        delete(Session).where(
            or_(
                Session.absolute_expires_at <= clock,
                Session.idle_expires_at <= clock,
                Session.revoked_at.is_not(None),
            )
        )
    )
    counts["sessions"] = _rowcount(sessions)  # type: ignore[arg-type]

    oidc = await db.execute(
        delete(OidcLoginState).where(
            or_(
                OidcLoginState.expires_at <= clock,
                OidcLoginState.consumed_at.is_not(None),
            )
        )
    )
    counts["oidc_login_states"] = _rowcount(oidc)  # type: ignore[arg-type]

    # Drop throttle rows whose lock has ended, or unlocked windows older than 24h.
    throttle_cutoff = clock - timedelta(hours=24)
    throttle = await db.execute(
        delete(AuthThrottle).where(
            or_(
                and_(AuthThrottle.locked_until.is_not(None), AuthThrottle.locked_until <= clock),
                and_(
                    AuthThrottle.locked_until.is_(None),
                    AuthThrottle.window_started_at <= throttle_cutoff,
                ),
            )
        )
    )
    counts["auth_throttle"] = _rowcount(throttle)  # type: ignore[arg-type]

    tokens = await db.execute(delete(EnrollmentToken).where(EnrollmentToken.expires_at <= clock))
    counts["enrollment_tokens"] = _rowcount(tokens)  # type: ignore[arg-type]

    counts.update(await expire_abandoned_jobs(db, now=clock))
    await db.commit()
    return counts


async def expire_abandoned_jobs(db: AsyncSession, *, now: datetime | None = None) -> dict[str, int]:
    """Mark overdue QUEUED/DISPATCHED/RUNNING jobs (and linked requests) EXPIRED."""
    clock = now or datetime.now(UTC)
    active = {
        JobStatus.QUEUED.value,
        JobStatus.DISPATCHED.value,
        JobStatus.RUNNING.value,
        JobStatus.VERIFYING.value,
    }
    overdue = (
        await db.scalars(
            select(InstallationJob).where(
                InstallationJob.status.in_(active),
                InstallationJob.expires_at <= clock,
            )
        )
    ).all()
    expired_jobs = 0
    expired_requests = 0
    for job in overdue:
        job.status = JobStatus.EXPIRED.value
        expired_jobs += 1
        request = await db.get(SoftwareRequest, job.request_id)
        if request is not None and request.status in {
            RequestStatus.QUEUED.value,
            RequestStatus.DISPATCHED.value,
            RequestStatus.RUNNING.value,
            RequestStatus.READY_TO_INSTALL.value,
            RequestStatus.AWAITING_APPROVAL.value,
        }:
            request.status = RequestStatus.EXPIRED.value
            request.version += 1
            expired_requests += 1
    await db.flush()
    return {"installation_jobs_expired": expired_jobs, "requests_expired": expired_requests}


def summarize(counts: dict[str, Any]) -> str:
    return ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
