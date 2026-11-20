"""Lightweight operational metrics (spec §15.2) — no external monitoring stack."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.enums import JobStatus, NotificationStatus, RequestStatus
from app.devices.models import Device
from app.requests.models import InstallationJob, Notification, SoftwareRequest


async def collect_metrics(db: AsyncSession) -> dict[str, Any]:
    now = datetime.now(UTC)
    stale_after = now - timedelta(minutes=15)

    async def count(model: type[Any], *where: Any) -> int:
        stmt = select(func.count()).select_from(model)
        for clause in where:
            stmt = stmt.where(clause)
        return int(await db.scalar(stmt) or 0)

    request_by_status: dict[str, int] = {}
    for req_status in RequestStatus:
        request_by_status[req_status.value] = await count(
            SoftwareRequest, SoftwareRequest.status == req_status.value
        )

    job_by_status: dict[str, int] = {}
    for job_status in JobStatus:
        job_by_status[job_status.value] = await count(
            InstallationJob, InstallationJob.status == job_status.value
        )

    awaiting = request_by_status.get(RequestStatus.AWAITING_APPROVAL.value, 0)
    queued_jobs = job_by_status.get(JobStatus.QUEUED.value, 0)
    oldest_queued = await db.scalar(
        select(func.min(InstallationJob.issued_at)).where(
            InstallationJob.status == JobStatus.QUEUED.value
        )
    )
    queue_age_seconds = (
        int((now - oldest_queued).total_seconds()) if oldest_queued is not None else None
    )

    devices_total = await count(Device)
    devices_stale = await count(
        Device,
        and_(Device.last_seen_at.is_not(None), Device.last_seen_at < stale_after),
    )

    notif_failed = await count(
        Notification,
        Notification.status.in_(
            [
                NotificationStatus.FAILED.value,
                NotificationStatus.NOT_CONFIGURED.value,
            ]
        ),
    )

    return {
        "generated_at": now.isoformat(),
        "requests_by_status": request_by_status,
        "jobs_by_status": job_by_status,
        "approvals_awaiting": awaiting,
        "job_queue_depth": queued_jobs,
        "job_queue_oldest_age_seconds": queue_age_seconds,
        "devices_total": devices_total,
        "devices_stale_15m": devices_stale,
        "notification_delivery_issues": notif_failed,
        "install_outcomes": {
            "succeeded": job_by_status.get(JobStatus.SUCCEEDED.value, 0),
            "failed": job_by_status.get(JobStatus.FAILED.value, 0),
            "failed_verification": job_by_status.get(JobStatus.FAILED_VERIFICATION.value, 0),
        },
    }
