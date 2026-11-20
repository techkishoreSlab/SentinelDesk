"""Admin operations: metrics and retention (Phase 9)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import Principal, require, require_any
from app.auth.rbac import Permission
from app.db.session import get_session
from app.ops import metrics as metrics_svc
from app.ops import retention as retention_svc

router = APIRouter(prefix="/api/v1/admin/ops", tags=["admin"])

_metrics_principal = require_any(Permission.INTEGRATION_READ, Permission.AUDIT_READ)
_purge_principal = require(Permission.DEVICE_MANAGE)


class MetricsOut(BaseModel):
    generated_at: str
    requests_by_status: dict[str, int]
    jobs_by_status: dict[str, int]
    approvals_awaiting: int
    job_queue_depth: int
    job_queue_oldest_age_seconds: int | None
    devices_total: int
    devices_stale_15m: int
    notification_delivery_issues: int
    install_outcomes: dict[str, int]


class PurgeResult(BaseModel):
    purged: dict[str, int] = Field(description="Row counts deleted or expired by category")


@router.get("/metrics", response_model=MetricsOut)
async def get_metrics(
    _: Principal = Depends(_metrics_principal),  # noqa: B008
    db: AsyncSession = Depends(get_session),  # noqa: B008
) -> MetricsOut:
    payload: dict[str, Any] = await metrics_svc.collect_metrics(db)
    return MetricsOut.model_validate(payload)


@router.post("/purge-expired", response_model=PurgeResult)
async def purge_expired(
    _: Principal = Depends(_purge_principal),  # noqa: B008
    db: AsyncSession = Depends(get_session),  # noqa: B008
) -> PurgeResult:
    """Purge expired sessions/OIDC/throttle/tokens and expire abandoned jobs."""
    counts = await retention_svc.purge_expired(db)
    return PurgeResult(purged=counts)
