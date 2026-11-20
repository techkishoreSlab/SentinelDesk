"""Admin approval queue and decisions (spec §10.3, §12.2)."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import Principal, require
from app.auth.rbac import Permission
from app.core.config import Settings
from app.db.session import get_session
from app.requests import service as requests_service
from app.requests.schemas import ApprovalDecisionIn, ApprovalDecisionOut, ApprovalQueueItem

router = APIRouter(prefix="/api/v1/admin/approvals", tags=["admin-approvals"])


def get_settings_from(request: Request) -> Settings:
    settings: Settings = request.app.state.settings
    return settings


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


@router.get("", response_model=list[ApprovalQueueItem])
async def pending_approvals(
    _: Principal = Depends(require(Permission.APPROVAL_READ)),  # noqa: B008
    db: AsyncSession = Depends(get_session),  # noqa: B008
) -> list[ApprovalQueueItem]:
    items = await requests_service.list_pending_approvals(db)
    return [ApprovalQueueItem.model_validate(i) for i in items]


@router.post("/{request_id}/decision", response_model=ApprovalDecisionOut)
async def decide(
    request_id: uuid.UUID,
    body: ApprovalDecisionIn,
    request: Request,
    principal: Principal = Depends(require(Permission.APPROVAL_DECIDE)),  # noqa: B008
    db: AsyncSession = Depends(get_session),  # noqa: B008
) -> ApprovalDecisionOut:
    payload = await requests_service.decide_approval(
        db,
        get_settings_from(request),
        request_id=request_id,
        approver_id=principal.user_id,
        decision=body.decision,
        comment=body.comment,
        expected_version=body.expected_version,
        actor_ip=_client_ip(request),
    )
    await db.commit()
    return ApprovalDecisionOut.model_validate(payload)
