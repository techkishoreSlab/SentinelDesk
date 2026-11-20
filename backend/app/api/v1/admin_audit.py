"""Read-only audit search and chain verification (AUDITOR, SECURITY_ADMIN)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import service as audit
from app.audit.models import AuditEvent
from app.auth.dependencies import Principal, require
from app.auth.rbac import Permission
from app.db.session import get_session

router = APIRouter(prefix="/api/v1/admin/audit", tags=["admin"])


class AuditEventOut(BaseModel):
    id: uuid.UUID
    seq: int
    occurred_at: datetime
    actor_type: str
    actor_id: uuid.UUID | None
    action: str
    resource_type: str
    resource_id: str | None
    correlation_id: str | None
    result: str
    reason_code: str | None
    metadata: dict[str, Any]
    event_hash: str


class AuditPage(BaseModel):
    items: list[AuditEventOut]
    next_before_seq: int | None


class ChainStatus(BaseModel):
    valid: bool
    events_checked: int
    first_invalid_seq: int | None


@router.get("", response_model=AuditPage)
async def search_audit(
    _: Principal = Depends(require(Permission.AUDIT_READ)),  # noqa: B008
    db: AsyncSession = Depends(get_session),  # noqa: B008
    actor_id: uuid.UUID | None = None,
    action: str | None = Query(default=None, max_length=60),
    resource_type: str | None = Query(default=None, max_length=40),
    resource_id: str | None = Query(default=None, max_length=64),
    correlation_id: str | None = Query(default=None, max_length=64),
    result: str | None = Query(default=None, max_length=16),
    occurred_from: datetime | None = None,
    occurred_to: datetime | None = None,
    before_seq: int | None = Query(default=None, ge=1),
    limit: int = Query(default=50, ge=1, le=100),
) -> AuditPage:
    stmt = select(AuditEvent).order_by(AuditEvent.seq.desc()).limit(limit)
    filters = {
        AuditEvent.actor_id: actor_id,
        AuditEvent.action: action,
        AuditEvent.resource_type: resource_type,
        AuditEvent.resource_id: resource_id,
        AuditEvent.correlation_id: correlation_id,
        AuditEvent.result: result,
    }
    for column, value in filters.items():
        if value is not None:
            stmt = stmt.where(column == value)
    if occurred_from:
        stmt = stmt.where(AuditEvent.occurred_at >= occurred_from)
    if occurred_to:
        stmt = stmt.where(AuditEvent.occurred_at <= occurred_to)
    if before_seq:
        stmt = stmt.where(AuditEvent.seq < before_seq)
    rows = (await db.scalars(stmt)).all()
    items = [
        AuditEventOut(
            id=e.id,
            seq=e.seq,
            occurred_at=e.occurred_at,
            actor_type=e.actor_type,
            actor_id=e.actor_id,
            action=e.action,
            resource_type=e.resource_type,
            resource_id=e.resource_id,
            correlation_id=e.correlation_id,
            result=e.result,
            reason_code=e.reason_code,
            metadata=e.metadata_,
            event_hash=e.event_hash,
        )
        for e in rows
    ]
    next_cursor = rows[-1].seq if len(rows) == limit else None
    return AuditPage(items=items, next_before_seq=next_cursor)


@router.get("/verify", response_model=ChainStatus)
async def verify_audit_chain(
    _: Principal = Depends(require(Permission.AUDIT_READ)),  # noqa: B008
    db: AsyncSession = Depends(get_session),  # noqa: B008
) -> ChainStatus:
    result = await audit.verify_chain(db)
    return ChainStatus(
        valid=result.valid,
        events_checked=result.events_checked,
        first_invalid_seq=result.first_invalid_seq,
    )
