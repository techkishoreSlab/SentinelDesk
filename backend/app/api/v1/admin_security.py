"""Security-admin banned rules and software policies (spec section 12.2)."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import service as audit
from app.auth.dependencies import Principal, client_ip, require
from app.auth.rbac import Permission
from app.catalogue import service as catalogue
from app.catalogue.models import BannedSoftware, SoftwarePolicy
from app.core.errors import AppError
from app.db.enums import ActorType, AuditResult, PolicyDecision
from app.db.session import get_session
from app.security.schemas import (
    BannedOut,
    CreateBanned,
    CreatePolicy,
    PolicyOut,
    ThreatStatusOut,
)
from app.security.threat import CompositeThreatIntel

router = APIRouter(prefix="/api/v1/admin/security", tags=["admin-security"])
_read = require(Permission.SECURITY_READ)
_manage = require(Permission.SECURITY_MANAGE)


@router.get("/threat-status", response_model=ThreatStatusOut)
async def threat_status(
    request: Request,
    _: Principal = Depends(_read),  # noqa: B008
) -> ThreatStatusOut:
    settings = request.app.state.settings
    threat = CompositeThreatIntel(settings, request.app.state.http_client)
    return ThreatStatusOut(
        mandatory=threat.mandatory,
        external_configured=threat.external_configured,
        provider=settings.threat_intel_provider,
    )


@router.get("/banned", response_model=list[BannedOut])
async def list_banned(
    _: Principal = Depends(_read),  # noqa: B008
    db: AsyncSession = Depends(get_session),  # noqa: B008
    active_only: bool = Query(default=True),
    limit: int = Query(default=100, ge=1, le=200),
) -> list[BannedOut]:
    stmt = select(BannedSoftware).order_by(BannedSoftware.created_at.desc()).limit(limit)
    if active_only:
        stmt = stmt.where(BannedSoftware.active.is_(True))
    rows = (await db.scalars(stmt)).all()
    return [
        BannedOut(
            id=r.id,
            match_type=r.match_type,
            match_value=r.match_value,
            reason_code=r.reason_code,
            public_message=r.public_message,
            severity=r.severity,
            active=r.active,
            created_at=r.created_at,
            notes=r.notes,
        )
        for r in rows
    ]


@router.post("/banned", response_model=BannedOut, status_code=201)
async def create_banned(
    body: CreateBanned,
    request: Request,
    principal: Principal = Depends(_manage),  # noqa: B008
    db: AsyncSession = Depends(get_session),  # noqa: B008
) -> BannedOut:
    existing = await db.scalar(
        select(BannedSoftware).where(
            BannedSoftware.match_type == body.match_type.value,
            BannedSoftware.match_value == body.match_value,
        )
    )
    if existing is not None:
        if not existing.active:
            existing.active = True
            existing.reason_code = body.reason_code
            existing.public_message = body.public_message
            existing.severity = body.severity.value
            existing.notes = body.notes
            row = existing
        else:
            raise AppError("CONFLICT", 409, {"field": "match_value"})
    else:
        row = BannedSoftware(
            match_type=body.match_type.value,
            match_value=body.match_value,
            reason_code=body.reason_code,
            public_message=body.public_message,
            severity=body.severity.value,
            active=True,
            created_by=principal.user_id,
            notes=body.notes,
        )
        db.add(row)
        await db.flush()
    await audit.record(
        db,
        action="BANNED_SOFTWARE_UPSERT",
        resource_type="banned_software",
        resource_id=row.id,
        result=AuditResult.SUCCESS,
        actor_type=ActorType.USER,
        actor_id=principal.user_id,
        source_ip=client_ip(request),
        metadata={"match_type": row.match_type, "reason_code": row.reason_code},
    )
    await db.commit()
    return BannedOut(
        id=row.id,
        match_type=row.match_type,
        match_value=row.match_value,
        reason_code=row.reason_code,
        public_message=row.public_message,
        severity=row.severity,
        active=row.active,
        created_at=row.created_at,
        notes=row.notes,
    )


@router.post("/banned/{rule_id}/deactivate", status_code=204)
async def deactivate_banned(
    rule_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(_manage),  # noqa: B008
    db: AsyncSession = Depends(get_session),  # noqa: B008
) -> None:
    row = await db.get(BannedSoftware, rule_id)
    if row is None:
        raise AppError("NOT_FOUND", 404)
    if row.active:
        row.active = False
        await audit.record(
            db,
            action="BANNED_SOFTWARE_DEACTIVATED",
            resource_type="banned_software",
            resource_id=row.id,
            result=AuditResult.SUCCESS,
            actor_type=ActorType.USER,
            actor_id=principal.user_id,
            source_ip=client_ip(request),
        )
        await db.commit()


@router.get("/policies", response_model=list[PolicyOut])
async def list_policies(
    _: Principal = Depends(_read),  # noqa: B008
    db: AsyncSession = Depends(get_session),  # noqa: B008
    software_id: uuid.UUID | None = None,
    limit: int = Query(default=100, ge=1, le=200),
) -> list[PolicyOut]:
    stmt = select(SoftwarePolicy).order_by(SoftwarePolicy.effective_from.desc()).limit(limit)
    if software_id is not None:
        stmt = stmt.where(SoftwarePolicy.software_id == software_id)
    rows = (await db.scalars(stmt)).all()
    return [
        PolicyOut(
            id=r.id,
            software_id=r.software_id,
            decision=r.decision,
            auto_approve_eligible=r.auto_approve_eligible,
            policy_revision=r.policy_revision,
            reason=r.reason,
            effective_from=r.effective_from,
            effective_to=r.effective_to,
        )
        for r in rows
    ]


@router.post("/policies", response_model=PolicyOut, status_code=201)
async def create_policy(
    body: CreatePolicy,
    request: Request,
    principal: Principal = Depends(_manage),  # noqa: B008
    db: AsyncSession = Depends(get_session),  # noqa: B008
) -> PolicyOut:
    await catalogue.get_software(db, body.software_id)
    latest = await db.scalar(
        select(SoftwarePolicy.policy_revision)
        .where(SoftwarePolicy.software_id == body.software_id)
        .order_by(SoftwarePolicy.policy_revision.desc())
        .limit(1)
    )
    revision = (latest or 0) + 1
    # Close the previous open policy for this software.
    open_rows = (
        await db.scalars(
            select(SoftwarePolicy).where(
                SoftwarePolicy.software_id == body.software_id,
                SoftwarePolicy.effective_to.is_(None),
            )
        )
    ).all()
    from datetime import UTC, datetime

    now = datetime.now(UTC)
    for row in open_rows:
        row.effective_to = now
    if body.auto_approve_eligible and body.decision != PolicyDecision.ALLOW:
        raise AppError("VALIDATION_ERROR", 422, {"field": "auto_approve_eligible"})
    row = SoftwarePolicy(
        software_id=body.software_id,
        decision=body.decision.value,
        auto_approve_eligible=body.auto_approve_eligible,
        policy_revision=revision,
        reason=body.reason.strip(),
        effective_to=body.effective_to,
        created_by=principal.user_id,
    )
    db.add(row)
    await db.flush()
    await audit.record(
        db,
        action="SOFTWARE_POLICY_CREATED",
        resource_type="software_policy",
        resource_id=row.id,
        result=AuditResult.SUCCESS,
        actor_type=ActorType.USER,
        actor_id=principal.user_id,
        source_ip=client_ip(request),
        metadata={
            "software_id": str(body.software_id),
            "decision": row.decision,
            "policy_revision": revision,
            "auto_approve": row.auto_approve_eligible,
        },
    )
    await db.commit()
    return PolicyOut(
        id=row.id,
        software_id=row.software_id,
        decision=row.decision,
        auto_approve_eligible=row.auto_approve_eligible,
        policy_revision=row.policy_revision,
        reason=row.reason,
        effective_from=row.effective_from,
        effective_to=row.effective_to,
    )
