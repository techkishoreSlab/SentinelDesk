"""Enrollment tokens and device administration (spec §11.1, §9.10). All mutations audited."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Literal

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from app.audit import service as audit
from app.auth.dependencies import (
    Principal,
    client_ip,
    get_settings_from,
    load_role_names,
    require,
    require_any,
)
from app.auth.rbac import Permission
from app.auth.tokens import hash_token
from app.core.errors import AppError
from app.db.enums import ActorType, AuditResult, DeviceStatus, RoleName
from app.db.session import get_session
from app.devices.credentials import new_enrollment_secret, revoke_device_credentials
from app.devices.models import Device, EnrollmentToken
from app.users.models import User

router = APIRouter(prefix="/api/v1/admin", tags=["admin"])

# Security admins can see and quarantine devices for incident response (spec §9.10).
_device_admin = require_any(Permission.DEVICE_MANAGE, Permission.SECURITY_MANAGE)

TokenStatus = Literal["PENDING", "USED", "EXPIRED", "REVOKED"]


class CreateEnrollmentToken(BaseModel):
    model_config = ConfigDict(extra="forbid")
    owner_user_id: uuid.UUID
    ttl_minutes: int | None = Field(default=None, ge=1, le=60)


class EnrollmentTokenCreated(BaseModel):
    id: uuid.UUID
    token: str
    owner_user_id: uuid.UUID
    owner_email: str
    expires_at: datetime


class EnrollmentTokenOut(BaseModel):
    id: uuid.UUID
    owner_email: str
    created_by_email: str
    created_at: datetime
    expires_at: datetime
    status: TokenStatus
    used_by_device_id: uuid.UUID | None


class AdminDeviceOut(BaseModel):
    id: uuid.UUID
    owner_email: str
    device_name: str
    os_family: str
    os_version: str
    architecture: str
    agent_version: str
    device_status: str
    enrolled_at: datetime | None
    last_seen_at: datetime | None


class QuarantineRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: Literal[
        "SUSPECTED_COMPROMISE", "CREDENTIAL_THEFT", "SIGNATURE_MISMATCH", "LOST_DEVICE", "OTHER"
    ]


def _token_status(t: EnrollmentToken, now: datetime) -> TokenStatus:
    if t.revoked_at:
        return "REVOKED"
    if t.used_at:
        return "USED"
    if t.expires_at <= now:
        return "EXPIRED"
    return "PENDING"


@router.post("/enrollment-tokens", response_model=EnrollmentTokenCreated, status_code=201)
async def create_enrollment_token(
    body: CreateEnrollmentToken,
    request: Request,
    principal: Principal = Depends(require(Permission.ENROLLMENT_MANAGE)),  # noqa: B008
    db: AsyncSession = Depends(get_session),  # noqa: B008
) -> EnrollmentTokenCreated:
    settings = get_settings_from(request)
    owner = await db.get(User, body.owner_user_id)
    if owner is None:
        raise AppError("NOT_FOUND", 404)
    if not owner.is_active or RoleName.EMPLOYEE.value not in await load_role_names(db, owner.id):
        raise AppError("OWNER_NOT_ELIGIBLE", 409)
    ttl = min(body.ttl_minutes or settings.device_enrollment_ttl_minutes, 60)
    secret = new_enrollment_secret()
    row = EnrollmentToken(
        token_hash=hash_token(secret),
        owner_user_id=owner.id,
        created_by=principal.user_id,
        expires_at=datetime.now(UTC) + timedelta(minutes=ttl),
    )
    db.add(row)
    await db.flush()
    await audit.record(
        db,
        action="ENROLLMENT_TOKEN_CREATED",
        resource_type="enrollment_token",
        resource_id=row.id,
        result=AuditResult.SUCCESS,
        actor_type=ActorType.USER,
        actor_id=principal.user_id,
        source_ip=client_ip(request),
        metadata={"owner_user_id": str(owner.id), "ttl_minutes": ttl},
    )
    await db.commit()
    return EnrollmentTokenCreated(
        id=row.id,
        token=secret,
        owner_user_id=owner.id,
        owner_email=owner.email,
        expires_at=row.expires_at,
    )


@router.get("/enrollment-tokens", response_model=list[EnrollmentTokenOut])
async def list_enrollment_tokens(
    _: Principal = Depends(require(Permission.ENROLLMENT_MANAGE)),  # noqa: B008
    db: AsyncSession = Depends(get_session),  # noqa: B008
    limit: int = Query(default=50, ge=1, le=100),
) -> list[EnrollmentTokenOut]:
    owner, creator = aliased(User), aliased(User)
    rows = (
        await db.execute(
            select(EnrollmentToken, owner.email, creator.email)
            .join(owner, owner.id == EnrollmentToken.owner_user_id)
            .join(creator, creator.id == EnrollmentToken.created_by)
            .order_by(EnrollmentToken.created_at.desc())
            .limit(limit)
        )
    ).all()
    now = datetime.now(UTC)
    return [
        EnrollmentTokenOut(
            id=t.id,
            owner_email=owner_email,
            created_by_email=creator_email,
            created_at=t.created_at,
            expires_at=t.expires_at,
            status=_token_status(t, now),
            used_by_device_id=t.used_by_device_id,
        )
        for t, owner_email, creator_email in rows
    ]


@router.post("/enrollment-tokens/{token_id}/revoke", status_code=204)
async def revoke_enrollment_token(
    token_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(require(Permission.ENROLLMENT_MANAGE)),  # noqa: B008
    db: AsyncSession = Depends(get_session),  # noqa: B008
) -> None:
    token = await db.scalar(
        select(EnrollmentToken).where(EnrollmentToken.id == token_id).with_for_update()
    )
    if token is None:
        raise AppError("NOT_FOUND", 404)
    if token.revoked_at is None and token.used_at is None:
        token.revoked_at = datetime.now(UTC)
        await audit.record(
            db,
            action="ENROLLMENT_TOKEN_REVOKED",
            resource_type="enrollment_token",
            resource_id=token.id,
            result=AuditResult.SUCCESS,
            actor_type=ActorType.USER,
            actor_id=principal.user_id,
            source_ip=client_ip(request),
        )
    await db.commit()


@router.get("/devices", response_model=list[AdminDeviceOut])
async def list_devices(
    _: Principal = Depends(_device_admin),  # noqa: B008
    db: AsyncSession = Depends(get_session),  # noqa: B008
    status: DeviceStatus | None = None,
    limit: int = Query(default=100, ge=1, le=200),
) -> list[AdminDeviceOut]:
    stmt = (
        select(Device, User.email)
        .join(User, User.id == Device.owner_user_id)
        .order_by(Device.last_seen_at.desc().nulls_last())
        .limit(limit)
    )
    if status is not None:
        stmt = stmt.where(Device.device_status == status.value)
    rows = (await db.execute(stmt)).all()
    return [
        AdminDeviceOut(
            id=d.id,
            owner_email=email,
            device_name=d.device_name,
            os_family=d.os_family,
            os_version=d.os_version,
            architecture=d.architecture,
            agent_version=d.agent_version,
            device_status=d.device_status,
            enrolled_at=d.enrolled_at,
            last_seen_at=d.last_seen_at,
        )
        for d, email in rows
    ]


@router.post("/devices/{device_id}/quarantine", status_code=204)
async def quarantine_device(
    device_id: uuid.UUID,
    body: QuarantineRequest,
    request: Request,
    principal: Principal = Depends(_device_admin),  # noqa: B008
    db: AsyncSession = Depends(get_session),  # noqa: B008
) -> None:
    """Spec §9.10: revoke credentials and mark QUARANTINED. Re-enrollment creates a new device."""
    device = await db.scalar(select(Device).where(Device.id == device_id).with_for_update())
    if device is None:
        raise AppError("NOT_FOUND", 404)
    previous = device.device_status
    device.device_status = DeviceStatus.QUARANTINED.value
    revoked = await revoke_device_credentials(db, device.id)
    await audit.record(
        db,
        action="DEVICE_QUARANTINED",
        resource_type="device",
        resource_id=device.id,
        result=AuditResult.SUCCESS,
        actor_type=ActorType.USER,
        actor_id=principal.user_id,
        reason_code=body.reason,
        source_ip=client_ip(request),
        metadata={"previous_status": previous, "revoked_count": revoked},
    )
    await db.commit()
