"""Endpoint-agent API (spec §11.1, §12.3). Device-authenticated; no employee cookies."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import service as audit
from app.auth import throttle
from app.auth.dependencies import client_ip, get_settings_from
from app.auth.tokens import hash_token
from app.core.errors import AppError
from app.db.enums import ActorType, AuditResult, DeviceStatus
from app.db.session import get_session
from app.devices.auth import DeviceContext, get_device
from app.devices.credentials import (
    ENROLLMENT_PREFIX,
    ROTATE_WITHIN,
    issue_credential,
    well_formed,
)
from app.devices.models import Device, DeviceCredential, DeviceFacts, EnrollmentToken
from app.devices.schemas import (
    DeviceFactsIn,
    EnrollRequest,
    EnrollResponse,
    HeartbeatRequest,
    HeartbeatResponse,
    RotateResponse,
)
from app.jobs import service as jobs
from app.jobs.schemas import JobEnvelopeOut, JobResultIn, JobResultOut, JobStartedIn
from app.users.models import User

router = APIRouter(prefix="/api/v1/agent", tags=["agent"])

ENROLL_IP_MAX_FAILURES = 10
MIN_HEARTBEAT_GAP = timedelta(seconds=5)
FACTS_SNAPSHOT_INTERVAL = timedelta(hours=1)
ROTATION_GRACE = timedelta(minutes=10)


def _summary(facts: DeviceFactsIn) -> dict[str, Any]:
    return {
        "count": len(facts.installed_software),
        "items": [s.model_dump() for s in facts.installed_software],
    }


def _snapshot(device: Device, facts: DeviceFactsIn) -> DeviceFacts:
    return DeviceFacts(
        device_id=device.id,
        cpu_arch=facts.architecture,
        cpu_cores=facts.cpu_cores,
        memory_total_bytes=facts.memory_total_bytes,
        disk_free_bytes=facts.disk_free_bytes,
        os_build=facts.os_build,
        installed_software_summary=_summary(facts),
    )


@router.post("/enroll", response_model=EnrollResponse, status_code=201)
async def enroll(
    body: EnrollRequest,
    request: Request,
    db: AsyncSession = Depends(get_session),  # noqa: B008
) -> EnrollResponse:
    settings = get_settings_from(request)
    ip = client_ip(request)
    ip_key = f"enroll-{throttle.ip_key(ip)}"
    if await throttle.is_locked(db, [ip_key]):
        raise AppError("RATE_LIMITED", 429)

    now = datetime.now(UTC)
    consumed = None
    if well_formed(body.enrollment_token, ENROLLMENT_PREFIX):
        consumed = (
            await db.execute(
                update(EnrollmentToken)
                .where(
                    EnrollmentToken.token_hash == hash_token(body.enrollment_token),
                    EnrollmentToken.used_at.is_(None),
                    EnrollmentToken.revoked_at.is_(None),
                    EnrollmentToken.expires_at > now,
                )
                .values(used_at=now)
                .returning(EnrollmentToken.id, EnrollmentToken.owner_user_id)
            )
        ).first()
    owner = await db.get(User, consumed.owner_user_id) if consumed else None
    if consumed is None or owner is None or not owner.is_active:
        await throttle.record_failure(db, settings, ip_key, ENROLL_IP_MAX_FAILURES)
        await audit.record(
            db,
            action="DEVICE_ENROLL_FAILED",
            resource_type="enrollment_token",
            resource_id=consumed.id if consumed else None,
            result=AuditResult.DENIED,
            actor_type=ActorType.ANONYMOUS,
            reason_code="OWNER_INACTIVE" if consumed else "TOKEN_INVALID",
            source_ip=ip,
        )
        await db.commit()
        raise AppError("ENROLLMENT_TOKEN_INVALID", 401)

    facts = body.facts
    device = Device(
        owner_user_id=owner.id,
        device_name=facts.device_name,
        os_family=facts.os_family.value,
        os_version=facts.os_version,
        architecture=facts.architecture,
        agent_version=body.agent_version,
        device_status=DeviceStatus.ACTIVE.value,
        enrolled_at=now,
        last_seen_at=now,
    )
    db.add(device)
    await db.flush()
    await db.execute(
        update(EnrollmentToken)
        .where(EnrollmentToken.id == consumed.id)
        .values(used_by_device_id=device.id)
    )
    db.add(_snapshot(device, facts))
    issued = await issue_credential(db, settings, device.id)
    await audit.record(
        db,
        action="DEVICE_ENROLLED",
        resource_type="device",
        resource_id=device.id,
        result=AuditResult.SUCCESS,
        actor_type=ActorType.DEVICE,
        actor_id=device.id,
        source_ip=ip,
        metadata={
            "owner_user_id": str(owner.id),
            "enrollment_id": str(consumed.id),
            "os_family": device.os_family,
            "architecture": device.architecture,
            "agent_version": device.agent_version,
        },
    )
    await db.commit()
    return EnrollResponse(
        device_id=device.id,
        device_credential=issued.secret,
        credential_expires_at=issued.credential.expires_at,
        heartbeat_interval_seconds=settings.heartbeat_interval_seconds,
    )


@router.post("/heartbeat", response_model=HeartbeatResponse)
async def heartbeat(
    body: HeartbeatRequest,
    request: Request,
    ctx: DeviceContext = Depends(get_device),  # noqa: B008
    db: AsyncSession = Depends(get_session),  # noqa: B008
) -> HeartbeatResponse:
    settings = get_settings_from(request)
    device, facts = ctx.device, body.facts
    now = datetime.now(UTC)
    if device.last_seen_at and now - device.last_seen_at < MIN_HEARTBEAT_GAP:
        raise AppError("RATE_LIMITED", 429)

    # OS family and CPU architecture are fixed at enrollment; a change means a different
    # machine is presenting this credential.
    if facts.os_family.value != device.os_family or facts.architecture != device.architecture:
        await audit.record(
            db,
            action="DEVICE_IDENTITY_MISMATCH",
            resource_type="device",
            resource_id=device.id,
            result=AuditResult.DENIED,
            actor_type=ActorType.DEVICE,
            actor_id=device.id,
            reason_code="PLATFORM_CHANGED",
            source_ip=client_ip(request),
            metadata={"os_family": facts.os_family.value, "architecture": facts.architecture},
        )
        await db.commit()
        raise AppError("DEVICE_NOT_ACTIVE", 403)

    device.last_seen_at = now
    device.device_name = facts.device_name
    device.os_version = facts.os_version
    device.agent_version = body.agent_version

    latest = await db.scalar(
        select(DeviceFacts)
        .where(DeviceFacts.device_id == device.id)
        .order_by(DeviceFacts.collected_at.desc())
        .limit(1)
    )
    candidate = _snapshot(device, facts)
    changed = latest is None or any(
        getattr(latest, f) != getattr(candidate, f)
        for f in (
            "cpu_arch",
            "cpu_cores",
            "memory_total_bytes",
            "os_build",
            "installed_software_summary",
        )
    )
    if changed or now - latest.collected_at >= FACTS_SNAPSHOT_INTERVAL:  # type: ignore[union-attr]
        db.add(candidate)
    await db.commit()
    return HeartbeatResponse(
        device_id=device.id,
        device_status=device.device_status,
        next_heartbeat_seconds=settings.heartbeat_interval_seconds,
        credential_expires_at=ctx.credential.expires_at,
        rotate_credential=ctx.credential.expires_at - now <= ROTATE_WITHIN,
    )


@router.get("/jobs/next", response_model=None)
async def next_job(
    request: Request,
    ctx: DeviceContext = Depends(get_device),  # noqa: B008
    db: AsyncSession = Depends(get_session),  # noqa: B008
) -> Response | JobEnvelopeOut:
    settings = get_settings_from(request)
    claimed = await jobs.claim_next_job(db, settings, device=ctx.device)
    await db.commit()
    if claimed is None:
        return Response(status_code=204)
    return JobEnvelopeOut.model_validate(claimed)


@router.post("/jobs/{job_id}/started", status_code=204)
async def job_started(
    job_id: uuid.UUID,
    _body: JobStartedIn,
    ctx: DeviceContext = Depends(get_device),  # noqa: B008
    db: AsyncSession = Depends(get_session),  # noqa: B008
) -> Response:
    await jobs.mark_started(db, device_id=ctx.device.id, job_id=job_id)
    await db.commit()
    return Response(status_code=204)


@router.post("/jobs/{job_id}/result", response_model=JobResultOut)
async def job_result(
    job_id: uuid.UUID,
    body: JobResultIn,
    ctx: DeviceContext = Depends(get_device),  # noqa: B008
    db: AsyncSession = Depends(get_session),  # noqa: B008
) -> JobResultOut:
    payload = await jobs.submit_result(
        db,
        device_id=ctx.device.id,
        job_id=job_id,
        result_code=body.result_code,
        result_summary=body.result_summary,
        exit_code=body.exit_code,
        installed_version=body.installed_version,
        verification_status=body.verification_status,
        result_details=body.details,
    )
    await db.commit()
    return JobResultOut.model_validate(payload)


@router.post("/credential/rotate", response_model=RotateResponse)
async def rotate_credential(
    request: Request,
    ctx: DeviceContext = Depends(get_device),  # noqa: B008
    db: AsyncSession = Depends(get_session),  # noqa: B008
) -> RotateResponse:
    settings = get_settings_from(request)
    now = datetime.now(UTC)
    issued = await issue_credential(db, settings, ctx.device.id)
    # The old credential stays usable briefly in case the response is lost in transit; the
    # first use of the new credential revokes it (see devices.auth).
    await db.execute(
        update(DeviceCredential)
        .where(DeviceCredential.id == ctx.credential.id)
        .values(expires_at=min(ctx.credential.expires_at, now + ROTATION_GRACE))
    )
    await audit.record(
        db,
        action="DEVICE_CREDENTIAL_ROTATED",
        resource_type="device",
        resource_id=ctx.device.id,
        result=AuditResult.SUCCESS,
        actor_type=ActorType.DEVICE,
        actor_id=ctx.device.id,
        source_ip=client_ip(request),
    )
    await db.commit()
    return RotateResponse(
        device_credential=issued.secret, credential_expires_at=issued.credential.expires_at
    )
