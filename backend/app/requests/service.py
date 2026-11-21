"""Software request persistence and approval decisions (spec §6, §10)."""

from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import service as audit
from app.catalogue import service as catalogue
from app.catalogue.models import CatalogueSoftware, CatalogueVersion
from app.core.config import Settings
from app.core.errors import AppError
from app.db.enums import (
    ActorType,
    ApprovalChannel,
    ApprovalDecision,
    AuditResult,
    JobStatus,
    RequestStatus,
)
from app.devices.models import Device
from app.notifications.outlook import enqueue_approval_notifications
from app.orchestration.orchestrator import run_preview
from app.requests.binding import approval_binding_hash
from app.requests.models import Approval, InstallationJob, SecurityCheck, SoftwareRequest
from app.requests.transitions import CANCELABLE, TERMINAL, status_for_outcome
from app.security.threat import CompositeThreatIntel
from app.users.models import User


def _expires_at(settings: Settings) -> datetime:
    # Reuse job TTL as the approval/request validity window for Phase 7.
    minutes = max(settings.job_ttl_minutes, 60)
    return datetime.now(UTC) + timedelta(minutes=minutes)


async def _software_labels(
    db: AsyncSession, software_id: uuid.UUID | None, version_id: uuid.UUID | None
) -> tuple[str | None, str | None, str | None, str | None]:
    slug = name = version = sha_prefix = None
    if software_id is not None:
        software = await db.get(CatalogueSoftware, software_id)
        if software is not None:
            slug, name = software.slug, software.display_name
    if version_id is not None:
        ver = await db.get(CatalogueVersion, version_id)
        if ver is not None:
            version = ver.version
            if ver.sha256:
                sha_prefix = ver.sha256[:12]
    return slug, name, version, sha_prefix


def serialize_request(
    row: SoftwareRequest,
    *,
    software_slug: str | None = None,
    software_name: str | None = None,
    version: str | None = None,
    explanation: str | None = None,
    replayed: bool = False,
    progress_phase: str | None = None,
    progress_bytes_done: int | None = None,
    progress_bytes_total: int | None = None,
    progress_updated_at: datetime | None = None,
    job_claimed_at: datetime | None = None,
) -> dict[str, Any]:
    return {
        "id": row.id,
        "status": row.status,
        "decision_reason": row.decision_reason,
        "raw_request": row.raw_request,
        "device_id": row.device_id,
        "software_id": row.software_id,
        "catalogue_version_id": row.catalogue_version_id,
        "software_slug": software_slug,
        "software_name": software_name,
        "version": version,
        "explanation": explanation,
        "policy_revision": row.policy_revision,
        "idempotency_key": row.idempotency_key,
        "request_version": row.version,
        "created_at": row.created_at,
        "updated_at": row.updated_at,
        "expires_at": row.expires_at,
        "replayed": replayed,
        "progress_phase": progress_phase,
        "progress_bytes_done": progress_bytes_done,
        "progress_bytes_total": progress_bytes_total,
        "progress_updated_at": progress_updated_at,
        "job_claimed_at": job_claimed_at,
    }


async def _job_progress(
    db: AsyncSession, request_id: uuid.UUID
) -> tuple[str | None, int | None, int | None, datetime | None, datetime | None]:
    job = await db.scalar(
        select(InstallationJob)
        .where(InstallationJob.request_id == request_id)
        .order_by(InstallationJob.issued_at.desc())
        .limit(1)
    )
    if job is None:
        return None, None, None, None, None
    return (
        job.progress_phase,
        job.progress_bytes_done,
        job.progress_bytes_total,
        job.progress_updated_at,
        job.claimed_at,
    )


async def create_request(
    db: AsyncSession,
    settings: Settings,
    threat: CompositeThreatIntel,
    *,
    requester_id: uuid.UUID,
    device_id: uuid.UUID,
    user_prompt: str,
    idempotency_key: str,
    http_client: httpx.AsyncClient,
    actor_ip: str | None = None,
) -> dict[str, Any]:
    existing = await db.scalar(
        select(SoftwareRequest).where(
            SoftwareRequest.requester_id == requester_id,
            SoftwareRequest.idempotency_key == idempotency_key,
        )
    )
    if existing is not None:
        slug, name, ver, _ = await _software_labels(
            db, existing.software_id, existing.catalogue_version_id
        )
        phase, done, total, updated, claimed = await _job_progress(db, existing.id)
        return serialize_request(
            existing,
            software_slug=slug,
            software_name=name,
            version=ver,
            replayed=True,
            progress_phase=phase,
            progress_bytes_done=done,
            progress_bytes_total=total,
            progress_updated_at=updated,
            job_claimed_at=claimed,
        )

    device = await db.scalar(
        select(Device).where(Device.id == device_id, Device.owner_user_id == requester_id)
    )
    if device is None:
        raise AppError("NOT_FOUND", 404)

    row = SoftwareRequest(
        requester_id=requester_id,
        device_id=device_id,
        raw_request=user_prompt,
        status=RequestStatus.RECEIVED.value,
        idempotency_key=idempotency_key,
        version=1,
        expires_at=_expires_at(settings),
    )
    db.add(row)
    await db.flush()

    row.status = RequestStatus.UNDERSTANDING.value
    await db.flush()

    preview = await run_preview(
        db,
        settings,
        threat,
        owner_user_id=requester_id,
        device_id=device_id,
        raw_request=user_prompt,
        http_client=http_client,
        request_id=row.id,
    )

    status = status_for_outcome(preview.status)
    row.status = status.value
    row.decision_reason = (preview.policy.reason_code if preview.policy else preview.status)[:60]
    row.normalized_intent = preview.intent.model_dump(mode="json")
    if preview.match is not None:
        row.software_id = preview.match.software_id
        row.catalogue_version_id = preview.match.catalogue_version_id
    if preview.policy is not None and preview.policy.policy_revision is not None:
        row.policy_revision = preview.policy.policy_revision

    await audit.record(
        db,
        action="software_request.created",
        resource_type="software_request",
        resource_id=row.id,
        result=AuditResult.SUCCESS,
        actor_type=ActorType.USER,
        actor_id=requester_id,
        reason_code=row.decision_reason,
        source_ip=actor_ip,
        metadata={"status": row.status},
    )

    if status == RequestStatus.AUTO_APPROVED:
        await _auto_approve(db, settings, row=row, actor_ip=actor_ip)
    elif status == RequestStatus.AWAITING_APPROVAL:
        await enqueue_approval_notifications(
            db, settings, request_id=row.id, exclude_user_id=requester_id
        )
        await audit.record(
            db,
            action="software_request.awaiting_approval",
            resource_type="software_request",
            resource_id=row.id,
            result=AuditResult.SUCCESS,
            actor_type=ActorType.SYSTEM,
            reason_code=row.decision_reason,
            metadata={"status": row.status},
        )

    slug = preview.match.software_slug if preview.match else None
    name = preview.match.display_name if preview.match else None
    ver = preview.match.version if preview.match else None
    await db.flush()
    return serialize_request(
        row,
        software_slug=slug,
        software_name=name,
        version=ver,
        explanation=preview.explanation,
    )


async def _auto_approve(
    db: AsyncSession,
    settings: Settings,
    *,
    row: SoftwareRequest,
    actor_ip: str | None,
) -> None:
    if row.software_id is None or row.catalogue_version_id is None:
        return
    version = await catalogue.get_version(db, row.catalogue_version_id)
    expires = row.expires_at or _expires_at(settings)
    binding = approval_binding_hash(
        request_id=row.id,
        requester_id=row.requester_id,
        device_id=row.device_id,
        software_id=row.software_id,
        catalogue_version_id=row.catalogue_version_id,
        sha256=version.sha256 or "",
        policy_revision=row.policy_revision,
        expires_at_iso=expires.astimezone(UTC).isoformat(),
        reason_code=row.decision_reason or "POLICY_AUTO_APPROVE",
    )
    db.add(
        Approval(
            request_id=row.id,
            approver_id=None,
            decision=ApprovalDecision.APPROVED.value,
            comment="Deterministic auto-approval",
            approval_binding_hash=binding,
            expires_at=expires,
            channel=ApprovalChannel.POLICY_AUTO.value,
        )
    )
    row.status = RequestStatus.READY_TO_INSTALL.value
    row.version += 1
    await _queue_job(db, settings, row=row, version=version)
    await audit.record(
        db,
        action="software_request.auto_approved",
        resource_type="software_request",
        resource_id=row.id,
        result=AuditResult.SUCCESS,
        actor_type=ActorType.SYSTEM,
        reason_code=row.decision_reason,
        source_ip=actor_ip,
        metadata={"binding_prefix": binding[:12]},
    )


async def _queue_job(
    db: AsyncSession,
    settings: Settings,
    *,
    row: SoftwareRequest,
    version: CatalogueVersion,
) -> InstallationJob:
    """Create a QUEUED job. Signing/dispatch execution is Phase 8."""
    existing = await db.scalar(select(InstallationJob).where(InstallationJob.request_id == row.id))
    if existing is not None:
        return existing
    nonce = secrets.token_urlsafe(24)
    payload = f"{row.id}:{row.catalogue_version_id}:{version.sha256}:{nonce}"
    job = InstallationJob(
        request_id=row.id,
        device_id=row.device_id,
        catalogue_version_id=row.catalogue_version_id,
        status=JobStatus.QUEUED.value,
        job_nonce=nonce,
        job_payload_hash=hashlib.sha256(payload.encode()).hexdigest(),
        expires_at=datetime.now(UTC) + timedelta(minutes=settings.job_ttl_minutes),
        attempt_count=0,
    )
    db.add(job)
    row.status = RequestStatus.QUEUED.value
    await db.flush()
    return job


async def list_own_requests(
    db: AsyncSession, *, requester_id: uuid.UUID, limit: int = 50
) -> list[dict[str, Any]]:
    rows = (
        await db.scalars(
            select(SoftwareRequest)
            .where(SoftwareRequest.requester_id == requester_id)
            .order_by(SoftwareRequest.created_at.desc())
            .limit(limit)
        )
    ).all()
    out: list[dict[str, Any]] = []
    for row in rows:
        slug, name, ver, _ = await _software_labels(db, row.software_id, row.catalogue_version_id)
        phase, done, total, updated, claimed = await _job_progress(db, row.id)
        out.append(
            serialize_request(
                row,
                software_slug=slug,
                software_name=name,
                version=ver,
                progress_phase=phase,
                progress_bytes_done=done,
                progress_bytes_total=total,
                progress_updated_at=updated,
                job_claimed_at=claimed,
            )
        )
    return out


async def get_own_request(
    db: AsyncSession, *, requester_id: uuid.UUID, request_id: uuid.UUID
) -> dict[str, Any]:
    row = await db.scalar(
        select(SoftwareRequest).where(
            SoftwareRequest.id == request_id, SoftwareRequest.requester_id == requester_id
        )
    )
    if row is None:
        raise AppError("NOT_FOUND", 404)
    slug, name, ver, _ = await _software_labels(db, row.software_id, row.catalogue_version_id)
    phase, done, total, updated, claimed = await _job_progress(db, row.id)
    return serialize_request(
        row,
        software_slug=slug,
        software_name=name,
        version=ver,
        progress_phase=phase,
        progress_bytes_done=done,
        progress_bytes_total=total,
        progress_updated_at=updated,
        job_claimed_at=claimed,
    )


async def cancel_own_request(
    db: AsyncSession,
    *,
    requester_id: uuid.UUID,
    request_id: uuid.UUID,
    actor_ip: str | None = None,
) -> dict[str, str | uuid.UUID]:
    row = await db.scalar(
        select(SoftwareRequest).where(
            SoftwareRequest.id == request_id, SoftwareRequest.requester_id == requester_id
        )
    )
    if row is None:
        raise AppError("NOT_FOUND", 404)
    if row.status in TERMINAL:
        raise AppError("CONFLICT", 409, {"status": row.status})
    if row.status not in CANCELABLE:
        raise AppError("CONFLICT", 409, {"status": row.status})
    row.status = RequestStatus.CANCELLED.value
    row.version += 1
    await audit.record(
        db,
        action="software_request.cancelled",
        resource_type="software_request",
        resource_id=row.id,
        result=AuditResult.SUCCESS,
        actor_type=ActorType.USER,
        actor_id=requester_id,
        source_ip=actor_ip,
        metadata={"status": row.status},
    )
    await db.flush()
    return {"id": row.id, "status": row.status}


async def list_pending_approvals(db: AsyncSession, *, limit: int = 50) -> list[dict[str, Any]]:
    rows = (
        await db.scalars(
            select(SoftwareRequest)
            .where(SoftwareRequest.status == RequestStatus.AWAITING_APPROVAL.value)
            .order_by(SoftwareRequest.created_at.asc())
            .limit(limit)
        )
    ).all()
    items: list[dict[str, Any]] = []
    for row in rows:
        user = await db.get(User, row.requester_id)
        device = await db.get(Device, row.device_id)
        slug, name, ver, sha_prefix = await _software_labels(
            db, row.software_id, row.catalogue_version_id
        )
        threat = None
        check = await db.scalar(
            select(SecurityCheck)
            .where(SecurityCheck.request_id == row.id)
            .order_by(SecurityCheck.checked_at.desc())
            .limit(1)
        )
        if check is not None:
            threat = check.verdict
        items.append(
            {
                "request_id": row.id,
                "status": row.status,
                "decision_reason": row.decision_reason,
                "raw_request": row.raw_request,
                "requester_id": row.requester_id,
                "requester_email": user.email if user else None,
                "device_id": row.device_id,
                "device_name": device.device_name if device else None,
                "software_slug": slug,
                "software_name": name,
                "version": ver,
                "sha256_prefix": sha_prefix,
                "threat_verdict": threat,
                "policy_revision": row.policy_revision,
                "created_at": row.created_at,
                "expires_at": row.expires_at,
                "request_version": row.version,
            }
        )
    return items


async def decide_approval(
    db: AsyncSession,
    settings: Settings,
    *,
    request_id: uuid.UUID,
    approver_id: uuid.UUID,
    decision: str,
    comment: str | None,
    expected_version: int,
    actor_ip: str | None = None,
) -> dict[str, Any]:
    row = await db.scalar(
        select(SoftwareRequest).where(SoftwareRequest.id == request_id).with_for_update()
    )
    if row is None:
        raise AppError("NOT_FOUND", 404)
    if row.requester_id == approver_id:
        raise AppError("SELF_APPROVAL_FORBIDDEN", 403)
    if row.status != RequestStatus.AWAITING_APPROVAL.value:
        raise AppError("ALREADY_DECIDED", 409, {"status": row.status})
    if row.expires_at is not None and row.expires_at <= datetime.now(UTC):
        row.status = RequestStatus.EXPIRED.value
        row.version += 1
        raise AppError("REQUEST_EXPIRED", 409)
    if row.version != expected_version:
        raise AppError(
            "VERSION_CONFLICT", 409, {"expected": expected_version, "actual": row.version}
        )
    if row.software_id is None or row.catalogue_version_id is None:
        raise AppError("VALIDATION_ERROR", 400)

    existing = await db.scalar(select(Approval).where(Approval.request_id == row.id))
    if existing is not None:
        raise AppError("ALREADY_DECIDED", 409)

    version = await catalogue.get_version(db, row.catalogue_version_id)
    expires = row.expires_at or _expires_at(settings)
    binding = approval_binding_hash(
        request_id=row.id,
        requester_id=row.requester_id,
        device_id=row.device_id,
        software_id=row.software_id,
        catalogue_version_id=row.catalogue_version_id,
        sha256=version.sha256 or "",
        policy_revision=row.policy_revision,
        expires_at_iso=expires.astimezone(UTC).isoformat(),
        reason_code=row.decision_reason or "POLICY_REQUIRE_APPROVAL",
    )
    approval = Approval(
        request_id=row.id,
        approver_id=approver_id,
        decision=decision,
        comment=comment,
        approval_binding_hash=binding,
        expires_at=expires,
        channel=ApprovalChannel.WEB.value,
    )
    db.add(approval)

    if decision == ApprovalDecision.REJECTED.value:
        row.status = RequestStatus.REJECTED.value
        row.version += 1
        await audit.record(
            db,
            action="software_request.rejected",
            resource_type="software_request",
            resource_id=row.id,
            result=AuditResult.SUCCESS,
            actor_type=ActorType.USER,
            actor_id=approver_id,
            source_ip=actor_ip,
            metadata={"binding_prefix": binding[:12]},
        )
    else:
        row.status = RequestStatus.APPROVED.value
        row.version += 1
        await db.flush()
        row.status = RequestStatus.READY_TO_INSTALL.value
        await _queue_job(db, settings, row=row, version=version)
        await audit.record(
            db,
            action="software_request.approved",
            resource_type="software_request",
            resource_id=row.id,
            result=AuditResult.SUCCESS,
            actor_type=ActorType.USER,
            actor_id=approver_id,
            source_ip=actor_ip,
            metadata={"binding_prefix": binding[:12], "job": "queued"},
        )

    await db.flush()
    return {
        "request_id": row.id,
        "status": row.status,
        "decision": decision,
        "approval_id": approval.id,
        "binding_hash": binding,
        "details": {},
    }
