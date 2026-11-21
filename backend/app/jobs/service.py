"""Claim and complete installation jobs for enrolled devices."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import service as audit
from app.catalogue.compatibility import ARCHIVE_KINDS
from app.catalogue.models import CatalogueSoftware, CatalogueVersion
from app.core.config import Settings
from app.core.errors import AppError
from app.db.enums import ActorType, AuditResult, JobStatus, RequestStatus, VerificationStatus
from app.devices.models import Device
from app.jobs.signing import sign_envelope
from app.requests.models import Approval, InstallationJob, InstallationResult, SoftwareRequest


def build_envelope(
    *,
    job: InstallationJob,
    request: SoftwareRequest,
    version: CatalogueVersion,
    binding_hash: str,
) -> dict[str, Any]:
    envelope: dict[str, Any] = {
        "job_id": str(job.id),
        "device_id": str(job.device_id),
        "nonce": job.job_nonce,
        "issued_at": job.issued_at.astimezone(UTC).isoformat(),
        "expires_at": job.expires_at.astimezone(UTC).isoformat(),
        "package_digest": (version.sha256 or "").lower(),
        "catalogue_version_id": str(job.catalogue_version_id),
        "policy_revision": request.policy_revision,
        "request_binding_hash": binding_hash,
        "request_id": str(job.request_id),
        "installer_type": version.installer_type,
        "source_type": version.source_type,
        "source_reference": version.source_reference,
        "package_identifier": version.package_identifier,
        "package_version": version.version,
        "os_family": version.os_family,
        "architecture": version.architecture,
        "signature_publisher": version.signature_publisher,
        "verification_method": version.verification_method,
        "package_size_bytes": version.package_size_bytes,
    }
    # Only archive kinds carry these keys, so flat .pkg envelopes stay byte-identical and
    # older agents (strict about unknown fields) keep parsing them.
    if version.installer_type in ARCHIVE_KINDS:
        envelope["expected_team_id"] = version.expected_team_id
        envelope["payload_path"] = version.payload_path
    return envelope


async def claim_next_job(
    db: AsyncSession,
    settings: Settings,
    *,
    device: Device,
) -> dict[str, Any] | None:
    now = datetime.now(UTC)
    # Phase 9 recovery: expire abandoned QUEUED/DISPATCHED/RUNNING jobs fleet-wide.
    from app.ops.retention import expire_abandoned_jobs

    await expire_abandoned_jobs(db, now=now)

    job = await db.scalar(
        select(InstallationJob)
        .where(
            InstallationJob.device_id == device.id,
            InstallationJob.status == JobStatus.QUEUED.value,
            InstallationJob.expires_at > now,
        )
        .order_by(InstallationJob.issued_at.asc())
        .with_for_update(skip_locked=True)
        .limit(1)
    )
    if job is None:
        return None

    request = await db.get(SoftwareRequest, job.request_id)
    if request is None:
        job.status = JobStatus.CANCELLED.value
        return None
    version = await db.get(CatalogueVersion, job.catalogue_version_id)
    software = await db.get(CatalogueSoftware, version.software_id) if version else None
    if version is None or software is None:
        job.status = JobStatus.CANCELLED.value
        return None

    approval = await db.scalar(select(Approval).where(Approval.request_id == request.id))
    binding = approval.approval_binding_hash if approval else ""

    envelope = build_envelope(job=job, request=request, version=version, binding_hash=binding)
    # Keep payload hash aligned with the signed envelope.
    canonical = hashlib.sha256(
        json.dumps(envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()
    job.job_payload_hash = canonical
    signature = sign_envelope(settings, envelope)

    job.status = JobStatus.DISPATCHED.value
    job.claimed_at = now
    request.status = RequestStatus.DISPATCHED.value
    request.version += 1

    await audit.record(
        db,
        action="installation_job.dispatched",
        resource_type="installation_job",
        resource_id=job.id,
        result=AuditResult.SUCCESS,
        actor_type=ActorType.DEVICE,
        actor_id=device.id,
        metadata={"software_slug": software.slug, "version": version.version},
    )
    await db.flush()
    return {
        "envelope": envelope,
        "signature": signature,
        "software_slug": software.slug,
        "display_name": software.display_name,
    }


async def mark_started(
    db: AsyncSession,
    *,
    device_id: uuid.UUID,
    job_id: uuid.UUID,
) -> None:
    job = await db.scalar(
        select(InstallationJob)
        .where(InstallationJob.id == job_id, InstallationJob.device_id == device_id)
        .with_for_update()
    )
    if job is None:
        raise AppError("NOT_FOUND", 404)
    if job.status not in {JobStatus.DISPATCHED.value, JobStatus.RUNNING.value}:
        raise AppError("CONFLICT", 409, {"status": job.status})
    if job.expires_at <= datetime.now(UTC):
        job.status = JobStatus.EXPIRED.value
        raise AppError("REQUEST_EXPIRED", 409)
    job.status = JobStatus.RUNNING.value
    job.attempt_count += 1
    request = await db.get(SoftwareRequest, job.request_id)
    if request is not None:
        request.status = RequestStatus.RUNNING.value
        request.version += 1
    await db.flush()


_PROGRESS_ACTIVE = frozenset({JobStatus.DISPATCHED.value, JobStatus.RUNNING.value})
_PROGRESS_MIN_GAP = timedelta(milliseconds=400)


async def record_progress(
    db: AsyncSession,
    *,
    device_id: uuid.UUID,
    job_id: uuid.UUID,
    phase: str,
    bytes_done: int | None,
    bytes_total: int | None,
) -> dict[str, Any]:
    """Persist agent mid-job progress. Does not change request status."""
    job = await db.scalar(
        select(InstallationJob)
        .where(InstallationJob.id == job_id, InstallationJob.device_id == device_id)
        .with_for_update()
    )
    if job is None:
        raise AppError("NOT_FOUND", 404)
    if job.status not in _PROGRESS_ACTIVE:
        raise AppError("CONFLICT", 409, {"status": job.status})
    if job.expires_at <= datetime.now(UTC):
        job.status = JobStatus.EXPIRED.value
        raise AppError("REQUEST_EXPIRED", 409)

    now = datetime.now(UTC)
    if (
        job.progress_updated_at is not None
        and now - job.progress_updated_at < _PROGRESS_MIN_GAP
        and job.progress_phase == phase
    ):
        # Throttle chatty agents; still ack with last stored values.
        return {
            "status": job.status,
            "phase": job.progress_phase or phase,
            "bytes_done": job.progress_bytes_done,
            "bytes_total": job.progress_bytes_total,
        }

    done = bytes_done
    total = bytes_total
    if phase == "DOWNLOADING":
        if done is None:
            done = 0
        if job.progress_bytes_done is not None and done < job.progress_bytes_done:
            done = job.progress_bytes_done  # monotonic clamp
        if total is not None and done > total:
            done = total
    else:
        # Install/verify: clear byte counters so the UI does not keep a stale download %.
        done = None
        total = None

    job.progress_phase = phase
    job.progress_bytes_done = done
    job.progress_bytes_total = total
    job.progress_updated_at = now
    await db.flush()
    return {
        "status": job.status,
        "phase": phase,
        "bytes_done": done,
        "bytes_total": total,
    }


async def submit_result(
    db: AsyncSession,
    *,
    device_id: uuid.UUID,
    job_id: uuid.UUID,
    result_code: str,
    result_summary: str | None,
    exit_code: int | None,
    installed_version: str | None,
    verification_status: str,
    result_details: dict[str, Any] | None = None,
) -> dict[str, str]:
    job = await db.scalar(
        select(InstallationJob)
        .where(InstallationJob.id == job_id, InstallationJob.device_id == device_id)
        .with_for_update()
    )
    if job is None:
        raise AppError("NOT_FOUND", 404)
    if job.status in {
        JobStatus.SUCCEEDED.value,
        JobStatus.FAILED.value,
        JobStatus.FAILED_VERIFICATION.value,
        JobStatus.CANCELLED.value,
        JobStatus.EXPIRED.value,
    }:
        # Idempotent replay of a completed result.
        return {"status": job.status, "result_code": job.result_code or result_code}

    if job.status not in {
        JobStatus.DISPATCHED.value,
        JobStatus.RUNNING.value,
        JobStatus.VERIFYING.value,
    }:
        raise AppError("CONFLICT", 409, {"status": job.status})

    now = datetime.now(UTC)
    if verification_status == VerificationStatus.VERIFIED.value and result_code == "SUCCEEDED":
        job.status = JobStatus.SUCCEEDED.value
        request_status = RequestStatus.SUCCEEDED.value
    elif verification_status == VerificationStatus.FAILED.value:
        job.status = JobStatus.FAILED_VERIFICATION.value
        request_status = RequestStatus.FAILED.value
    else:
        job.status = JobStatus.FAILED.value
        request_status = RequestStatus.FAILED.value

    job.result_code = result_code[:60]
    job.result_summary = (result_summary or "")[:500] or None
    job.completed_at = now

    db.add(
        InstallationResult(
            job_id=job.id,
            device_id=device_id,
            started_at=job.claimed_at,
            finished_at=now,
            exit_code=exit_code,
            installed_version=installed_version,
            verification_status=verification_status,
            result_details=result_details or {},
        )
    )
    request = await db.get(SoftwareRequest, job.request_id)
    if request is not None:
        request.status = request_status
        if request_status == RequestStatus.FAILED.value:
            # Surfaced to the employee as friendly copy (APP_IN_USE, DOWNGRADE_REFUSED, ...).
            request.decision_reason = job.result_code
        request.version += 1

    await audit.record(
        db,
        action="installation_job.completed",
        resource_type="installation_job",
        resource_id=job.id,
        result=AuditResult.SUCCESS
        if job.status == JobStatus.SUCCEEDED.value
        else AuditResult.FAILURE,
        actor_type=ActorType.DEVICE,
        actor_id=device_id,
        reason_code=result_code[:60],
        metadata={"job_status": job.status},
    )
    await db.flush()
    return {"status": job.status, "result_code": job.result_code or result_code}
