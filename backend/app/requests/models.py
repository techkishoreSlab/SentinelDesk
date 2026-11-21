from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.columns import created_at, enum_check, non_negative, updated_at, uuid_pk
from app.db.enums import (
    ApprovalChannel,
    ApprovalDecision,
    JobStatus,
    NotificationChannel,
    NotificationStatus,
    RequestStatus,
    ThreatVerdict,
    VerificationStatus,
)


class SoftwareRequest(Base):
    __tablename__ = "software_requests"
    __table_args__ = (
        UniqueConstraint("requester_id", "idempotency_key"),
        Index("ix_software_requests_requester", "requester_id", "status", "created_at"),
        Index("ix_software_requests_status", "status"),
        enum_check("status", RequestStatus),
        CheckConstraint("char_length(raw_request) <= 500", name="raw_request_length"),
        CheckConstraint("version >= 1", name="version_positive"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    requester_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    device_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("devices.id", ondelete="RESTRICT"), nullable=False
    )
    raw_request: Mapped[str] = mapped_column(String(500), nullable=False)
    normalized_intent: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    software_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("catalogue_software.id", ondelete="RESTRICT")
    )
    catalogue_version_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("catalogue_versions.id", ondelete="RESTRICT")
    )
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    decision_reason: Mapped[str | None] = mapped_column(String(60))
    policy_revision: Mapped[int | None] = mapped_column(Integer)
    idempotency_key: Mapped[str] = mapped_column(String(80), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = created_at()
    updated_at: Mapped[datetime] = updated_at()
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class SecurityCheck(Base):
    """Recorded threat-intelligence / integrity verdicts (spec §9.6 evidence)."""

    __tablename__ = "security_checks"
    __table_args__ = (
        Index("ix_security_checks_version", "catalogue_version_id", "checked_at"),
        enum_check("verdict", ThreatVerdict),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    request_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("software_requests.id", ondelete="RESTRICT")
    )
    catalogue_version_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("catalogue_versions.id", ondelete="RESTRICT"), nullable=False
    )
    provider: Mapped[str] = mapped_column(String(40), nullable=False)
    check_type: Mapped[str] = mapped_column(String(40), nullable=False)
    verdict: Mapped[str] = mapped_column(String(16), nullable=False)
    error_code: Mapped[str | None] = mapped_column(String(60))
    checked_at: Mapped[datetime] = created_at()
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)


class Approval(Base):
    __tablename__ = "approvals"
    __table_args__ = (
        # MVP: exactly one terminal decision per request (spec §10.5).
        UniqueConstraint("request_id"),
        Index("ix_approvals_expiry", "expires_at"),
        enum_check("decision", ApprovalDecision),
        enum_check("channel", ApprovalChannel),
        CheckConstraint("char_length(comment) <= 1000", name="comment_length"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    request_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("software_requests.id", ondelete="RESTRICT"), nullable=False
    )
    approver_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="RESTRICT")
    )
    decision: Mapped[str] = mapped_column(String(16), nullable=False)
    comment: Mapped[str | None] = mapped_column(String(1000))
    approval_binding_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = created_at()
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    channel: Mapped[str] = mapped_column(String(16), nullable=False)


class InstallationJob(Base):
    __tablename__ = "installation_jobs"
    __table_args__ = (
        UniqueConstraint("request_id"),
        Index("ix_installation_jobs_device", "device_id", "status", "expires_at"),
        enum_check("status", JobStatus),
        *non_negative("attempt_count"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    request_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("software_requests.id", ondelete="RESTRICT"), nullable=False
    )
    device_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("devices.id", ondelete="RESTRICT"), nullable=False
    )
    catalogue_version_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("catalogue_versions.id", ondelete="RESTRICT"), nullable=False
    )
    status: Mapped[str] = mapped_column(String(24), nullable=False)
    job_nonce: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    job_payload_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    issued_at: Mapped[datetime] = created_at()
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    result_code: Mapped[str | None] = mapped_column(String(60))
    result_summary: Mapped[str | None] = mapped_column(String(500))
    # Agent-reported mid-job progress (download bytes / install phase). Nullable for
    # legacy agents and terminal jobs that never posted progress.
    progress_phase: Mapped[str | None] = mapped_column(String(16))
    progress_bytes_done: Mapped[int | None] = mapped_column(BigInteger)
    progress_bytes_total: Mapped[int | None] = mapped_column(BigInteger)
    progress_updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class InstallationResult(Base):
    __tablename__ = "installation_results"
    __table_args__ = (
        Index("ix_installation_results_job", "job_id"),
        enum_check("verification_status", VerificationStatus),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    job_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("installation_jobs.id", ondelete="RESTRICT"), nullable=False
    )
    device_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("devices.id", ondelete="RESTRICT"), nullable=False
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    exit_code: Mapped[int | None] = mapped_column(BigInteger)
    installed_version: Mapped[str | None] = mapped_column(String(40))
    verification_status: Mapped[str] = mapped_column(String(16), nullable=False)
    result_details: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)


class Notification(Base):
    __tablename__ = "notifications"
    __table_args__ = (
        UniqueConstraint("request_id", "recipient_id", "channel"),
        Index("ix_notifications_status", "status", "created_at"),
        enum_check("channel", NotificationChannel),
        enum_check("status", NotificationStatus),
        *non_negative("attempt_count"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    request_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("software_requests.id", ondelete="RESTRICT"), nullable=False
    )
    recipient_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    channel: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    provider_message_id: Mapped[str | None] = mapped_column(String(200))
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_error_code: Mapped[str | None] = mapped_column(String(60))
    created_at: Mapped[datetime] = created_at()
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
