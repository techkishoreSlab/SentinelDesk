from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.columns import created_at, enum_check, non_negative, updated_at, uuid_pk
from app.db.enums import (
    Architecture,
    BanMatchType,
    InstallerType,
    LifecycleStatus,
    OsFamily,
    PolicyDecision,
    RiskLevel,
    Severity,
    SourceType,
    VerificationMethod,
)

ARCHIVE_INSTALLER_TYPES = (
    InstallerType.MACOS_DMG_APP.value,
    InstallerType.MACOS_DMG_PKG.value,
    InstallerType.MACOS_ZIP_APP.value,
)
_ARCHIVE_IN = ", ".join(f"'{t}'" for t in ARCHIVE_INSTALLER_TYPES)
ARCHIVE_FIELDS_CHECK = (
    f"installer_type NOT IN ({_ARCHIVE_IN}) "
    "OR (expected_team_id IS NOT NULL AND payload_path IS NOT NULL)"
)
# One top-level name: no slash, no leading dot, no "..", correct suffix for the kind.
PAYLOAD_PATH_CHECK = (
    "payload_path IS NULL OR ("
    "payload_path !~ '[/\\\\]' AND payload_path !~ '^\\.' AND position('..' in payload_path) = 0 "
    "AND ((installer_type IN ('MACOS_DMG_APP', 'MACOS_ZIP_APP') AND payload_path ~ '\\.app$') "
    "OR (installer_type = 'MACOS_DMG_PKG' AND payload_path ~ '\\.pkg$')))"
)


class CatalogueSoftware(Base):
    __tablename__ = "catalogue_software"
    __table_args__ = (
        enum_check("lifecycle_status", LifecycleStatus),
        enum_check("risk_level", RiskLevel),
        CheckConstraint("slug ~ '^[a-z0-9][a-z0-9-]{1,63}$'", name="slug_format"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    slug: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    display_name: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str] = mapped_column(String(1000), nullable=False, default="")
    publisher: Mapped[str] = mapped_column(String(120), nullable=False)
    category: Mapped[str] = mapped_column(String(60), nullable=False)
    lifecycle_status: Mapped[str] = mapped_column(String(16), nullable=False)
    risk_level: Mapped[str] = mapped_column(String(16), nullable=False)
    created_at: Mapped[datetime] = created_at()
    updated_at: Mapped[datetime] = updated_at()


class SoftwareAlias(Base):
    __tablename__ = "software_aliases"
    __table_args__ = (
        CheckConstraint("alias_normalized = lower(alias_normalized)", name="alias_normalized"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    software_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("catalogue_software.id", ondelete="RESTRICT"), nullable=False
    )
    alias_normalized: Mapped[str] = mapped_column(String(120), nullable=False, unique=True)
    created_at: Mapped[datetime] = created_at()


class CatalogueVersion(Base):
    __tablename__ = "catalogue_versions"
    __table_args__ = (
        UniqueConstraint("software_id", "version", "os_family", "architecture"),
        Index("ix_catalogue_versions_platform", "os_family", "architecture", "release_status"),
        enum_check("os_family", OsFamily),
        enum_check("architecture", Architecture),
        enum_check("installer_type", InstallerType),
        enum_check("source_type", SourceType),
        enum_check("release_status", LifecycleStatus),
        enum_check("verification_method", VerificationMethod),
        CheckConstraint("sha256 IS NULL OR sha256 ~ '^[0-9a-f]{64}$'", name="sha256_format"),
        CheckConstraint(
            "expected_team_id IS NULL OR expected_team_id ~ '^[A-Z0-9]{10}$'",
            name="expected_team_id_format",
        ),
        CheckConstraint(ARCHIVE_FIELDS_CHECK, name="archive_fields_required"),
        CheckConstraint(PAYLOAD_PATH_CHECK, name="payload_path_format"),
        *non_negative("minimum_memory_bytes", "minimum_disk_bytes", "package_size_bytes"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    software_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("catalogue_software.id", ondelete="RESTRICT"), nullable=False
    )
    version: Mapped[str] = mapped_column(String(40), nullable=False)
    os_family: Mapped[str] = mapped_column(String(16), nullable=False)
    architecture: Mapped[str] = mapped_column(String(16), nullable=False)
    minimum_os_version: Mapped[str | None] = mapped_column(String(40))
    minimum_memory_bytes: Mapped[int | None] = mapped_column(BigInteger)
    minimum_disk_bytes: Mapped[int | None] = mapped_column(BigInteger)
    installer_type: Mapped[str] = mapped_column(String(16), nullable=False)
    source_type: Mapped[str] = mapped_column(String(32), nullable=False)
    source_reference: Mapped[str | None] = mapped_column(String(300))
    package_identifier: Mapped[str | None] = mapped_column(String(200))
    verification_method: Mapped[str | None] = mapped_column(String(32))
    sha256: Mapped[str | None] = mapped_column(String(64))
    signature_publisher: Mapped[str | None] = mapped_column(String(200))
    signature_required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    package_size_bytes: Mapped[int | None] = mapped_column(BigInteger)
    release_status: Mapped[str] = mapped_column(String(16), nullable=False)
    # Archive installers (DMG / ZIP): Apple Developer Team ID and the single top-level item
    # inside the container to install. Both are NULL for flat .pkg versions.
    expected_team_id: Mapped[str | None] = mapped_column(String(10))
    payload_path: Mapped[str | None] = mapped_column(String(200))
    created_at: Mapped[datetime] = created_at()


class SoftwarePolicy(Base):
    __tablename__ = "software_policies"
    __table_args__ = (
        Index("ix_software_policies_software", "software_id", "effective_from"),
        enum_check("decision", PolicyDecision),
        CheckConstraint("policy_revision >= 1", name="policy_revision_positive"),
        CheckConstraint(
            "NOT auto_approve_eligible OR decision = 'ALLOW'", name="auto_approve_requires_allow"
        ),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    software_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("catalogue_software.id", ondelete="RESTRICT"), nullable=False
    )
    decision: Mapped[str] = mapped_column(String(20), nullable=False)
    auto_approve_eligible: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    policy_revision: Mapped[int] = mapped_column(Integer, nullable=False)
    reason: Mapped[str] = mapped_column(String(500), nullable=False)
    effective_from: Mapped[datetime] = created_at()
    effective_to: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )


class BannedSoftware(Base):
    __tablename__ = "banned_software"
    __table_args__ = (
        Index("ix_banned_software_active_match", "active", "match_type", "match_value"),
        UniqueConstraint("match_type", "match_value"),
        enum_check("match_type", BanMatchType),
        enum_check("severity", Severity),
        CheckConstraint("match_value = lower(match_value)", name="match_value_normalized"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    match_type: Mapped[str] = mapped_column(String(16), nullable=False)
    match_value: Mapped[str] = mapped_column(String(200), nullable=False)
    reason_code: Mapped[str] = mapped_column(String(60), nullable=False)
    public_message: Mapped[str] = mapped_column(String(300), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    created_at: Mapped[datetime] = created_at()
    notes: Mapped[str | None] = mapped_column(Text)
