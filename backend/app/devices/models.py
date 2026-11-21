from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, DateTime, ForeignKey, Index, Integer, String
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.columns import created_at, enum_check, non_negative, updated_at, uuid_pk
from app.db.enums import Architecture, DeviceStatus, OsFamily


class Device(Base):
    __tablename__ = "devices"
    __table_args__ = (
        Index("ix_devices_owner_status", "owner_user_id", "device_status"),
        Index("ix_devices_last_seen", "last_seen_at"),
        enum_check("os_family", OsFamily),
        enum_check("architecture", Architecture),
        enum_check("device_status", DeviceStatus),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    owner_user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    device_name: Mapped[str] = mapped_column(String(120), nullable=False)
    os_family: Mapped[str] = mapped_column(String(16), nullable=False)
    os_version: Mapped[str] = mapped_column(String(40), nullable=False)
    architecture: Mapped[str] = mapped_column(String(16), nullable=False)
    agent_version: Mapped[str] = mapped_column(String(32), nullable=False)
    device_status: Mapped[str] = mapped_column(String(16), nullable=False)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    enrolled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    policy_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    # Installer kinds this endpoint (agent + privileged daemon) reported. NULL = legacy agent,
    # which only supports MACOS_PKG.
    supported_installers: Mapped[list[str] | None] = mapped_column(JSONB)
    created_at: Mapped[datetime] = created_at()
    updated_at: Mapped[datetime] = updated_at()


class DeviceCredential(Base):
    __tablename__ = "device_credentials"
    __table_args__ = (Index("ix_device_credentials_device", "device_id"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    device_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("devices.id", ondelete="RESTRICT"), nullable=False
    )
    credential_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    created_at: Mapped[datetime] = created_at()
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class EnrollmentToken(Base):
    __tablename__ = "enrollment_tokens"
    __table_args__ = (Index("ix_enrollment_tokens_owner", "owner_user_id"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    owner_user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    created_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    created_at: Mapped[datetime] = created_at()
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    used_by_device_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("devices.id", ondelete="RESTRICT")
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class DeviceFacts(Base):
    __tablename__ = "device_facts"
    __table_args__ = (
        Index("ix_device_facts_device_time", "device_id", "collected_at"),
        *non_negative("cpu_cores", "memory_total_bytes", "disk_free_bytes"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    device_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("devices.id", ondelete="RESTRICT"), nullable=False
    )
    collected_at: Mapped[datetime] = created_at()
    cpu_arch: Mapped[str] = mapped_column(String(16), nullable=False)
    cpu_cores: Mapped[int] = mapped_column(Integer, nullable=False)
    memory_total_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    disk_free_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    os_build: Mapped[str] = mapped_column(String(40), nullable=False)
    installed_software_summary: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict
    )
