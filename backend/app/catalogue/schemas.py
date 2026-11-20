"""Pydantic shapes for catalogue APIs. Unknown fields are rejected."""

from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.db.enums import (
    Architecture,
    InstallerType,
    LifecycleStatus,
    OsFamily,
    RiskLevel,
    SourceType,
    VerificationMethod,
)

_SLUG = re.compile(r"^[a-z0-9][a-z0-9-]{1,63}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_VERSION = re.compile(r"^[A-Za-z0-9._+\-]{1,40}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9._+\-]{1,200}$")


class AliasOut(BaseModel):
    alias_normalized: str


class SoftwareSummary(BaseModel):
    id: uuid.UUID
    slug: str
    display_name: str
    description: str
    publisher: str
    category: str
    lifecycle_status: str
    risk_level: str
    aliases: list[str]


class VersionOut(BaseModel):
    id: uuid.UUID
    software_id: uuid.UUID
    version: str
    os_family: str
    architecture: str
    minimum_os_version: str | None
    minimum_memory_bytes: int | None
    minimum_disk_bytes: int | None
    installer_type: str
    source_type: str
    source_reference: str | None
    package_identifier: str | None
    verification_method: str | None
    sha256: str | None
    signature_publisher: str | None
    signature_required: bool
    package_size_bytes: int | None
    release_status: str
    metadata_complete: bool
    created_at: datetime


class SoftwareDetail(SoftwareSummary):
    versions: list[VersionOut]
    created_at: datetime
    updated_at: datetime


class CreateSoftware(BaseModel):
    model_config = ConfigDict(extra="forbid")
    slug: str = Field(max_length=64)
    display_name: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=1000)
    publisher: str = Field(min_length=1, max_length=120)
    category: str = Field(min_length=1, max_length=60)
    risk_level: RiskLevel = RiskLevel.MEDIUM
    aliases: list[str] = Field(default_factory=list, max_length=20)

    @field_validator("slug")
    @classmethod
    def _slug(cls, value: str) -> str:
        if not _SLUG.fullmatch(value):
            raise ValueError("invalid slug")
        return value


class CreateVersion(BaseModel):
    model_config = ConfigDict(extra="forbid")
    software_id: uuid.UUID
    version: str = Field(min_length=1, max_length=40)
    os_family: OsFamily
    architecture: Architecture
    minimum_os_version: str | None = Field(default=None, max_length=40)
    minimum_memory_bytes: int | None = Field(default=None, ge=0, le=1 << 50)
    minimum_disk_bytes: int | None = Field(default=None, ge=0, le=1 << 55)
    installer_type: InstallerType
    source_type: SourceType
    source_reference: str | None = Field(default=None, max_length=300)
    package_identifier: str | None = Field(default=None, max_length=200)
    verification_method: VerificationMethod | None = None
    sha256: str | None = Field(default=None, max_length=64)
    signature_publisher: str | None = Field(default=None, max_length=200)
    signature_required: bool = True
    package_size_bytes: int | None = Field(default=None, ge=0, le=1 << 40)
    release_status: LifecycleStatus = LifecycleStatus.PENDING_REVIEW

    @field_validator("version")
    @classmethod
    def _version(cls, value: str) -> str:
        if not _VERSION.fullmatch(value):
            raise ValueError("invalid version")
        return value

    @field_validator("sha256")
    @classmethod
    def _sha(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not _SHA256.fullmatch(value):
            raise ValueError("sha256 must be 64 lowercase hex characters")
        return value

    @field_validator("package_identifier")
    @classmethod
    def _ident(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not _IDENTIFIER.fullmatch(value):
            raise ValueError("invalid package_identifier")
        return value

    @field_validator("source_reference")
    @classmethod
    def _source_ref(cls, value: str | None) -> str | None:
        if value is None:
            return None
        # Reject raw http(s) URLs from admins in Phase 4; only configured source identifiers.
        lowered = value.strip().casefold()
        if lowered.startswith(("http://", "https://", "ftp://", "file:")):
            raise ValueError("source_reference must be a configured source id, not a URL")
        return value.strip()


class PatchVersion(BaseModel):
    model_config = ConfigDict(extra="forbid")
    minimum_os_version: str | None = Field(default=None, max_length=40)
    minimum_memory_bytes: int | None = Field(default=None, ge=0, le=1 << 50)
    minimum_disk_bytes: int | None = Field(default=None, ge=0, le=1 << 55)
    source_reference: str | None = Field(default=None, max_length=300)
    package_identifier: str | None = Field(default=None, max_length=200)
    verification_method: VerificationMethod | None = None
    sha256: str | None = Field(default=None, max_length=64)
    signature_publisher: str | None = Field(default=None, max_length=200)
    signature_required: bool | None = None
    package_size_bytes: int | None = Field(default=None, ge=0, le=1 << 40)
    release_status: LifecycleStatus | None = None

    @field_validator("sha256")
    @classmethod
    def _sha(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not _SHA256.fullmatch(value):
            raise ValueError("sha256 must be 64 lowercase hex characters")
        return value

    @field_validator("source_reference")
    @classmethod
    def _source_ref(cls, value: str | None) -> str | None:
        if value is None:
            return None
        lowered = value.strip().casefold()
        if lowered.startswith(("http://", "https://", "ftp://", "file:")):
            raise ValueError("source_reference must be a configured source id, not a URL")
        return value.strip()


class CompatibilityRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    device_id: uuid.UUID
    catalogue_version_id: uuid.UUID


class CompatibilityOut(BaseModel):
    compatible: bool
    reason_code: str
    details: dict[str, Any]
    software_id: uuid.UUID
    software_slug: str
    software_display_name: str
    catalogue_version_id: uuid.UUID
    version: str


class SearchHit(BaseModel):
    software: SoftwareSummary
    matched_alias: str | None
    active_versions: list[VersionOut]
