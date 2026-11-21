"""Agent wire schemas. Closed, bounded and validated; unknown fields are rejected (spec §11.2)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

from app.db.enums import OsFamily

PROTOCOL_VERSION = 1
MAX_INSTALLED_ITEMS = 1000

# Printable text without control characters; hostnames can contain spaces and unicode.
_PRINTABLE = r"^[^\x00-\x1f\x7f]+$"
DisplayText = Annotated[str, StringConstraints(min_length=1, max_length=120, pattern=_PRINTABLE)]
ShortText = Annotated[str, StringConstraints(min_length=1, max_length=40, pattern=_PRINTABLE)]
VersionText = Annotated[
    str, StringConstraints(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._+\-~: ()]+$")
]
AgentVersion = Annotated[
    str, StringConstraints(min_length=1, max_length=32, pattern=r"^[0-9A-Za-z.+\-]+$")
]
SoftwareIdentifier = Annotated[
    str, StringConstraints(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9._+\-]+$")
]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class InstalledSoftware(_Strict):
    identifier: SoftwareIdentifier
    version: VersionText
    source: Literal["app_bundle", "pkg_receipt"]


class DeviceFactsIn(_Strict):
    device_name: DisplayText
    os_family: OsFamily
    os_version: ShortText
    os_build: ShortText
    architecture: Literal["x86_64", "arm64"]
    cpu_cores: int = Field(ge=1, le=1024)
    memory_total_bytes: int = Field(ge=0, le=2**50)
    disk_free_bytes: int = Field(ge=0, le=2**55)
    installed_software: list[InstalledSoftware] = Field(max_length=MAX_INSTALLED_ITEMS)


InstallerKind = Literal["MACOS_PKG", "MACOS_DMG_APP", "MACOS_DMG_PKG", "MACOS_ZIP_APP"]


class DeviceCapabilitiesIn(_Strict):
    """What the endpoint can install. Omitted by legacy agents (implies MACOS_PKG only)."""

    installers: list[InstallerKind] = Field(min_length=1, max_length=8)

    @field_validator("installers")
    @classmethod
    def _dedupe(cls, value: list[str]) -> list[str]:
        return sorted(set(value))


class EnrollRequest(_Strict):
    protocol_version: Literal[1]
    enrollment_token: str = Field(min_length=1, max_length=128)
    agent_version: AgentVersion
    facts: DeviceFactsIn
    capabilities: DeviceCapabilitiesIn | None = None


class EnrollResponse(BaseModel):
    protocol_version: int = PROTOCOL_VERSION
    device_id: uuid.UUID
    device_credential: str
    credential_expires_at: datetime
    heartbeat_interval_seconds: int


class HeartbeatRequest(_Strict):
    protocol_version: Literal[1]
    agent_version: AgentVersion
    facts: DeviceFactsIn
    capabilities: DeviceCapabilitiesIn | None = None


class HeartbeatResponse(BaseModel):
    protocol_version: int = PROTOCOL_VERSION
    device_id: uuid.UUID
    device_status: str
    next_heartbeat_seconds: int
    credential_expires_at: datetime
    rotate_credential: bool


class RotateResponse(BaseModel):
    protocol_version: int = PROTOCOL_VERSION
    device_credential: str
    credential_expires_at: datetime
