"""Agent job claim / result wire schemas."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class JobEnvelopeOut(BaseModel):
    envelope: dict[str, Any]
    signature: str
    software_slug: str
    display_name: str


class JobStartedIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    protocol_version: Literal[1] = 1


class JobResultIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    protocol_version: Literal[1] = 1
    result_code: str = Field(min_length=1, max_length=60, pattern=r"^[A-Z][A-Z0-9_]{0,58}$")
    result_summary: str | None = Field(default=None, max_length=500)
    exit_code: int | None = Field(default=None, ge=-2147483648, le=2147483647)
    installed_version: str | None = Field(default=None, max_length=40)
    verification_status: Literal["VERIFIED", "FAILED", "NOT_ATTEMPTED"]
    details: dict[str, Any] = Field(default_factory=dict)


class JobResultOut(BaseModel):
    status: str
    result_code: str
