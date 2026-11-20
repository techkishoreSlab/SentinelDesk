"""API schemas for security/policy endpoints."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.catalogue.normalize import normalize_alias
from app.db.enums import BanMatchType, PolicyDecision, Severity


class EvaluateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    device_id: uuid.UUID
    catalogue_version_id: uuid.UUID


class EvaluateOut(BaseModel):
    outcome: str
    reason_code: str
    public_message: str
    compatible: bool | None
    compatibility_reason: str | None
    threat_verdict: str | None
    threat_provider: str | None
    ban_rule_id: uuid.UUID | None
    policy_decision: str | None
    policy_revision: int | None
    auto_approve_eligible: bool
    software_id: uuid.UUID
    software_slug: str
    catalogue_version_id: uuid.UUID
    details: dict[str, Any]


class BannedOut(BaseModel):
    id: uuid.UUID
    match_type: str
    match_value: str
    reason_code: str
    public_message: str
    severity: str
    active: bool
    created_at: datetime
    notes: str | None


class CreateBanned(BaseModel):
    model_config = ConfigDict(extra="forbid")
    match_type: BanMatchType
    match_value: str = Field(min_length=1, max_length=200)
    reason_code: str = Field(min_length=1, max_length=60, pattern=r"^[A-Z][A-Z0-9_]{1,58}$")
    public_message: str = Field(min_length=1, max_length=300)
    severity: Severity = Severity.HIGH
    notes: str | None = Field(default=None, max_length=1000)

    @model_validator(mode="after")
    def _normalize_value(self) -> CreateBanned:
        raw = self.match_value.strip()
        if self.match_type == BanMatchType.HASH:
            digest = raw.lower()
            if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
                raise ValueError("hash match_value must be 64 lowercase hex characters")
            self.match_value = digest
        elif self.match_type == BanMatchType.CATALOGUE_ID:
            self.match_value = raw.lower()
        elif self.match_type == BanMatchType.PACKAGE_ID:
            self.match_value = raw.casefold()
        else:
            self.match_value = normalize_alias(raw)
        return self


class PolicyOut(BaseModel):
    id: uuid.UUID
    software_id: uuid.UUID
    decision: str
    auto_approve_eligible: bool
    policy_revision: int
    reason: str
    effective_from: datetime
    effective_to: datetime | None


class CreatePolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    software_id: uuid.UUID
    decision: PolicyDecision
    auto_approve_eligible: bool = False
    reason: str = Field(min_length=1, max_length=500)
    effective_to: datetime | None = None

    @field_validator("auto_approve_eligible")
    @classmethod
    def _auto_requires_allow(cls, value: bool, info: Any) -> bool:
        decision = info.data.get("decision")
        if value and decision is not None and decision != PolicyDecision.ALLOW:
            raise ValueError("auto_approve_eligible requires decision ALLOW")
        return value


class ThreatStatusOut(BaseModel):
    mandatory: bool
    external_configured: bool
    provider: Literal["virustotal"] | None
