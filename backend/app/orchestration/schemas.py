"""Request/response schemas for software preview (no persistence — Phase 7)."""

from __future__ import annotations

import uuid
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class PreviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    device_id: uuid.UUID
    raw_request: str = Field(min_length=1, max_length=500)

    @field_validator("raw_request")
    @classmethod
    def _printable(cls, value: str) -> str:
        cleaned = "".join(ch for ch in value if ch.isprintable() or ch in "\n\t")
        cleaned = cleaned.strip()
        if not cleaned:
            raise ValueError("raw_request must not be empty")
        return cleaned


class IntentOut(BaseModel):
    intent: str
    software_query: str
    edition: str | None
    requested_version: str | None
    platform_preference: str | None
    clarification_required: bool
    clarification_question: str | None
    confidence: float
    source: Literal["gemini", "fallback"]


class MatchOut(BaseModel):
    software_id: uuid.UUID | None = None
    software_slug: str | None = None
    display_name: str | None = None
    matched_alias: str | None = None
    catalogue_version_id: uuid.UUID | None = None
    version: str | None = None


class PolicyOut(BaseModel):
    outcome: str
    reason_code: str
    public_message: str
    compatible: bool | None = None
    compatibility_reason: str | None = None
    threat_verdict: str | None = None
    threat_provider: str | None = None
    policy_decision: str | None = None
    policy_revision: int | None = None
    auto_approve_eligible: bool = False
    details: dict[str, Any] = Field(default_factory=dict)


PreviewStatus = Literal[
    "READY",
    "NEEDS_CLARIFICATION",
    "NOT_FOUND",
    "UNKNOWN_INTENT",
    "BLOCKED",
    "INCOMPATIBLE",
    "ALREADY_INSTALLED",
    "REQUIRE_APPROVAL",
    "AUTO_APPROVE",
    "ALLOW",
    "SECURITY_REVIEW",
    "SECURITY_CHECK_UNAVAILABLE",
    "PACKAGE_NOT_APPROVED",
]


class PreviewOut(BaseModel):
    status: PreviewStatus
    intent: IntentOut
    match: MatchOut | None = None
    policy: PolicyOut | None = None
    explanation: str
    tool_trace: list[str]
    gemini_configured: bool
    model: str | None = None
