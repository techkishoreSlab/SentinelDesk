"""API schemas for software requests and approvals."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class CreateSoftwareRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    device_id: uuid.UUID
    user_prompt: str = Field(min_length=1, max_length=500)
    idempotency_key: str = Field(min_length=8, max_length=80, pattern=r"^[A-Za-z0-9._:-]+$")

    @field_validator("user_prompt")
    @classmethod
    def _printable(cls, value: str) -> str:
        cleaned = "".join(ch for ch in value if ch.isprintable() or ch in "\n\t").strip()
        if not cleaned:
            raise ValueError("user_prompt must not be empty")
        return cleaned


class RequestOut(BaseModel):
    id: uuid.UUID
    status: str
    decision_reason: str | None
    raw_request: str
    device_id: uuid.UUID
    software_id: uuid.UUID | None
    catalogue_version_id: uuid.UUID | None
    software_slug: str | None = None
    software_name: str | None = None
    version: str | None = None
    explanation: str | None = None
    policy_revision: int | None
    idempotency_key: str
    request_version: int
    created_at: datetime
    updated_at: datetime
    expires_at: datetime | None
    replayed: bool = False


class RequestListOut(BaseModel):
    items: list[RequestOut]


class CancelOut(BaseModel):
    id: uuid.UUID
    status: str


class ApprovalQueueItem(BaseModel):
    request_id: uuid.UUID
    status: str
    decision_reason: str | None
    raw_request: str
    requester_id: uuid.UUID
    requester_email: str | None
    device_id: uuid.UUID
    device_name: str | None
    software_slug: str | None
    software_name: str | None
    version: str | None
    sha256_prefix: str | None
    threat_verdict: str | None
    policy_revision: int | None
    created_at: datetime
    expires_at: datetime | None
    request_version: int


class ApprovalDecisionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: Literal["APPROVED", "REJECTED"]
    comment: str | None = Field(default=None, max_length=1000)
    expected_version: int = Field(ge=1)


class ApprovalDecisionOut(BaseModel):
    request_id: uuid.UUID
    status: str
    decision: str
    approval_id: uuid.UUID
    binding_hash: str
    details: dict[str, Any] = Field(default_factory=dict)
