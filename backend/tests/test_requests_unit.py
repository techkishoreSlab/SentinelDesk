"""Unit tests for request transitions and approval binding."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from app.db.enums import RequestStatus
from app.requests.binding import approval_binding_hash
from app.requests.transitions import status_for_outcome


def test_outcome_mapping() -> None:
    assert status_for_outcome("REQUIRE_APPROVAL") == RequestStatus.AWAITING_APPROVAL
    assert status_for_outcome("AUTO_APPROVE") == RequestStatus.AUTO_APPROVED
    assert status_for_outcome("ALLOW") == RequestStatus.AWAITING_APPROVAL
    assert status_for_outcome("BLOCKED") == RequestStatus.BLOCKED
    assert status_for_outcome("UNKNOWN_INTENT") == RequestStatus.NEEDS_CLARIFICATION


def test_binding_hash_stable_and_sensitive() -> None:
    ids = {
        "request_id": uuid.uuid4(),
        "requester_id": uuid.uuid4(),
        "device_id": uuid.uuid4(),
        "software_id": uuid.uuid4(),
        "catalogue_version_id": uuid.uuid4(),
    }
    expires = datetime(2026, 11, 17, tzinfo=UTC).isoformat()
    a = approval_binding_hash(
        **ids,
        sha256="a" * 64,
        policy_revision=1,
        expires_at_iso=expires,
        reason_code="POLICY_REQUIRE_APPROVAL",
    )
    b = approval_binding_hash(
        **ids,
        sha256="a" * 64,
        policy_revision=1,
        expires_at_iso=expires,
        reason_code="POLICY_REQUIRE_APPROVAL",
    )
    c = approval_binding_hash(
        **ids,
        sha256="b" * 64,
        policy_revision=1,
        expires_at_iso=expires,
        reason_code="POLICY_REQUIRE_APPROVAL",
    )
    assert a == b
    assert a != c
    assert len(a) == 64
