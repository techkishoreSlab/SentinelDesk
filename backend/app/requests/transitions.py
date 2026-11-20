"""Map deterministic policy/preview outcomes onto request statuses (spec §6)."""

from __future__ import annotations

from app.db.enums import RequestStatus

# Preview / policy outcomes → persistent request status.
OUTCOME_TO_STATUS: dict[str, RequestStatus] = {
    "BLOCKED": RequestStatus.BLOCKED,
    "INCOMPATIBLE": RequestStatus.INCOMPATIBLE,
    "ALREADY_INSTALLED": RequestStatus.ALREADY_INSTALLED,
    "NOT_FOUND": RequestStatus.NOT_FOUND,
    "NEEDS_CLARIFICATION": RequestStatus.NEEDS_CLARIFICATION,
    "UNKNOWN_INTENT": RequestStatus.NEEDS_CLARIFICATION,
    "SECURITY_REVIEW": RequestStatus.SECURITY_REVIEW,
    "SECURITY_CHECK_UNAVAILABLE": RequestStatus.SECURITY_CHECK_UNAVAILABLE,
    "PACKAGE_NOT_APPROVED": RequestStatus.BLOCKED,
    "REQUIRE_APPROVAL": RequestStatus.AWAITING_APPROVAL,
    "AUTO_APPROVE": RequestStatus.AUTO_APPROVED,
    "ALLOW": RequestStatus.AWAITING_APPROVAL,
    "READY": RequestStatus.AWAITING_APPROVAL,
}

CANCELABLE = frozenset(
    {
        RequestStatus.RECEIVED.value,
        RequestStatus.UNDERSTANDING.value,
        RequestStatus.NEEDS_CLARIFICATION.value,
        RequestStatus.AWAITING_APPROVAL.value,
        RequestStatus.AUTO_APPROVED.value,
        RequestStatus.APPROVED.value,
        RequestStatus.READY_TO_INSTALL.value,
        RequestStatus.QUEUED.value,
    }
)

TERMINAL = frozenset(
    {
        RequestStatus.BLOCKED.value,
        RequestStatus.INCOMPATIBLE.value,
        RequestStatus.NOT_FOUND.value,
        RequestStatus.ALREADY_INSTALLED.value,
        RequestStatus.REJECTED.value,
        RequestStatus.EXPIRED.value,
        RequestStatus.SUCCEEDED.value,
        RequestStatus.FAILED.value,
        RequestStatus.CANCELLED.value,
        RequestStatus.SECURITY_CHECK_UNAVAILABLE.value,
    }
)


def status_for_outcome(outcome: str) -> RequestStatus:
    return OUTCOME_TO_STATUS.get(outcome, RequestStatus.NEEDS_CLARIFICATION)
