"""Deterministic explanations for policy outcomes (Gemini may polish later)."""

from __future__ import annotations

from app.security.engine import (
    OUTCOME_ALLOW,
    OUTCOME_ALREADY_INSTALLED,
    OUTCOME_AUTO_APPROVE,
    OUTCOME_BLOCKED,
    OUTCOME_INCOMPATIBLE,
    OUTCOME_NOT_FOUND,
    OUTCOME_PACKAGE_NOT_APPROVED,
    OUTCOME_REQUIRE_APPROVAL,
    OUTCOME_SECURITY_CHECK_UNAVAILABLE,
    OUTCOME_SECURITY_REVIEW,
)


def decision_summary(
    *,
    software_name: str,
    version: str | None,
    outcome: str,
    reason_code: str,
    public_message: str,
) -> str:
    ver = f" version {version}" if version else ""
    return (
        f"Software: {software_name}{ver}. Outcome: {outcome}. "
        f"Reason: {reason_code}. Message: {public_message}"
    )


def deterministic_explanation(
    *,
    software_name: str | None,
    version: str | None,
    outcome: str,
    reason_code: str,
    public_message: str,
) -> str:
    """Short plain-language explanation that never invents security verdicts."""
    name = software_name or "the requested software"
    ver = f" ({version})" if version else ""
    if outcome == OUTCOME_BLOCKED:
        return f"{name}{ver} is blocked by organisational policy ({reason_code})."
    if outcome == OUTCOME_INCOMPATIBLE:
        return f"{name}{ver} is not compatible with this device ({reason_code})."
    if outcome == OUTCOME_ALREADY_INSTALLED:
        return f"{name}{ver} is already installed on this device."
    if outcome == OUTCOME_SECURITY_CHECK_UNAVAILABLE:
        return (
            f"Security verification for {name}{ver} is temporarily unavailable, "
            "so installation is paused."
        )
    if outcome == OUTCOME_SECURITY_REVIEW:
        return f"{name}{ver} needs a security review before it can proceed."
    if outcome == OUTCOME_REQUIRE_APPROVAL:
        return f"{name}{ver} matches the catalogue and needs administrator approval."
    if outcome == OUTCOME_AUTO_APPROVE:
        return f"{name}{ver} is eligible for automatic approval on this device."
    if outcome == OUTCOME_ALLOW:
        return f"{name}{ver} is allowed by policy on this device."
    if outcome == OUTCOME_NOT_FOUND:
        return f"{name} is not in the organisation catalogue."
    if outcome == OUTCOME_PACKAGE_NOT_APPROVED:
        return f"{name}{ver} cannot be installed until catalogue metadata is complete."
    if outcome == "NEEDS_CLARIFICATION":
        return public_message
    if outcome == "UNKNOWN_INTENT":
        return "SentinelDesk could not identify a software installation request."
    return public_message
