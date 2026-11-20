"""Deterministic policy engine (spec section 9.1).

Hard blocks (ban, malware, indeterminate mandatory check, incompatible package) always
win over approval paths. This phase evaluates a catalogue version against a device; the
natural-language request workflow is Phase 7.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.catalogue import service as catalogue
from app.catalogue.compatibility import (
    REASON_ALREADY_INSTALLED,
    REASON_COMPATIBLE,
    DeviceSnapshot,
)
from app.catalogue.compatibility import (
    evaluate as evaluate_compat,
)
from app.catalogue.models import CatalogueSoftware, CatalogueVersion, SoftwarePolicy
from app.core.config import Settings
from app.db.enums import LifecycleStatus, PolicyDecision, ThreatVerdict
from app.devices.models import Device, DeviceFacts
from app.requests.models import SecurityCheck
from app.security.banned import BanHit, find_ban
from app.security.threat import CompositeThreatIntel, ThreatResult

# Terminal / routing outcomes exposed to APIs (aligned with request statuses where useful).
OUTCOME_BLOCKED = "BLOCKED"
OUTCOME_INCOMPATIBLE = "INCOMPATIBLE"
OUTCOME_ALREADY_INSTALLED = "ALREADY_INSTALLED"
OUTCOME_SECURITY_CHECK_UNAVAILABLE = "SECURITY_CHECK_UNAVAILABLE"
OUTCOME_SECURITY_REVIEW = "SECURITY_REVIEW"
OUTCOME_REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
OUTCOME_AUTO_APPROVE = "AUTO_APPROVE"
OUTCOME_ALLOW = "ALLOW"
OUTCOME_NOT_FOUND = "NOT_FOUND"
OUTCOME_PACKAGE_NOT_APPROVED = "PACKAGE_NOT_APPROVED"


@dataclass(frozen=True, slots=True)
class PolicyEvaluation:
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
    details: dict[str, Any] = field(default_factory=dict)


_PUBLIC: dict[str, str] = {
    OUTCOME_BLOCKED: (
        "This software is blocked by your organisation's security policy. "
        "No installation was attempted."
    ),
    OUTCOME_INCOMPATIBLE: "This software version is not compatible with this device.",
    OUTCOME_ALREADY_INSTALLED: "The requested version is already installed on this device.",
    OUTCOME_SECURITY_CHECK_UNAVAILABLE: (
        "Security verification is temporarily unavailable. Installation has been paused."
    ),
    OUTCOME_SECURITY_REVIEW: (
        "This package requires a security review before installation can continue."
    ),
    OUTCOME_REQUIRE_APPROVAL: "Your request is waiting for administrator approval.",
    OUTCOME_AUTO_APPROVE: "This package is eligible for automatic approval on this device.",
    OUTCOME_ALLOW: "This package is allowed by policy on this device.",
    OUTCOME_NOT_FOUND: "This software is not currently available in your organisation's catalogue.",
    OUTCOME_PACKAGE_NOT_APPROVED: (
        "This package cannot be activated until every mandatory catalogue field is set."
    ),
}


async def _active_policy(db: AsyncSession, software_id: uuid.UUID) -> SoftwarePolicy | None:
    now = datetime.now(UTC)
    rows = (
        await db.scalars(
            select(SoftwarePolicy)
            .where(SoftwarePolicy.software_id == software_id)
            .order_by(SoftwarePolicy.policy_revision.desc())
            .limit(20)
        )
    ).all()
    for row in rows:
        if row.effective_from <= now and (row.effective_to is None or row.effective_to > now):
            return row
    return None


def _device_snapshot(device: Device, facts: DeviceFacts | None) -> DeviceSnapshot:
    installed: list[dict[str, Any]] = []
    if facts is not None and isinstance(facts.installed_software_summary, dict):
        raw = facts.installed_software_summary.get("items", [])
        if isinstance(raw, list):
            installed = [i for i in raw if isinstance(i, dict)]
    return DeviceSnapshot(
        enrolled=True,
        status=device.device_status,
        last_seen_at=device.last_seen_at,
        os_family=device.os_family,
        os_version=device.os_version,
        architecture=device.architecture,
        memory_total_bytes=facts.memory_total_bytes if facts else None,
        disk_free_bytes=facts.disk_free_bytes if facts else None,
        installed_software=installed,
    )


async def evaluate_install(
    db: AsyncSession,
    settings: Settings,
    threat: CompositeThreatIntel,
    *,
    device: Device,
    software: CatalogueSoftware,
    version: CatalogueVersion,
    record_security_check: bool = True,
    request_id: uuid.UUID | None = None,
) -> PolicyEvaluation:
    """Evaluate ban → trust → threat → compatibility → organisational policy."""

    def finish(
        outcome: str,
        reason: str,
        *,
        ban: BanHit | None = None,
        threat_result: ThreatResult | None = None,
        policy: SoftwarePolicy | None = None,
        compat_reason: str | None = None,
        compatible: bool | None = None,
        details: dict[str, Any] | None = None,
        auto: bool = False,
    ) -> PolicyEvaluation:
        return PolicyEvaluation(
            outcome=outcome,
            reason_code=reason,
            public_message=_PUBLIC[outcome],
            compatible=compatible,
            compatibility_reason=compat_reason,
            threat_verdict=threat_result.verdict.value if threat_result else None,
            threat_provider=threat_result.provider if threat_result else None,
            ban_rule_id=ban.rule_id if ban else None,
            policy_decision=policy.decision if policy else None,
            policy_revision=policy.policy_revision if policy else None,
            auto_approve_eligible=auto,
            software_id=software.id,
            software_slug=software.slug,
            catalogue_version_id=version.id,
            details=details or {},
        )

    if (
        software.lifecycle_status != LifecycleStatus.ACTIVE.value
        or version.release_status != LifecycleStatus.ACTIVE.value
    ):
        return finish(OUTCOME_NOT_FOUND, "PACKAGE_NOT_APPROVED")

    # 5. Banned software (terminal hard block).
    ban = await find_ban(db, software=software, version=version)
    if ban is not None:
        return finish(
            OUTCOME_BLOCKED,
            ban.reason_code,
            ban=ban,
            details={"match_type": ban.match_type, "severity": ban.severity},
        )

    # 6. Package trust / provenance (mandatory catalogue fields).
    snap = catalogue.package_snapshot(software, version)
    from app.catalogue.compatibility import mandatory_fields_complete

    if not mandatory_fields_complete(snap):
        return finish(OUTCOME_PACKAGE_NOT_APPROVED, "PACKAGE_METADATA_INCOMPLETE")

    # 7. Threat intelligence (mandatory → fail closed on INDETERMINATE).
    threat_result = await threat.check_hash(version.sha256 or "")
    if record_security_check:
        db.add(
            SecurityCheck(
                request_id=request_id,
                catalogue_version_id=version.id,
                provider=threat_result.provider,
                check_type="hash_lookup",
                verdict=threat_result.verdict.value,
                error_code=threat_result.error_code,
                expires_at=datetime.now(UTC)
                + timedelta(seconds=settings.threat_intel_cache_ttl_seconds),
                details={},  # never store raw provider payloads
            )
        )
        await db.flush()

    if threat_result.verdict == ThreatVerdict.MALICIOUS:
        return finish(OUTCOME_BLOCKED, "THREAT_MALICIOUS", threat_result=threat_result)
    if threat_result.verdict == ThreatVerdict.SUSPICIOUS:
        return finish(OUTCOME_SECURITY_REVIEW, "THREAT_SUSPICIOUS", threat_result=threat_result)
    if threat_result.verdict == ThreatVerdict.INDETERMINATE and threat.mandatory:
        return finish(
            OUTCOME_SECURITY_CHECK_UNAVAILABLE,
            threat_result.error_code or "THREAT_INDETERMINATE",
            threat_result=threat_result,
        )

    # 8. Compatibility.
    facts = await db.scalar(
        select(DeviceFacts)
        .where(DeviceFacts.device_id == device.id)
        .order_by(DeviceFacts.collected_at.desc())
        .limit(1)
    )
    compat = evaluate_compat(
        _device_snapshot(device, facts),
        snap,
        stale_after=timedelta(seconds=settings.device_stale_after_seconds),
    )
    if compat.reason_code == REASON_ALREADY_INSTALLED:
        return finish(
            OUTCOME_ALREADY_INSTALLED,
            compat.reason_code,
            threat_result=threat_result,
            compat_reason=compat.reason_code,
            compatible=False,
            details=compat.details,
        )
    if compat.reason_code != REASON_COMPATIBLE:
        return finish(
            OUTCOME_INCOMPATIBLE,
            compat.reason_code,
            threat_result=threat_result,
            compat_reason=compat.reason_code,
            compatible=False,
            details=compat.details,
        )

    # 9-10. Organisational allow / approval policy.
    policy = await _active_policy(db, software.id)
    if policy is None:
        # No explicit policy: require approval (fail closed on silent allow).
        return finish(
            OUTCOME_REQUIRE_APPROVAL,
            "POLICY_DEFAULT_REQUIRE_APPROVAL",
            threat_result=threat_result,
            compat_reason=compat.reason_code,
            compatible=True,
        )
    if policy.decision == PolicyDecision.BLOCK.value:
        return finish(
            OUTCOME_BLOCKED,
            "POLICY_BLOCK",
            threat_result=threat_result,
            policy=policy,
            compat_reason=compat.reason_code,
            compatible=True,
        )
    if policy.decision == PolicyDecision.REQUIRE_APPROVAL.value:
        return finish(
            OUTCOME_REQUIRE_APPROVAL,
            "POLICY_REQUIRE_APPROVAL",
            threat_result=threat_result,
            policy=policy,
            compat_reason=compat.reason_code,
            compatible=True,
        )
    if policy.decision == PolicyDecision.ALLOW.value and policy.auto_approve_eligible:
        return finish(
            OUTCOME_AUTO_APPROVE,
            "POLICY_AUTO_APPROVE",
            threat_result=threat_result,
            policy=policy,
            compat_reason=compat.reason_code,
            compatible=True,
            auto=True,
        )
    if policy.decision == PolicyDecision.ALLOW.value:
        return finish(
            OUTCOME_ALLOW,
            "POLICY_ALLOW",
            threat_result=threat_result,
            policy=policy,
            compat_reason=compat.reason_code,
            compatible=True,
        )
    return finish(
        OUTCOME_REQUIRE_APPROVAL,
        "POLICY_UNKNOWN",
        threat_result=threat_result,
        policy=policy,
        compatible=True,
    )
