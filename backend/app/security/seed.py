"""Seed banned rules and software policies for the demo (spec section 19)."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.catalogue.models import (
    BannedSoftware,
    CatalogueSoftware,
    CatalogueVersion,
    SoftwareAlias,
    SoftwarePolicy,
)
from app.catalogue.normalize import normalize_alias
from app.catalogue.seed import demo_digest, seed_catalogue
from app.db.enums import (
    Architecture,
    BanMatchType,
    InstallerType,
    LifecycleStatus,
    OsFamily,
    PolicyDecision,
    RiskLevel,
    Severity,
    SourceType,
    VerificationMethod,
)
from app.users.models import User


async def _user_id(db: AsyncSession, email: str) -> object | None:
    return await db.scalar(select(User.id).where(User.email == email))


async def seed_security(db: AsyncSession) -> dict[str, int]:
    """Idempotent: catalogue seed + bans + policies + synthetic malware sample."""
    counts = await seed_catalogue(db)
    created_bans = created_policies = 0

    creator = await _user_id(db, "security.admin@sentinel.test")
    if creator is None:
        creator = await _user_id(db, "platform.admin@sentinel.test")
    if creator is None:
        return {**counts, "bans": 0, "policies": 0, "malware_sample": 0}

    # Synthetic malware catalogue entry (clearly labeled demo fixture).
    malware_created = 0
    malware = await db.scalar(
        select(CatalogueSoftware).where(CatalogueSoftware.slug == "demo-malware-sample")
    )
    if malware is None:
        malware = CatalogueSoftware(
            slug="demo-malware-sample",
            display_name="Demo Malware Sample",
            description="Synthetic policy-test fixture. Not real malware.",
            publisher="SentinelDesk Demo Fixtures",
            category="security-test",
            lifecycle_status=LifecycleStatus.ACTIVE.value,
            risk_level=RiskLevel.CRITICAL.value,
        )
        db.add(malware)
        await db.flush()
        db.add(SoftwareAlias(software_id=malware.id, alias_normalized="demo malware sample"))
        db.add(
            CatalogueVersion(
                software_id=malware.id,
                version="1.0.0",
                os_family=OsFamily.MACOS.value,
                architecture=Architecture.X86_64.value,
                minimum_os_version="12.0",
                minimum_memory_bytes=512 * 1024**2,
                minimum_disk_bytes=10 * 1024**2,
                installer_type=InstallerType.MACOS_PKG.value,
                source_type=SourceType.INTERNAL_ARTIFACT_STORE.value,
                source_reference="artifact://demo/malware-sample/1.0.0",
                package_identifier="com.sentineldesk.demo.MalwareSample",
                verification_method=VerificationMethod.MACOS_APP_BUNDLE.value,
                sha256=demo_digest("demo-malware-sample-1.0.0"),
                signature_publisher="SentinelDesk Demo Fixtures",
                signature_required=True,
                package_size_bytes=1024,
                release_status=LifecycleStatus.ACTIVE.value,
            )
        )
        malware_created = 1

    bans = [
        (
            BanMatchType.CATALOGUE_ID,
            "restricted-remote-access",
            "ORG_BANNED_REMOTE_ACCESS",
            "This software is blocked by your organisation's security policy. "
            "No installation was attempted.",
            Severity.HIGH,
        ),
        (
            BanMatchType.HASH,
            demo_digest("demo-malware-sample-1.0.0"),
            "DEMO_MALWARE_HASH",
            "This software is blocked by your organisation's security policy. "
            "No installation was attempted.",
            Severity.CRITICAL,
        ),
        (
            BanMatchType.PACKAGE_ID,
            "com.sentineldesk.demo.MalwareSample",
            "DEMO_MALWARE_PACKAGE",
            "This software is blocked by your organisation's security policy. "
            "No installation was attempted.",
            Severity.CRITICAL,
        ),
    ]
    for match_type, value, reason, message, severity in bans:
        match_value = (
            value.lower()
            if match_type in (BanMatchType.HASH, BanMatchType.CATALOGUE_ID)
            else value.casefold()
            if match_type == BanMatchType.PACKAGE_ID
            else normalize_alias(value)
        )
        exists = await db.scalar(
            select(BannedSoftware).where(
                BannedSoftware.match_type == match_type.value,
                BannedSoftware.match_value == match_value,
            )
        )
        if exists is None:
            db.add(
                BannedSoftware(
                    match_type=match_type.value,
                    match_value=match_value,
                    reason_code=reason,
                    public_message=message,
                    severity=severity.value,
                    active=True,
                    created_by=creator,
                    notes="Synthetic demo fixture",
                )
            )
            created_bans += 1

    # Policies: VS Code auto-approve; Git / GitHub CLI require approval.
    policy_specs = [
        ("visual-studio-code", PolicyDecision.ALLOW, True, "Low-risk approved editor for demo"),
        ("git", PolicyDecision.REQUIRE_APPROVAL, False, "VCS tools require approver sign-off"),
        (
            "github-cli",
            PolicyDecision.REQUIRE_APPROVAL,
            False,
            "Phase 8 real-install candidate requires approver sign-off",
        ),
        (
            "golang",
            PolicyDecision.REQUIRE_APPROVAL,
            False,
            "Official Go toolchain requires approver sign-off",
        ),
        (
            "contoso-notepad-win",
            PolicyDecision.ALLOW,
            True,
            "Allowed on Windows hosts only; Mac fails compatibility",
        ),
    ]
    for slug, decision, auto, reason in policy_specs:
        software = await db.scalar(select(CatalogueSoftware).where(CatalogueSoftware.slug == slug))
        if software is None:
            continue
        existing = await db.scalar(
            select(SoftwarePolicy).where(
                SoftwarePolicy.software_id == software.id,
                SoftwarePolicy.effective_to.is_(None),
            )
        )
        if existing is not None:
            continue
        latest = await db.scalar(
            select(SoftwarePolicy.policy_revision)
            .where(SoftwarePolicy.software_id == software.id)
            .order_by(SoftwarePolicy.policy_revision.desc())
            .limit(1)
        )
        db.add(
            SoftwarePolicy(
                software_id=software.id,
                decision=decision.value,
                auto_approve_eligible=auto,
                policy_revision=(latest or 0) + 1,
                reason=reason,
                created_by=creator,
            )
        )
        created_policies += 1

    await db.commit()
    return {
        **counts,
        "bans": created_bans,
        "policies": created_policies,
        "malware_sample": malware_created,
    }
