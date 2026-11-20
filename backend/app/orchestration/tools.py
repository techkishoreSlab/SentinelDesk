"""Fixed typed tool registry. The model never selects or invokes these (D1 / §7.3)."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.catalogue import service as catalogue
from app.catalogue.compatibility import DeviceSnapshot
from app.catalogue.compatibility import evaluate as evaluate_compat
from app.catalogue.models import CatalogueSoftware, CatalogueVersion
from app.catalogue.normalize import normalize_alias
from app.catalogue.versions import parse_version
from app.core.config import Settings
from app.db.enums import LifecycleStatus
from app.devices.models import Device, DeviceFacts
from app.security.engine import PolicyEvaluation, evaluate_install
from app.security.threat import CompositeThreatIntel

TOOL_EXTRACT_INTENT = "extract_intent"
TOOL_RESOLVE_ALIAS = "resolve_catalogue_alias"
TOOL_PICK_VERSION = "pick_catalogue_version"
TOOL_EVALUATE_POLICY = "evaluate_policy"
TOOL_EXPLAIN = "explain_decision"

# Ordered registry — orchestrator calls these; Gemini never chooses them.
TOOL_REGISTRY: tuple[str, ...] = (
    TOOL_EXTRACT_INTENT,
    TOOL_RESOLVE_ALIAS,
    TOOL_PICK_VERSION,
    TOOL_EVALUATE_POLICY,
    TOOL_EXPLAIN,
)


@dataclass(frozen=True, slots=True)
class AliasMatch:
    software: CatalogueSoftware
    matched_alias: str | None
    versions: list[CatalogueVersion]


@dataclass(frozen=True, slots=True)
class AliasResolution:
    status: str  # MATCHED | NOT_FOUND | AMBIGUOUS
    matches: list[AliasMatch]
    clarification_question: str | None = None


@dataclass(frozen=True, slots=True)
class VersionPick:
    status: str  # PICKED | NONE_COMPATIBLE | VERSION_NOT_FOUND
    version: CatalogueVersion | None
    reason_code: str | None = None


def _alias_query_variants(query: str) -> list[str]:
    """Deterministic exact-match variants only (no fuzzy search)."""
    seen: set[str] = set()
    out: list[str] = []
    candidates = [query.strip()]
    normalized = normalize_alias(query)
    if normalized:
        candidates.append(normalized)
        for prefix in ("microsoft ", "google ", "apple ", "adobe ", "mozilla "):
            if normalized.startswith(prefix):
                candidates.append(normalized[len(prefix) :])
    for item in candidates:
        key = normalize_alias(item)
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


async def resolve_catalogue_alias(db: AsyncSession, query: str) -> AliasResolution:
    """Exact alias / slug / display-name match only — never fuzzy guess."""
    hits: list[tuple[CatalogueSoftware, str | None, list[CatalogueVersion]]] = []
    for variant in _alias_query_variants(query):
        hits = await catalogue.search_approved(db, variant, limit=10)
        if hits:
            break
    if not hits:
        exact = None
        for variant in _alias_query_variants(query):
            exact = await catalogue.resolve_exact(db, variant)
            if exact is not None:
                break
        if exact is None:
            return AliasResolution(status="NOT_FOUND", matches=[])
        versions = (
            await db.scalars(
                select(CatalogueVersion).where(
                    CatalogueVersion.software_id == exact.id,
                    CatalogueVersion.release_status == LifecycleStatus.ACTIVE.value,
                )
            )
        ).all()
        return AliasResolution(
            status="MATCHED",
            matches=[
                AliasMatch(
                    software=exact,
                    matched_alias=normalize_alias(query),
                    versions=list(versions),
                )
            ],
        )
    if len(hits) > 1:
        names = ", ".join(h[0].display_name for h in hits[:5])
        return AliasResolution(
            status="AMBIGUOUS",
            matches=[
                AliasMatch(software=s, matched_alias=alias, versions=list(vers))
                for s, alias, vers in hits
            ],
            clarification_question=(
                f"Multiple catalogue matches were found ({names}). "
                "Which exact product should be installed?"
            ),
        )
    software, alias, versions = hits[0]
    return AliasResolution(
        status="MATCHED",
        matches=[AliasMatch(software=software, matched_alias=alias, versions=list(versions))],
    )


def _version_sort_key(version: CatalogueVersion) -> tuple[int, ...]:
    parsed = parse_version(version.version)
    return parsed if parsed is not None else (0,)


def pick_catalogue_version(
    *,
    software: CatalogueSoftware,
    versions: list[CatalogueVersion],
    device: Device,
    facts: DeviceFacts | None,
    requested_version: str | None,
    stale_after_seconds: int,
) -> VersionPick:
    """Pick latest active catalogue version for the device, or an exact requested version."""
    installed: list[dict[str, Any]] = []
    if facts is not None and isinstance(facts.installed_software_summary, dict):
        raw = facts.installed_software_summary.get("items", [])
        if isinstance(raw, list):
            installed = [i for i in raw if isinstance(i, dict)]
    snapshot = DeviceSnapshot(
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
    stale_after = timedelta(seconds=stale_after_seconds)

    active = [v for v in versions if v.release_status == LifecycleStatus.ACTIVE.value]
    req = (requested_version or "").strip().casefold()
    if req and req not in {"stable", "latest", "current"}:
        candidates = [v for v in active if v.version.casefold() == req]
        if not candidates:
            return VersionPick(
                status="VERSION_NOT_FOUND",
                version=None,
                reason_code="VERSION_NOT_IN_CATALOGUE",
            )
    else:
        candidates = active

    # Prefer OS/arch matches; among those, highest numeric version.
    platform_ok: list[CatalogueVersion] = []
    for version in candidates:
        snap = catalogue.package_snapshot(software, version)
        result = evaluate_compat(snapshot, snap, stale_after=stale_after)
        # ALREADY_INSTALLED still counts as a pickable package for policy evaluation.
        if result.compatible or result.reason_code == "ALREADY_INSTALLED":
            platform_ok.append(version)

    if not platform_ok:
        # Fall back to any OS/arch match so policy can return INCOMPATIBLE with a concrete version.
        os_arch = [
            v
            for v in candidates
            if v.os_family == device.os_family and v.architecture == device.architecture
        ]
        if not os_arch:
            os_arch = [v for v in candidates if v.os_family == device.os_family]
        if not os_arch:
            return VersionPick(status="NONE_COMPATIBLE", version=None, reason_code="OS_UNSUPPORTED")
        platform_ok = os_arch

    platform_ok.sort(key=_version_sort_key, reverse=True)
    return VersionPick(status="PICKED", version=platform_ok[0])


async def evaluate_policy_tool(
    db: AsyncSession,
    settings: Settings,
    threat: CompositeThreatIntel,
    *,
    device: Device,
    software: CatalogueSoftware,
    version: CatalogueVersion,
    request_id: uuid.UUID | None = None,
) -> PolicyEvaluation:
    return await evaluate_install(
        db,
        settings,
        threat,
        device=device,
        software=software,
        version=version,
        record_security_check=True,
        request_id=request_id,
    )


async def load_owned_device(
    db: AsyncSession, *, device_id: uuid.UUID, owner_user_id: uuid.UUID
) -> tuple[Device, DeviceFacts | None] | None:
    device = await db.scalar(
        select(Device).where(Device.id == device_id, Device.owner_user_id == owner_user_id)
    )
    if device is None:
        return None
    facts = await db.scalar(select(DeviceFacts).where(DeviceFacts.device_id == device.id))
    return device, facts
