"""Catalogue ingest: inspect a package (upload, URL or preset) into a draft, then commit it.

The server detects type, identifier, version, architecture, minimum macOS, Team ID and
publisher. The admin only reviews the name, aliases and the approval toggle. Committed files
are content-addressed (``<sha256>.<ext>``) and their digest is pinned for threat checks.
"""

from __future__ import annotations

import asyncio
import contextlib
import re
import time
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.catalogue.compatibility import ARCHIVE_KINDS, mandatory_fields_complete
from app.catalogue.inspect import InspectError, Inspection, inspect_sandboxed
from app.catalogue.inspect.detect import detect_container, extension_for
from app.catalogue.inspect.messages import hint_for
from app.catalogue.models import CatalogueSoftware, CatalogueVersion, SoftwareAlias, SoftwarePolicy
from app.catalogue.normalize import normalize_alias, slug_candidate
from app.catalogue.presets import Preset, get_preset, preset_url
from app.catalogue.schemas import CreateSoftware, CreateVersion
from app.catalogue.service import (
    create_software,
    create_version,
    package_snapshot,
    software_detail,
    version_out,
)
from app.catalogue.store import (
    Draft,
    commit_artifact,
    discard_draft,
    download_url,
    filename_from_url,
    load_draft,
    new_draft_dir,
    save_stream,
    store_root,
)
from app.core.config import Settings
from app.core.errors import AppError
from app.db.enums import (
    Architecture,
    InstallerType,
    LifecycleStatus,
    OsFamily,
    PolicyDecision,
    RiskLevel,
    SourceType,
    VerificationMethod,
)

_SAFE_NAME = re.compile(r"^[A-Za-z0-9._+\-]{1,180}\.(pkg|dmg|zip)$")
_SLUG = re.compile(r"^[a-z0-9][a-z0-9-]{1,63}$")
_MIN_MEMORY = 512 * 1024**2
_MIN_DISK = 200 * 1024**2
# Downloads and sandboxed inspections are heavy; cap how many run at once per API process.
_SLOTS = asyncio.Semaphore(2)
_SLOT_WAIT_SECONDS = 20


def package_store(settings: Settings) -> Path:
    return store_root(settings)


def pin_digest(settings: Settings, sha256: str) -> None:
    """Persist organisation pin so fail-closed threat checks accept the new package."""
    store = package_store(settings)
    pin_file = store / "pinned.sha256"
    digest = sha256.lower()
    existing: set[str] = set()
    if pin_file.is_file():
        existing = {
            line.strip().lower() for line in pin_file.read_text().splitlines() if line.strip()
        }
    if digest not in existing:
        with pin_file.open("a", encoding="utf-8") as fh:
            fh.write(digest + "\n")


def load_store_pins(settings: Settings) -> set[str]:
    pin_file = Path(settings.package_store_dir) / "pinned.sha256"
    if not pin_file.is_file():
        return set()
    out: set[str] = set()
    for line in pin_file.read_text().splitlines():
        item = line.strip().lower()
        if len(item) == 64 and all(c in "0123456789abcdef" for c in item):
            out.add(item)
    return out


def _safe_filename(name: str) -> str:
    base = Path(name).name
    if not _SAFE_NAME.fullmatch(base):
        raise AppError("VALIDATION_ERROR", 422, {"field": "package", "reason": "pkg_filename"})
    return base


def rejected(exc: InspectError) -> AppError:
    details: dict[str, Any] = {"reason": exc.code, "hint": hint_for(exc.code)}
    for key, value in exc.detail.items():
        if key not in details and isinstance(value, str | list):
            details[key] = value
    return AppError("PACKAGE_REJECTED", 422, details)


@contextlib.asynccontextmanager
async def _slot() -> AsyncIterator[None]:
    try:
        await asyncio.wait_for(_SLOTS.acquire(), timeout=_SLOT_WAIT_SECONDS)
    except TimeoutError as exc:
        raise InspectError("INSPECT_BUSY") from exc
    try:
        yield
    finally:
        _SLOTS.release()


# ------------------------------------------------------------------ inspect


@dataclass(slots=True)
class _Fetched:
    sha256: str
    size: int
    hint: str | None
    source_url: str | None


async def _fetch(
    settings: Settings,
    directory: Path,
    *,
    upload: AsyncIterator[bytes] | None,
    upload_name: str | None,
    url: str | None,
) -> _Fetched:
    dest = directory / "package.bin"
    limit = settings.catalogue_max_package_bytes
    if upload is not None:
        sha, size = await save_stream(upload, dest, limit)
        return _Fetched(sha, size, Path(upload_name).name if upload_name else None, None)
    if url:
        sha, size, final = await download_url(url, dest, limit)
        return _Fetched(sha, size, filename_from_url(final), url)
    raise InspectError("MISSING_SOURCE")


async def _existing(
    db: AsyncSession, *, sha256: str, slug: str, identifier: str
) -> tuple[CatalogueVersion | None, CatalogueSoftware | None]:
    version = await db.scalar(select(CatalogueVersion).where(CatalogueVersion.sha256 == sha256))
    if version is not None:
        return version, await db.get(CatalogueSoftware, version.software_id)
    software = await db.scalar(select(CatalogueSoftware).where(CatalogueSoftware.slug == slug))
    if software is None:
        by_ident = await db.scalar(
            select(CatalogueVersion)
            .where(CatalogueVersion.package_identifier == identifier)
            .order_by(CatalogueVersion.created_at.desc())
            .limit(1)
        )
        if by_ident is not None:
            software = await db.get(CatalogueSoftware, by_ident.software_id)
    return None, software


def _suggest_slug(name: str, preset: Preset | None) -> str:
    if preset is not None:
        return preset.slug
    slug = slug_candidate(name)[:64].strip("-")
    return slug if _SLUG.fullmatch(slug) else f"app-{uuid.uuid4().hex[:8]}"


def _suggest_aliases(name: str, slug: str, preset: Preset | None) -> list[str]:
    raw = [name, slug.replace("-", " "), *(preset.aliases if preset else ())]
    out: list[str] = []
    for item in raw:
        alias = normalize_alias(item)
        if alias and alias not in out:
            out.append(alias)
    return out[:10]


async def inspect_source(
    db: AsyncSession,
    settings: Settings,
    *,
    actor_id: uuid.UUID,
    upload: AsyncIterator[bytes] | None = None,
    upload_name: str | None = None,
    source_url: str | None = None,
    preset_id: str | None = None,
    architecture: str | None = None,
) -> dict[str, Any]:
    preset: Preset | None = None
    if preset_id:
        preset = get_preset(preset_id)
        if preset is None:
            raise rejected(InspectError("PRESET_NOT_FOUND"))
        _arch, source_url = preset_url(preset, architecture)
        upload = None

    draft_id, directory = new_draft_dir(settings)
    try:
        async with _slot():
            fetched = await _fetch(
                settings, directory, upload=upload, upload_name=upload_name, url=source_url
            )
            inspection = await inspect_sandboxed(
                directory / "package.bin",
                fetched.hint,
                seven_zip_path=settings.seven_zip_path,
                timeout=settings.catalogue_inspect_timeout_seconds,
            )
        if preset is not None:
            if inspection.team_id != preset.team_id:
                raise InspectError(
                    "TEAM_ID_MISMATCH", expected=preset.team_id, found=inspection.team_id
                )
            if inspection.kind != preset.kind:
                inspection.warnings.append("PRESET_KIND_CHANGED")
            if preset.urls.keys() - {"universal"} and inspection.architecture == "universal":
                inspection.warnings.append("PRESET_ARCH_UNIVERSAL")
        now = time.time()
        draft = Draft(
            draft_id=draft_id,
            directory=directory,
            created_at=now,
            expires_at=now + settings.catalogue_draft_ttl_seconds,
            actor_id=str(actor_id),
            sha256=fetched.sha256,
            size=fetched.size,
            filename_hint=fetched.hint,
            source_url=fetched.source_url,
            preset_id=preset.id if preset else None,
            inspection=inspection.to_dict(),
        )
        draft.save()
    except InspectError as exc:
        discard_draft(settings, draft_id)
        raise rejected(exc) from exc
    except BaseException:
        discard_draft(settings, draft_id)
        raise

    slug = _suggest_slug(inspection.name, preset)
    version, software = await _existing(
        db, sha256=fetched.sha256, slug=slug, identifier=inspection.identifier
    )
    return {
        "draft_id": draft_id,
        "expires_at": int(draft.expires_at),
        "kind": inspection.kind,
        "name": preset.name if preset else inspection.name,
        "version": inspection.version,
        "identifier": inspection.identifier,
        "architecture": inspection.architecture,
        "minimum_os_version": inspection.minimum_os_version,
        "team_id": inspection.team_id,
        "publisher": inspection.publisher or (preset.publisher if preset else ""),
        "signer": inspection.signer,
        "payload_path": inspection.payload_path,
        "package_size_bytes": fetched.size,
        "sha256": fetched.sha256,
        "suggested_slug": software.slug if software else slug,
        "suggested_aliases": _suggest_aliases(
            preset.name if preset else inspection.name, slug, preset
        ),
        "require_approval_default": preset.require_approval if preset else True,
        "existing_software": (
            {"id": str(software.id), "slug": software.slug, "display_name": software.display_name}
            if software
            else None
        ),
        "already_in_catalogue": (
            {"version_id": str(version.id), "version": version.version} if version else None
        ),
        "warnings": [{"code": w, "hint": hint_for(w)} for w in inspection.warnings],
        "preset_id": preset.id if preset else None,
    }


# ------------------------------------------------------------------- commit


async def _ensure_policy(
    db: AsyncSession, software: CatalogueSoftware, actor_id: uuid.UUID, require_approval: bool
) -> str:
    policy_row = await db.scalar(
        select(SoftwarePolicy).where(
            SoftwarePolicy.software_id == software.id,
            SoftwarePolicy.effective_to.is_(None),
        )
    )
    if policy_row is not None:
        return policy_row.decision
    latest = await db.scalar(
        select(SoftwarePolicy.policy_revision)
        .where(SoftwarePolicy.software_id == software.id)
        .order_by(SoftwarePolicy.policy_revision.desc())
        .limit(1)
    )
    decision = PolicyDecision.REQUIRE_APPROVAL if require_approval else PolicyDecision.ALLOW
    db.add(
        SoftwarePolicy(
            software_id=software.id,
            decision=decision.value,
            auto_approve_eligible=not require_approval,
            policy_revision=(latest or 0) + 1,
            reason="Added via catalogue wizard (production default: require approval).",
            created_by=actor_id,
        )
    )
    return decision.value


async def _add_aliases(db: AsyncSession, software: CatalogueSoftware, aliases: list[str]) -> None:
    for raw in aliases[:20]:
        alias = normalize_alias(raw)
        if not alias or len(alias) > 120:
            continue
        taken = await db.scalar(
            select(SoftwareAlias).where(SoftwareAlias.alias_normalized == alias)
        )
        if taken is None:
            db.add(SoftwareAlias(software_id=software.id, alias_normalized=alias))


@dataclass(slots=True)
class CommitInput:
    actor_id: uuid.UUID
    inspection: Inspection
    sha256: str
    size: int
    slug: str
    display_name: str
    aliases: list[str]
    require_approval: bool
    category: str
    risk: RiskLevel
    description: str


async def _commit(
    db: AsyncSession, settings: Settings, data: CommitInput, draft: Draft
) -> dict[str, Any]:
    info = data.inspection
    existing_version = await db.scalar(
        select(CatalogueVersion).where(CatalogueVersion.sha256 == data.sha256)
    )
    if existing_version is not None:
        software = await db.get(CatalogueSoftware, existing_version.software_id)
        assert software is not None
        discard_draft(settings, draft.draft_id)
        return {
            "status": "ALREADY_IN_CATALOGUE",
            "software": await software_detail(db, software),
            "version": version_out(software, existing_version),
            "policy": None,
        }

    if not _SLUG.fullmatch(data.slug):
        raise AppError("VALIDATION_ERROR", 422, {"field": "slug"})
    software = await db.scalar(select(CatalogueSoftware).where(CatalogueSoftware.slug == data.slug))
    if software is None:
        _version, software = await _existing(
            db, sha256=data.sha256, slug=data.slug, identifier=info.identifier
        )
    if software is None:
        free = [a for a in data.aliases if normalize_alias(a)]
        taken = {
            row.alias_normalized
            for row in (
                await db.scalars(
                    select(SoftwareAlias).where(
                        SoftwareAlias.alias_normalized.in_([normalize_alias(a) for a in free])
                    )
                )
            ).all()
        }
        software = await create_software(
            db,
            CreateSoftware(
                slug=data.slug,
                display_name=data.display_name,
                description=data.description[:1000],
                publisher=(info.publisher or info.team_id or "Unknown")[:120],
                category=data.category,
                risk_level=data.risk,
                aliases=[a for a in free if normalize_alias(a) not in taken],
            ),
        )
    else:
        await _add_aliases(db, software, data.aliases)

    kind = info.kind
    is_archive = kind in ARCHIVE_KINDS
    ext = extension_for(kind)
    factor = 3 if is_archive else 2
    try:
        version = await create_version(
            db,
            CreateVersion(
                software_id=software.id,
                version=info.version,
                os_family=OsFamily.MACOS,
                architecture=Architecture(info.architecture),
                minimum_os_version=info.minimum_os_version,
                minimum_memory_bytes=_MIN_MEMORY,
                minimum_disk_bytes=max(_MIN_DISK, data.size * factor),
                installer_type=InstallerType(kind),
                source_type=SourceType.INTERNAL_ARTIFACT_STORE,
                source_reference=f"artifact://sha256/{data.sha256}.{ext}",
                package_identifier=info.identifier,
                verification_method=(
                    VerificationMethod.MACOS_PKG_RECEIPT
                    if kind in {"MACOS_PKG", "MACOS_DMG_PKG"}
                    else VerificationMethod.MACOS_APP_BUNDLE
                ),
                sha256=data.sha256,
                signature_publisher=(info.signer or info.publisher or info.team_id)[:200],
                signature_required=True,
                package_size_bytes=data.size,
                release_status=LifecycleStatus.PENDING_REVIEW,
                expected_team_id=info.team_id if is_archive else None,
                payload_path=info.payload_path if is_archive else None,
            ),
        )
    except AppError as exc:
        if exc.code == "CONFLICT" and (exc.details or {}).get("field") == "version":
            raise AppError(
                "CATALOGUE_VERSION_EXISTS",
                409,
                {"version": info.version, "architecture": info.architecture},
            ) from exc
        raise
    software.lifecycle_status = LifecycleStatus.ACTIVE.value
    version.release_status = LifecycleStatus.ACTIVE.value
    if not mandatory_fields_complete(package_snapshot(software, version)):
        raise AppError("PACKAGE_METADATA_INCOMPLETE", 409)
    await db.flush()

    policy = await _ensure_policy(db, software, data.actor_id, data.require_approval)
    stored = commit_artifact(settings, draft, ext)
    pin_digest(settings, data.sha256)
    discard_draft(settings, draft.draft_id)
    return {
        "status": "ADDED",
        "software": await software_detail(db, software),
        "version": version_out(software, version),
        "policy": policy,
        "stored_path": str(stored),
        "filename": stored.name,
    }


async def commit_draft(
    db: AsyncSession,
    settings: Settings,
    *,
    actor_id: uuid.UUID,
    draft_id: str,
    display_name: str,
    aliases: list[str],
    require_approval: bool,
    slug: str | None = None,
) -> dict[str, Any]:
    try:
        draft = load_draft(settings, draft_id)
        info = Inspection.from_dict(draft.inspection)
    except InspectError as exc:
        raise rejected(exc) from exc
    preset = get_preset(draft.preset_id) if draft.preset_id else None
    if preset is not None and info.team_id != preset.team_id:
        raise rejected(InspectError("TEAM_ID_MISMATCH"))
    name = display_name.strip()[:120] or info.name
    chosen_slug = (slug or "").strip() or _suggest_slug(name, preset)
    result = await _commit(
        db,
        settings,
        CommitInput(
            actor_id=actor_id,
            inspection=info,
            sha256=draft.sha256,
            size=draft.size,
            slug=chosen_slug,
            display_name=name,
            aliases=[name, *aliases],
            require_approval=require_approval,
            category=preset.category if preset else "applications",
            risk=preset.risk if preset else RiskLevel.MEDIUM,
            description=(preset.description if preset else "") or f"{name} for macOS",
        ),
        draft,
    )
    result["draft"] = {
        "kind": info.kind,
        "team_id": info.team_id,
        "sha256": draft.sha256,
        "source_url": draft.source_url,
        "preset_id": draft.preset_id,
    }
    return result


# ------------------------------------------------------------------- legacy


async def ingest_package(
    db: AsyncSession,
    settings: Settings,
    *,
    actor_id: uuid.UUID,
    slug: str,
    display_name: str,
    publisher: str,
    version: str,
    package_identifier: str,
    aliases: list[str],
    architecture: Architecture,
    minimum_os_version: str,
    require_approval: bool,
    source_url: str | None,
    upload_name: str | None,
    upload: AsyncIterator[bytes] | None,
) -> dict[str, Any]:
    """Legacy one-step ``/ingest``: inspect + commit in a single call.

    Inspected metadata wins when available. A flat .pkg that can't be inspected (for
    example an unsigned internal build) keeps the old behaviour and uses the form fields.
    """
    if not _SLUG.fullmatch(slug):
        raise AppError("VALIDATION_ERROR", 422, {"field": "slug"})
    if upload is not None and upload_name:
        _safe_filename(upload_name)
    elif not source_url:
        raise AppError("VALIDATION_ERROR", 422, {"field": "package", "reason": "missing_source"})

    draft_id, directory = new_draft_dir(settings)
    try:
        async with _slot():
            fetched = await _fetch(
                settings,
                directory,
                upload=upload if upload_name else None,
                upload_name=upload_name,
                url=None if upload_name else source_url,
            )
            try:
                info = await inspect_sandboxed(
                    directory / "package.bin",
                    fetched.hint,
                    seven_zip_path=settings.seven_zip_path,
                    timeout=settings.catalogue_inspect_timeout_seconds,
                )
                manual = False
            except InspectError as exc:
                if detect_container(directory / "package.bin", fetched.hint) != "pkg":
                    raise
                info = Inspection(
                    kind=InstallerType.MACOS_PKG.value,
                    name=display_name,
                    version=version,
                    identifier=package_identifier,
                    architecture=architecture.value,
                    minimum_os_version=minimum_os_version,
                    team_id="",
                    publisher=publisher,
                    signer=publisher,
                    payload_path=None,
                    warnings=[exc.code],
                )
                manual = True
        now = time.time()
        draft = Draft(
            draft_id=draft_id,
            directory=directory,
            created_at=now,
            expires_at=now + settings.catalogue_draft_ttl_seconds,
            actor_id=str(actor_id),
            sha256=fetched.sha256,
            size=fetched.size,
            filename_hint=fetched.hint,
            source_url=fetched.source_url,
            preset_id=None,
            inspection={},
        )
        result = await _commit(
            db,
            settings,
            CommitInput(
                actor_id=actor_id,
                inspection=info,
                sha256=fetched.sha256,
                size=fetched.size,
                slug=slug,
                display_name=display_name,
                aliases=aliases,
                require_approval=require_approval,
                category="developer-tools",
                risk=RiskLevel.LOW,
                description=f"Ingested package {fetched.hint or info.identifier}",
            ),
            draft,
        )
    except InspectError as exc:
        discard_draft(settings, draft_id)
        raise rejected(exc) from exc
    except BaseException:
        discard_draft(settings, draft_id)
        raise
    return {
        "software": result["software"],
        "staged_path": result.get("stored_path", ""),
        "sha256": fetched.sha256,
        "package_size_bytes": fetched.size,
        "filename": result.get("filename", f"{fetched.sha256}.{extension_for(info.kind)}"),
        "source_reference": result["version"].source_reference,
        "policy": "REQUIRE_APPROVAL" if require_approval else "ALLOW",
        "kind": info.kind,
        "team_id": info.team_id or None,
        "manual_metadata": manual,
    }
