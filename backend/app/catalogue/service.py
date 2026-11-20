"""Catalogue persistence helpers: search, detail, create, activate."""

from __future__ import annotations

import uuid
from collections.abc import Sequence

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.catalogue.compatibility import PackageSnapshot, mandatory_fields_complete
from app.catalogue.models import CatalogueSoftware, CatalogueVersion, SoftwareAlias
from app.catalogue.normalize import normalize_alias, slug_candidate
from app.catalogue.schemas import (
    CreateSoftware,
    CreateVersion,
    PatchVersion,
    SoftwareDetail,
    SoftwareSummary,
    VersionOut,
)
from app.core.errors import AppError
from app.db.enums import LifecycleStatus


def version_out(software: CatalogueSoftware, version: CatalogueVersion) -> VersionOut:
    snap = package_snapshot(software, version)
    return VersionOut(
        id=version.id,
        software_id=version.software_id,
        version=version.version,
        os_family=version.os_family,
        architecture=version.architecture,
        minimum_os_version=version.minimum_os_version,
        minimum_memory_bytes=version.minimum_memory_bytes,
        minimum_disk_bytes=version.minimum_disk_bytes,
        installer_type=version.installer_type,
        source_type=version.source_type,
        source_reference=version.source_reference,
        package_identifier=version.package_identifier,
        verification_method=version.verification_method,
        sha256=version.sha256,
        signature_publisher=version.signature_publisher,
        signature_required=version.signature_required,
        package_size_bytes=version.package_size_bytes,
        release_status=version.release_status,
        metadata_complete=mandatory_fields_complete(snap),
        created_at=version.created_at,
    )


def package_snapshot(software: CatalogueSoftware, version: CatalogueVersion) -> PackageSnapshot:
    return PackageSnapshot(
        software_lifecycle=software.lifecycle_status,
        release_status=version.release_status,
        os_family=version.os_family,
        architecture=version.architecture,
        minimum_os_version=version.minimum_os_version,
        minimum_memory_bytes=version.minimum_memory_bytes,
        minimum_disk_bytes=version.minimum_disk_bytes,
        installer_type=version.installer_type,
        source_type=version.source_type,
        source_reference=version.source_reference,
        sha256=version.sha256,
        signature_publisher=version.signature_publisher,
        signature_required=version.signature_required,
        verification_method=version.verification_method,
        package_identifier=version.package_identifier,
        version=version.version,
    )


async def aliases_for(
    db: AsyncSession, software_ids: Sequence[uuid.UUID]
) -> dict[uuid.UUID, list[str]]:
    if not software_ids:
        return {}
    rows = (
        await db.scalars(
            select(SoftwareAlias).where(SoftwareAlias.software_id.in_(list(software_ids)))
        )
    ).all()
    out: dict[uuid.UUID, list[str]] = {sid: [] for sid in software_ids}
    for row in rows:
        out.setdefault(row.software_id, []).append(row.alias_normalized)
    for aliases in out.values():
        aliases.sort()
    return out


def software_summary(software: CatalogueSoftware, aliases: list[str]) -> SoftwareSummary:
    return SoftwareSummary(
        id=software.id,
        slug=software.slug,
        display_name=software.display_name,
        description=software.description,
        publisher=software.publisher,
        category=software.category,
        lifecycle_status=software.lifecycle_status,
        risk_level=software.risk_level,
        aliases=aliases,
    )


async def get_software(db: AsyncSession, software_id: uuid.UUID) -> CatalogueSoftware:
    software = await db.get(CatalogueSoftware, software_id)
    if software is None:
        raise AppError("NOT_FOUND", 404)
    return software


async def get_version(db: AsyncSession, version_id: uuid.UUID) -> CatalogueVersion:
    version = await db.get(CatalogueVersion, version_id)
    if version is None:
        raise AppError("NOT_FOUND", 404)
    return version


async def software_detail(db: AsyncSession, software: CatalogueSoftware) -> SoftwareDetail:
    alias_map = await aliases_for(db, [software.id])
    versions = (
        await db.scalars(
            select(CatalogueVersion)
            .where(CatalogueVersion.software_id == software.id)
            .order_by(CatalogueVersion.created_at.desc())
            .limit(100)
        )
    ).all()
    return SoftwareDetail(
        **software_summary(software, alias_map.get(software.id, [])).model_dump(),
        versions=[version_out(software, v) for v in versions],
        created_at=software.created_at,
        updated_at=software.updated_at,
    )


async def search_approved(
    db: AsyncSession, query: str, *, limit: int = 20
) -> list[tuple[CatalogueSoftware, str | None, list[CatalogueVersion]]]:
    """Exact alias / slug / display-name match against ACTIVE software only."""
    needle = normalize_alias(query)
    if not needle or len(needle) > 120:
        return []
    slug = slug_candidate(query)

    alias_hit = await db.scalar(
        select(SoftwareAlias).where(SoftwareAlias.alias_normalized == needle)
    )
    software_ids: list[uuid.UUID] = []
    matched: dict[uuid.UUID, str | None] = {}
    if alias_hit is not None:
        software_ids.append(alias_hit.software_id)
        matched[alias_hit.software_id] = alias_hit.alias_normalized

    by_slug = await db.scalar(
        select(CatalogueSoftware).where(
            CatalogueSoftware.slug == slug,
            CatalogueSoftware.lifecycle_status == LifecycleStatus.ACTIVE.value,
        )
    )
    if by_slug is not None and by_slug.id not in matched:
        software_ids.append(by_slug.id)
        matched[by_slug.id] = None

    # Exact normalized display name as a last deterministic key (still exact, not fuzzy).
    candidates = (
        await db.scalars(
            select(CatalogueSoftware)
            .where(
                CatalogueSoftware.lifecycle_status == LifecycleStatus.ACTIVE.value,
                or_(
                    CatalogueSoftware.slug == slug,
                    CatalogueSoftware.display_name.ilike(query.strip()),
                ),
            )
            .limit(limit)
        )
    ).all()
    for software in candidates:
        if software.id not in matched:
            software_ids.append(software.id)
            matched[software.id] = None

    if not software_ids:
        return []

    softwares = (
        await db.scalars(
            select(CatalogueSoftware).where(
                CatalogueSoftware.id.in_(software_ids),
                CatalogueSoftware.lifecycle_status == LifecycleStatus.ACTIVE.value,
            )
        )
    ).all()
    by_id = {s.id: s for s in softwares}
    versions = (
        await db.scalars(
            select(CatalogueVersion).where(
                CatalogueVersion.software_id.in_(software_ids),
                CatalogueVersion.release_status == LifecycleStatus.ACTIVE.value,
            )
        )
    ).all()
    versions_by: dict[uuid.UUID, list[CatalogueVersion]] = {sid: [] for sid in software_ids}
    for version in versions:
        versions_by.setdefault(version.software_id, []).append(version)

    results: list[tuple[CatalogueSoftware, str | None, list[CatalogueVersion]]] = []
    for sid in software_ids:
        row = by_id.get(sid)
        if row is None:
            continue
        results.append((row, matched.get(sid), versions_by.get(sid, [])))
        if len(results) >= limit:
            break
    return results


async def resolve_exact(db: AsyncSession, query: str) -> CatalogueSoftware | None:
    """Single exact alias match used by later AI fallback (Phase 6)."""
    needle = normalize_alias(query)
    if not needle:
        return None
    alias = await db.scalar(select(SoftwareAlias).where(SoftwareAlias.alias_normalized == needle))
    if alias is None:
        return None
    software = await db.get(CatalogueSoftware, alias.software_id)
    if software is None or software.lifecycle_status != LifecycleStatus.ACTIVE.value:
        return None
    return software


async def create_software(db: AsyncSession, body: CreateSoftware) -> CatalogueSoftware:
    existing = await db.scalar(select(CatalogueSoftware).where(CatalogueSoftware.slug == body.slug))
    if existing is not None:
        raise AppError("CONFLICT", 409, {"field": "slug"})
    aliases = _unique_aliases([body.display_name, body.slug, *body.aliases])
    await _assert_aliases_free(db, aliases)
    software = CatalogueSoftware(
        slug=body.slug,
        display_name=body.display_name.strip(),
        description=body.description.strip(),
        publisher=body.publisher.strip(),
        category=body.category.strip(),
        lifecycle_status=LifecycleStatus.PENDING_REVIEW.value,
        risk_level=body.risk_level.value,
    )
    db.add(software)
    await db.flush()
    for alias in aliases:
        db.add(SoftwareAlias(software_id=software.id, alias_normalized=alias))
    await db.flush()
    return software


async def create_version(db: AsyncSession, body: CreateVersion) -> CatalogueVersion:
    software = await get_software(db, body.software_id)
    clash = await db.scalar(
        select(CatalogueVersion).where(
            CatalogueVersion.software_id == body.software_id,
            CatalogueVersion.version == body.version,
            CatalogueVersion.os_family == body.os_family.value,
            CatalogueVersion.architecture == body.architecture.value,
        )
    )
    if clash is not None:
        raise AppError("CONFLICT", 409, {"field": "version"})
    if body.release_status == LifecycleStatus.ACTIVE:
        # Build a temporary snapshot to validate completeness before insert.
        probe = CatalogueVersion(
            software_id=software.id,
            version=body.version,
            os_family=body.os_family.value,
            architecture=body.architecture.value,
            minimum_os_version=body.minimum_os_version,
            minimum_memory_bytes=body.minimum_memory_bytes,
            minimum_disk_bytes=body.minimum_disk_bytes,
            installer_type=body.installer_type.value,
            source_type=body.source_type.value,
            source_reference=body.source_reference,
            package_identifier=body.package_identifier,
            verification_method=body.verification_method.value
            if body.verification_method
            else None,
            sha256=body.sha256,
            signature_publisher=body.signature_publisher,
            signature_required=body.signature_required,
            package_size_bytes=body.package_size_bytes,
            release_status=body.release_status.value,
        )
        if (
            software.lifecycle_status != LifecycleStatus.ACTIVE.value
            or not mandatory_fields_complete(package_snapshot(software, probe))
        ):
            raise AppError("PACKAGE_METADATA_INCOMPLETE", 409)

    version = CatalogueVersion(
        software_id=software.id,
        version=body.version,
        os_family=body.os_family.value,
        architecture=body.architecture.value,
        minimum_os_version=body.minimum_os_version,
        minimum_memory_bytes=body.minimum_memory_bytes,
        minimum_disk_bytes=body.minimum_disk_bytes,
        installer_type=body.installer_type.value,
        source_type=body.source_type.value,
        source_reference=body.source_reference,
        package_identifier=body.package_identifier,
        verification_method=body.verification_method.value if body.verification_method else None,
        sha256=body.sha256,
        signature_publisher=body.signature_publisher,
        signature_required=body.signature_required,
        package_size_bytes=body.package_size_bytes,
        release_status=body.release_status.value,
    )
    db.add(version)
    await db.flush()
    return version


async def patch_version(
    db: AsyncSession, version_id: uuid.UUID, body: PatchVersion
) -> CatalogueVersion:
    version = await get_version(db, version_id)
    software = await get_software(db, version.software_id)
    data = body.model_dump(exclude_unset=True)
    if "verification_method" in data and data["verification_method"] is not None:
        data["verification_method"] = data["verification_method"].value
    if "release_status" in data and data["release_status"] is not None:
        data["release_status"] = data["release_status"].value
    for key, value in data.items():
        setattr(version, key, value)
    await db.flush()
    if version.release_status == LifecycleStatus.ACTIVE.value and (
        software.lifecycle_status != LifecycleStatus.ACTIVE.value
        or not mandatory_fields_complete(package_snapshot(software, version))
    ):
        raise AppError("PACKAGE_METADATA_INCOMPLETE", 409)
    return version


async def set_software_lifecycle(
    db: AsyncSession, software_id: uuid.UUID, status: LifecycleStatus
) -> CatalogueSoftware:
    software = await get_software(db, software_id)
    software.lifecycle_status = status.value
    await db.flush()
    if status == LifecycleStatus.ACTIVE:
        # Any version already marked ACTIVE must still satisfy mandatory fields.
        active_versions = (
            await db.scalars(
                select(CatalogueVersion).where(
                    CatalogueVersion.software_id == software.id,
                    CatalogueVersion.release_status == LifecycleStatus.ACTIVE.value,
                )
            )
        ).all()
        for version in active_versions:
            if not mandatory_fields_complete(package_snapshot(software, version)):
                raise AppError("PACKAGE_METADATA_INCOMPLETE", 409)
    return software


def _unique_aliases(raw: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in raw:
        alias = normalize_alias(item)
        if not alias or alias in seen or len(alias) > 120:
            continue
        seen.add(alias)
        out.append(alias)
    if not out:
        raise AppError("VALIDATION_ERROR", 422, {"field": "aliases"})
    return out


async def _assert_aliases_free(db: AsyncSession, aliases: list[str]) -> None:
    clash = await db.scalar(
        select(SoftwareAlias).where(SoftwareAlias.alias_normalized.in_(aliases)).limit(1)
    )
    if clash is not None:
        raise AppError("CONFLICT", 409, {"field": "alias"})
