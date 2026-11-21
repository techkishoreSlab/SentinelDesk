"""Software-admin catalogue management (spec §12.2)."""

from __future__ import annotations

import re
import uuid
from collections.abc import AsyncIterator
from typing import Any, Literal

from fastapi import APIRouter, Depends, File, Form, Query, Request, UploadFile
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import service as audit
from app.auth.dependencies import Principal, client_ip, require
from app.auth.rbac import Permission
from app.catalogue import service as catalogue
from app.catalogue.ingest import commit_draft, ingest_package, inspect_source
from app.catalogue.models import CatalogueSoftware
from app.catalogue.presets import PRESETS, Preset
from app.catalogue.schemas import (
    CreateSoftware,
    CreateVersion,
    PatchVersion,
    SoftwareDetail,
    SoftwareSummary,
    VersionOut,
)
from app.catalogue.store import discard_draft
from app.core.config import get_settings
from app.core.errors import AppError
from app.db.enums import ActorType, Architecture, AuditResult, LifecycleStatus
from app.db.session import get_session

router = APIRouter(prefix="/api/v1/admin/catalogue", tags=["admin-catalogue"])
_manage = require(Permission.CATALOGUE_MANAGE)


@router.get("/software", response_model=list[SoftwareSummary])
async def list_software(
    _: Principal = Depends(_manage),  # noqa: B008
    db: AsyncSession = Depends(get_session),  # noqa: B008
    status: LifecycleStatus | None = None,
    limit: int = Query(default=100, ge=1, le=200),
) -> list[SoftwareSummary]:
    stmt = select(CatalogueSoftware).order_by(CatalogueSoftware.display_name).limit(limit)
    if status is not None:
        stmt = stmt.where(CatalogueSoftware.lifecycle_status == status.value)
    rows = (await db.scalars(stmt)).all()
    alias_map = await catalogue.aliases_for(db, [r.id for r in rows])
    return [catalogue.software_summary(r, alias_map.get(r.id, [])) for r in rows]


@router.get("/software/{software_id}", response_model=SoftwareDetail)
async def get_software(
    software_id: uuid.UUID,
    _: Principal = Depends(_manage),  # noqa: B008
    db: AsyncSession = Depends(get_session),  # noqa: B008
) -> SoftwareDetail:
    return await catalogue.software_detail(db, await catalogue.get_software(db, software_id))


@router.post("/software", response_model=SoftwareDetail, status_code=201)
async def create_software(
    body: CreateSoftware,
    request: Request,
    principal: Principal = Depends(_manage),  # noqa: B008
    db: AsyncSession = Depends(get_session),  # noqa: B008
) -> SoftwareDetail:
    software = await catalogue.create_software(db, body)
    await audit.record(
        db,
        action="CATALOGUE_SOFTWARE_CREATED",
        resource_type="catalogue_software",
        resource_id=software.id,
        result=AuditResult.SUCCESS,
        actor_type=ActorType.USER,
        actor_id=principal.user_id,
        source_ip=client_ip(request),
        metadata={"slug": software.slug},
    )
    await db.commit()
    return await catalogue.software_detail(db, software)


@router.post("/software/{software_id}/lifecycle", response_model=SoftwareDetail)
async def set_lifecycle(
    software_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(_manage),  # noqa: B008
    db: AsyncSession = Depends(get_session),  # noqa: B008
    status: Literal["PENDING_REVIEW", "ACTIVE", "DEPRECATED", "RETIRED"] = Query(...),
) -> SoftwareDetail:
    software = await catalogue.set_software_lifecycle(db, software_id, LifecycleStatus(status))
    await audit.record(
        db,
        action="CATALOGUE_SOFTWARE_LIFECYCLE",
        resource_type="catalogue_software",
        resource_id=software.id,
        result=AuditResult.SUCCESS,
        actor_type=ActorType.USER,
        actor_id=principal.user_id,
        source_ip=client_ip(request),
        metadata={"lifecycle_status": status},
    )
    await db.commit()
    return await catalogue.software_detail(db, software)


@router.post("/versions", response_model=VersionOut, status_code=201)
async def create_version(
    body: CreateVersion,
    request: Request,
    principal: Principal = Depends(_manage),  # noqa: B008
    db: AsyncSession = Depends(get_session),  # noqa: B008
) -> VersionOut:
    version = await catalogue.create_version(db, body)
    software = await catalogue.get_software(db, version.software_id)
    await audit.record(
        db,
        action="CATALOGUE_VERSION_CREATED",
        resource_type="catalogue_version",
        resource_id=version.id,
        result=AuditResult.SUCCESS,
        actor_type=ActorType.USER,
        actor_id=principal.user_id,
        source_ip=client_ip(request),
        metadata={
            "software_id": str(software.id),
            "version": version.version,
            "os_family": version.os_family,
            "architecture": version.architecture,
            "release_status": version.release_status,
        },
    )
    await db.commit()
    return catalogue.version_out(software, version)


@router.patch("/versions/{version_id}", response_model=VersionOut)
async def patch_version(
    version_id: uuid.UUID,
    body: PatchVersion,
    request: Request,
    principal: Principal = Depends(_manage),  # noqa: B008
    db: AsyncSession = Depends(get_session),  # noqa: B008
) -> VersionOut:
    if not body.model_fields_set:
        raise AppError("VALIDATION_ERROR", 422)
    version = await catalogue.patch_version(db, version_id, body)
    software = await catalogue.get_software(db, version.software_id)
    await audit.record(
        db,
        action="CATALOGUE_VERSION_UPDATED",
        resource_type="catalogue_version",
        resource_id=version.id,
        result=AuditResult.SUCCESS,
        actor_type=ActorType.USER,
        actor_id=principal.user_id,
        source_ip=client_ip(request),
        metadata={
            "fields": sorted(body.model_fields_set),
            "release_status": version.release_status,
        },
    )
    await db.commit()
    return catalogue.version_out(software, version)


class InspectIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source_url: str | None = Field(default=None, max_length=2000)
    preset_id: str | None = Field(default=None, max_length=64, pattern=r"^[a-z0-9-]{1,64}$")
    architecture: Literal["universal", "arm64", "x86_64"] | None = None


class CommitIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    draft_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    display_name: str = Field(min_length=1, max_length=120)
    aliases: list[str] = Field(default_factory=list, max_length=20)
    require_approval: bool = True
    slug: str | None = Field(default=None, max_length=64)


def _preset_out(preset: Preset) -> dict[str, Any]:
    return {
        "id": preset.id,
        "name": preset.name,
        "publisher": preset.publisher,
        "category": preset.category,
        "kind": preset.kind,
        "team_id": preset.team_id,
        "architectures": list(preset.urls),
        "description": preset.description,
        "require_approval": preset.require_approval,
    }


@router.get("/presets")
async def list_presets(
    _: Principal = Depends(_manage),  # noqa: B008
    db: AsyncSession = Depends(get_session),  # noqa: B008
) -> list[dict[str, Any]]:
    """Curated one-click presets, with whether each is already in the catalogue."""
    slugs = {p.slug for p in PRESETS}
    present = set(
        (
            await db.scalars(
                select(CatalogueSoftware.slug).where(CatalogueSoftware.slug.in_(slugs))
            )
        ).all()
    )
    return [{**_preset_out(p), "in_catalogue": p.slug in present} for p in PRESETS]


async def _audit_inspect(
    db: AsyncSession,
    request: Request,
    principal: Principal,
    *,
    result: AuditResult,
    source: str,
    reason: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> None:
    await audit.record(
        db,
        action="CATALOGUE_PACKAGE_INSPECTED",
        resource_type="catalogue_draft",
        resource_id=None,
        result=result,
        actor_type=ActorType.USER,
        actor_id=principal.user_id,
        source_ip=client_ip(request),
        reason_code=reason,
        metadata={"source": source, **(metadata or {})},
    )
    await db.commit()


async def _run_inspect(
    db: AsyncSession, request: Request, principal: Principal, source: str, **kwargs: Any
) -> dict[str, Any]:
    try:
        draft = await inspect_source(db, get_settings(), actor_id=principal.user_id, **kwargs)
    except AppError as exc:
        reason = (exc.details or {}).get("reason") if exc.code == "PACKAGE_REJECTED" else exc.code
        await db.rollback()
        await _audit_inspect(
            db, request, principal, result=AuditResult.FAILURE, source=source, reason=reason
        )
        raise
    await _audit_inspect(
        db,
        request,
        principal,
        result=AuditResult.SUCCESS,
        source=source,
        metadata={
            "draft_id": draft["draft_id"],
            "kind": draft["kind"],
            "sha256": draft["sha256"],
            "team_id": draft["team_id"],
            "preset_id": draft["preset_id"],
        },
    )
    return draft


@router.post("/inspect")
async def inspect_package(
    body: InspectIn,
    request: Request,
    principal: Principal = Depends(_manage),  # noqa: B008
    db: AsyncSession = Depends(get_session),  # noqa: B008
) -> dict[str, Any]:
    """Step 1 of add: fetch a preset or https URL and auto-detect everything into a draft."""
    if bool(body.preset_id) == bool(body.source_url):
        raise AppError("VALIDATION_ERROR", 422, {"field": "source", "reason": "one_of"})
    return await _run_inspect(
        db,
        request,
        principal,
        "preset" if body.preset_id else "url",
        source_url=(body.source_url or "").strip() or None,
        preset_id=body.preset_id,
        architecture=body.architecture,
    )


@router.post("/inspect/upload")
async def inspect_upload(
    request: Request,
    principal: Principal = Depends(_manage),  # noqa: B008
    db: AsyncSession = Depends(get_session),  # noqa: B008
    filename: str = Query(min_length=1, max_length=200),
) -> dict[str, Any]:
    """Step 1 of add (upload): the raw file is the request body, streamed straight to disk."""
    name = filename.rsplit("/", 1)[-1]
    if not re.fullmatch(r"[A-Za-z0-9 ._+()\-]{1,200}", name):
        raise AppError("VALIDATION_ERROR", 422, {"field": "filename"})
    return await _run_inspect(
        db, request, principal, "upload", upload=request.stream(), upload_name=name
    )


@router.delete("/drafts/{draft_id}", status_code=204)
async def discard_inspection(
    draft_id: str,
    _: Principal = Depends(_manage),  # noqa: B008
) -> None:
    discard_draft(get_settings(), draft_id)


@router.post("/commit")
async def commit_package(
    body: CommitIn,
    request: Request,
    principal: Principal = Depends(_manage),  # noqa: B008
    db: AsyncSession = Depends(get_session),  # noqa: B008
) -> dict[str, Any]:
    """Step 2 of add: store the inspected file by digest and create the catalogue version."""
    result = await commit_draft(
        db,
        get_settings(),
        actor_id=principal.user_id,
        draft_id=body.draft_id,
        display_name=body.display_name,
        aliases=[a.strip() for a in body.aliases if a.strip()],
        require_approval=body.require_approval,
        slug=body.slug,
    )
    software = result["software"]
    version = result["version"]
    if result["status"] == "ADDED":
        await audit.record(
            db,
            action="CATALOGUE_INGESTED",
            resource_type="catalogue_version",
            resource_id=version.id,
            result=AuditResult.SUCCESS,
            actor_type=ActorType.USER,
            actor_id=principal.user_id,
            source_ip=client_ip(request),
            metadata={
                "slug": software.slug,
                "version": version.version,
                "kind": version.installer_type,
                "team_id": result["draft"]["team_id"],
                "sha256": version.sha256,
                "preset_id": result["draft"]["preset_id"],
                "policy": result["policy"],
            },
        )
    await db.commit()
    return {
        "status": result["status"],
        "software_id": str(software.id),
        "slug": software.slug,
        "display_name": software.display_name,
        "version": version.model_dump(mode="json"),
        "policy": result["policy"],
    }


@router.post("/ingest")
async def ingest_software_package(
    request: Request,
    principal: Principal = Depends(_manage),  # noqa: B008
    db: AsyncSession = Depends(get_session),  # noqa: B008
    slug: str = Form(...),
    display_name: str = Form(...),
    publisher: str = Form(...),
    version: str = Form(...),
    package_identifier: str = Form(...),
    aliases: str = Form(default=""),
    architecture: str = Form(default="x86_64"),
    minimum_os_version: str = Form(default="12.0"),
    require_approval: bool = Form(default=True),
    source_url: str | None = Form(default=None),
    package: UploadFile | None = File(default=None),  # noqa: B008
) -> dict[str, Any]:
    """Legacy one-step add (form). Prefer ``/inspect`` + ``/commit``."""
    settings = get_settings()
    alias_list = [a.strip() for a in aliases.split(",") if a.strip()][:20]
    try:
        arch = Architecture(architecture)
    except ValueError as exc:
        raise AppError("VALIDATION_ERROR", 422, {"field": "architecture"}) from exc

    upload_name = None
    upload = None
    if package is not None and package.filename:
        upload_name = package.filename
        upload = _iter_upload(package)

    result = await ingest_package(
        db,
        settings,
        actor_id=principal.user_id,
        slug=slug.strip(),
        display_name=display_name.strip(),
        publisher=publisher.strip(),
        version=version.strip(),
        package_identifier=package_identifier.strip(),
        aliases=alias_list,
        architecture=arch,
        minimum_os_version=minimum_os_version.strip() or "12.0",
        require_approval=require_approval,
        source_url=(source_url or "").strip() or None,
        upload_name=upload_name,
        upload=upload,
    )
    await audit.record(
        db,
        action="CATALOGUE_INGESTED",
        resource_type="catalogue_software",
        resource_id=result["software"].id,
        result=AuditResult.SUCCESS,
        actor_type=ActorType.USER,
        actor_id=principal.user_id,
        source_ip=client_ip(request),
        metadata={
            "slug": slug,
            "sha256": result["sha256"],
            "filename": result["filename"],
            "policy": result["policy"],
            "kind": result["kind"],
            "team_id": result["team_id"],
            "manual_metadata": result["manual_metadata"],
        },
    )
    await db.commit()
    return {
        "slug": result["software"].slug,
        "display_name": result["software"].display_name,
        "sha256": result["sha256"],
        "package_size_bytes": result["package_size_bytes"],
        "filename": result["filename"],
        "staged_path": result["staged_path"],
        "policy": result["policy"],
        "software_id": str(result["software"].id),
    }


async def _iter_upload(package: UploadFile) -> AsyncIterator[bytes]:
    while chunk := await package.read(1024 * 1024):
        yield chunk
