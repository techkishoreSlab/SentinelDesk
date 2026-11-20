"""Software-admin catalogue management (spec §12.2)."""

from __future__ import annotations

import uuid
from typing import Any, Literal

from fastapi import APIRouter, Depends, File, Form, Query, Request, UploadFile
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import service as audit
from app.auth.dependencies import Principal, client_ip, require
from app.auth.rbac import Permission
from app.catalogue import service as catalogue
from app.catalogue.ingest import ingest_package
from app.catalogue.models import CatalogueSoftware
from app.catalogue.schemas import (
    CreateSoftware,
    CreateVersion,
    PatchVersion,
    SoftwareDetail,
    SoftwareSummary,
    VersionOut,
)
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
    """One-step add: upload a .pkg or paste an https URL. SHA-256/size computed server-side."""
    settings = get_settings()
    alias_list = [a.strip() for a in aliases.split(",") if a.strip()][:20]
    try:
        arch = Architecture(architecture)
    except ValueError as exc:
        raise AppError("VALIDATION_ERROR", 422, {"field": "architecture"}) from exc

    upload_name = None
    upload_bytes = None
    if package is not None and package.filename:
        upload_name = package.filename
        upload_bytes = await package.read()

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
        upload_bytes=upload_bytes,
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
        },
    )
    await db.commit()
    return {
        "slug": slug,
        "display_name": display_name,
        "sha256": result["sha256"],
        "package_size_bytes": result["package_size_bytes"],
        "filename": result["filename"],
        "staged_path": result["staged_path"],
        "policy": result["policy"],
        "software_id": str(result["software"].id),
    }
