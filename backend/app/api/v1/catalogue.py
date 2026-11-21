"""Employee-facing catalogue search and device compatibility (spec §12.1, §8.2)."""

from __future__ import annotations

import uuid
from datetime import timedelta

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import Principal, require
from app.auth.rbac import Permission
from app.catalogue import service as catalogue
from app.catalogue.compatibility import device_snapshot_from, evaluate
from app.catalogue.models import CatalogueSoftware
from app.catalogue.schemas import (
    CompatibilityOut,
    CompatibilityRequest,
    SearchHit,
    SoftwareDetail,
    SoftwareSummary,
)
from app.core.config import Settings
from app.core.errors import AppError
from app.db.enums import LifecycleStatus
from app.db.session import get_session
from app.devices.models import Device, DeviceFacts

router = APIRouter(prefix="/api/v1/catalogue", tags=["catalogue"])


def get_settings_from(request: Request) -> Settings:
    settings: Settings = request.app.state.settings
    return settings


@router.get("/search", response_model=list[SearchHit])
async def search_catalogue(
    q: str = Query(min_length=1, max_length=120),
    _: Principal = Depends(require(Permission.CATALOGUE_READ)),  # noqa: B008
    db: AsyncSession = Depends(get_session),  # noqa: B008
    limit: int = Query(default=20, ge=1, le=50),
) -> list[SearchHit]:
    hits = await catalogue.search_approved(db, q, limit=limit)
    if not hits:
        return []
    alias_map = await catalogue.aliases_for(db, [s.id for s, _, _ in hits])
    return [
        SearchHit(
            software=catalogue.software_summary(software, alias_map.get(software.id, [])),
            matched_alias=matched,
            active_versions=[catalogue.version_out(software, v) for v in versions],
        )
        for software, matched, versions in hits
    ]


@router.get("/software", response_model=list[SoftwareSummary])
async def list_active_software(
    _: Principal = Depends(require(Permission.CATALOGUE_READ)),  # noqa: B008
    db: AsyncSession = Depends(get_session),  # noqa: B008
    limit: int = Query(default=50, ge=1, le=100),
) -> list[SoftwareSummary]:
    rows = (
        await db.scalars(
            select(CatalogueSoftware)
            .where(CatalogueSoftware.lifecycle_status == LifecycleStatus.ACTIVE.value)
            .order_by(CatalogueSoftware.display_name)
            .limit(limit)
        )
    ).all()
    alias_map = await catalogue.aliases_for(db, [r.id for r in rows])
    return [catalogue.software_summary(r, alias_map.get(r.id, [])) for r in rows]


@router.get("/software/{software_id}", response_model=SoftwareDetail)
async def get_software(
    software_id: uuid.UUID,
    _: Principal = Depends(require(Permission.CATALOGUE_READ)),  # noqa: B008
    db: AsyncSession = Depends(get_session),  # noqa: B008
) -> SoftwareDetail:
    software = await catalogue.get_software(db, software_id)
    if software.lifecycle_status != LifecycleStatus.ACTIVE.value:
        raise AppError("NOT_FOUND", 404)
    return await catalogue.software_detail(db, software)


@router.post("/compatibility", response_model=CompatibilityOut)
async def check_compatibility(
    body: CompatibilityRequest,
    request: Request,
    principal: Principal = Depends(require(Permission.CATALOGUE_READ)),  # noqa: B008
    db: AsyncSession = Depends(get_session),  # noqa: B008
) -> CompatibilityOut:
    settings = get_settings_from(request)
    device = await db.scalar(
        select(Device).where(Device.id == body.device_id, Device.owner_user_id == principal.user_id)
    )
    if device is None:
        raise AppError("NOT_FOUND", 404)

    version = await catalogue.get_version(db, body.catalogue_version_id)
    software = await catalogue.get_software(db, version.software_id)
    facts = await db.scalar(
        select(DeviceFacts)
        .where(DeviceFacts.device_id == device.id)
        .order_by(DeviceFacts.collected_at.desc())
        .limit(1)
    )
    snapshot = device_snapshot_from(device, facts)
    result = evaluate(
        snapshot,
        catalogue.package_snapshot(software, version),
        stale_after=timedelta(seconds=settings.device_stale_after_seconds),
    )
    return CompatibilityOut(
        compatible=result.compatible,
        reason_code=result.reason_code,
        details=result.details,
        software_id=software.id,
        software_slug=software.slug,
        software_display_name=software.display_name,
        catalogue_version_id=version.id,
        version=version.version,
    )
