"""Devices visible to the current user. Ownership is enforced on every lookup (IDOR)."""

from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import Principal, require
from app.auth.rbac import Permission
from app.core.errors import AppError
from app.db.session import get_session
from app.devices.models import Device

router = APIRouter(prefix="/api/v1/devices", tags=["devices"])


class DeviceOut(BaseModel):
    id: uuid.UUID
    device_name: str
    os_family: str
    os_version: str
    architecture: str
    agent_version: str
    device_status: str
    last_seen_at: datetime | None
    enrolled_at: datetime | None


def _out(d: Device) -> DeviceOut:
    return DeviceOut(
        id=d.id,
        device_name=d.device_name,
        os_family=d.os_family,
        os_version=d.os_version,
        architecture=d.architecture,
        agent_version=d.agent_version,
        device_status=d.device_status,
        last_seen_at=d.last_seen_at,
        enrolled_at=d.enrolled_at,
    )


@router.get("", response_model=list[DeviceOut])
async def list_own_devices(
    principal: Principal = Depends(require(Permission.DEVICE_READ_OWN)),  # noqa: B008
    db: AsyncSession = Depends(get_session),  # noqa: B008
) -> list[DeviceOut]:
    rows = await db.scalars(
        select(Device)
        .where(Device.owner_user_id == principal.user_id)
        .order_by(Device.device_name)
        .limit(100)
    )
    return [_out(d) for d in rows.all()]


@router.get("/{device_id}", response_model=DeviceOut)
async def get_own_device(
    device_id: uuid.UUID,
    principal: Principal = Depends(require(Permission.DEVICE_READ_OWN)),  # noqa: B008
    db: AsyncSession = Depends(get_session),  # noqa: B008
) -> DeviceOut:
    # Another user's device returns 404, not 403, so device IDs cannot be probed.
    device = await db.scalar(
        select(Device).where(Device.id == device_id, Device.owner_user_id == principal.user_id)
    )
    if device is None:
        raise AppError("NOT_FOUND", 404)
    return _out(device)
