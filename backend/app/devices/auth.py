"""Device authentication for `/api/v1/agent/*` (spec §12.3).

Agents authenticate with `Authorization: Bearer sdc_…`. Employee cookies are never accepted
on these routes, and every handler acts only on the authenticated device.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from fastapi import Depends, Request
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import service as audit
from app.auth.dependencies import client_ip
from app.auth.tokens import hash_token
from app.core.errors import AppError
from app.db.enums import ActorType, AuditResult, DeviceStatus
from app.db.session import get_session
from app.devices.credentials import CREDENTIAL_PREFIX, well_formed
from app.devices.models import Device, DeviceCredential

_TOUCH_INTERVAL = timedelta(seconds=60)


@dataclass(frozen=True)
class DeviceContext:
    device: Device
    credential: DeviceCredential


def _bearer(request: Request) -> str | None:
    header = request.headers.get("authorization", "")
    scheme, _, value = header.partition(" ")
    if scheme.lower() != "bearer" or not well_formed(value.strip(), CREDENTIAL_PREFIX):
        return None
    return value.strip()


async def get_device(
    request: Request,
    db: AsyncSession = Depends(get_session),  # noqa: B008
) -> DeviceContext:
    secret = _bearer(request)
    if secret is None:
        raise AppError("DEVICE_UNAUTHENTICATED", 401)
    now = datetime.now(UTC)
    row = (
        await db.execute(
            select(DeviceCredential, Device)
            .join(Device, Device.id == DeviceCredential.device_id)
            .where(DeviceCredential.credential_hash == hash_token(secret))
            .with_for_update(of=DeviceCredential)
        )
    ).first()
    if row is None:
        raise AppError("DEVICE_UNAUTHENTICATED", 401)
    credential, device = row[0], row[1]
    if credential.revoked_at is not None or credential.expires_at <= now:
        await audit.record(
            db,
            action="DEVICE_AUTH_FAILED",
            resource_type="device",
            resource_id=device.id,
            result=AuditResult.DENIED,
            actor_type=ActorType.DEVICE,
            actor_id=device.id,
            reason_code="CREDENTIAL_REVOKED" if credential.revoked_at else "CREDENTIAL_EXPIRED",
            source_ip=client_ip(request),
        )
        await db.commit()
        raise AppError("DEVICE_UNAUTHENTICATED", 401)
    if device.device_status != DeviceStatus.ACTIVE:
        raise AppError("DEVICE_NOT_ACTIVE", 403)
    if credential.last_used_at is None:
        # First use of a rotated credential proves the agent stored it; retire the others.
        await db.execute(
            update(DeviceCredential)
            .where(
                DeviceCredential.device_id == device.id,
                DeviceCredential.id != credential.id,
                DeviceCredential.revoked_at.is_(None),
            )
            .values(revoked_at=now)
        )
    if credential.last_used_at is None or now - credential.last_used_at >= _TOUCH_INTERVAL:
        credential.last_used_at = now
    return DeviceContext(device, credential)
