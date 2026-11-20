"""Device credentials and enrollment tokens (spec §9.9, §11.1).

Secrets are random, shown exactly once, and stored only as SHA-256 hashes. A credential is
bound to one device; there is no shared fleet secret.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.tokens import hash_token, new_token
from app.core.config import Settings
from app.devices.models import DeviceCredential

CREDENTIAL_PREFIX = "sdc_"
ENROLLMENT_PREFIX = "sde_"
# Prefix + urlsafe base64 of 32 bytes (43 chars). Anything else is rejected before hashing.
SECRET_LENGTH = 4 + 43
ROTATE_WITHIN = timedelta(days=7)


def new_enrollment_secret() -> str:
    return ENROLLMENT_PREFIX + new_token(32)


def well_formed(secret: str, prefix: str) -> bool:
    return len(secret) == SECRET_LENGTH and secret.startswith(prefix)


@dataclass(frozen=True)
class IssuedCredential:
    credential: DeviceCredential
    secret: str


async def issue_credential(
    db: AsyncSession, settings: Settings, device_id: uuid.UUID
) -> IssuedCredential:
    secret = CREDENTIAL_PREFIX + new_token(32)
    row = DeviceCredential(
        device_id=device_id,
        credential_hash=hash_token(secret),
        expires_at=datetime.now(UTC) + timedelta(days=settings.device_credential_ttl_days),
    )
    db.add(row)
    await db.flush()
    return IssuedCredential(row, secret)


async def revoke_device_credentials(db: AsyncSession, device_id: uuid.UUID) -> int:
    result = await db.execute(
        update(DeviceCredential)
        .where(DeviceCredential.device_id == device_id, DeviceCredential.revoked_at.is_(None))
        .values(revoked_at=datetime.now(UTC))
    )
    return int(result.rowcount)  # type: ignore[attr-defined]
