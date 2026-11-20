"""Active banned-software matching (spec section 9.2)."""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.catalogue.models import BannedSoftware, CatalogueSoftware, CatalogueVersion
from app.catalogue.normalize import normalize_alias
from app.db.enums import BanMatchType


@dataclass(frozen=True, slots=True)
class BanHit:
    rule_id: uuid.UUID
    match_type: str
    reason_code: str
    public_message: str
    severity: str


async def find_ban(
    db: AsyncSession,
    *,
    software: CatalogueSoftware,
    version: CatalogueVersion,
) -> BanHit | None:
    """Return the first active matching ban. Exact matches only (no fuzzy malware claims)."""
    rules = (
        await db.scalars(select(BannedSoftware).where(BannedSoftware.active.is_(True)).limit(500))
    ).all()
    if not rules:
        return None

    candidates: dict[BanMatchType, set[str]] = {
        BanMatchType.CATALOGUE_ID: {str(software.id).lower(), software.slug.lower()},
        BanMatchType.PUBLISHER: {normalize_alias(software.publisher)},
        BanMatchType.PACKAGE_ID: set(),
        BanMatchType.HASH: set(),
        BanMatchType.SIGNING_ID: set(),
    }
    if version.package_identifier:
        candidates[BanMatchType.PACKAGE_ID].add(version.package_identifier.casefold())
    if version.sha256:
        candidates[BanMatchType.HASH].add(version.sha256.lower())
    if version.signature_publisher:
        candidates[BanMatchType.SIGNING_ID].add(normalize_alias(version.signature_publisher))

    for rule in rules:
        try:
            match_type = BanMatchType(rule.match_type)
        except ValueError:
            continue
        values = candidates.get(match_type, set())
        if rule.match_value in values:
            return BanHit(
                rule_id=rule.id,
                match_type=rule.match_type,
                reason_code=rule.reason_code,
                public_message=rule.public_message,
                severity=rule.severity,
            )
    return None
