"""Simple catalogue ingest: upload or URL → auto SHA-256 + staged package (Mac demo/prod)."""

from __future__ import annotations

import hashlib
import re
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.catalogue.models import CatalogueSoftware, SoftwarePolicy
from app.catalogue.schemas import CreateSoftware, CreateVersion
from app.catalogue.service import create_software, create_version, software_detail
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

_SAFE_NAME = re.compile(r"^[A-Za-z0-9._+\-]{1,180}\.pkg$")
_SLUG = re.compile(r"^[a-z0-9][a-z0-9-]{1,63}$")
_MAX_BYTES = 200 * 1024 * 1024


def package_store(settings: Settings) -> Path:
    path = Path(settings.package_store_dir)
    path.mkdir(parents=True, exist_ok=True)
    return path


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


def _sha256_file(path: Path) -> tuple[str, int]:
    h = hashlib.sha256()
    size = 0
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > _MAX_BYTES:
                raise AppError("VALIDATION_ERROR", 422, {"field": "package", "reason": "too_large"})
            h.update(chunk)
    return h.hexdigest(), size


async def _download_url(url: str, dest: Path) -> tuple[str, int]:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise AppError("VALIDATION_ERROR", 422, {"field": "source_url", "reason": "https_required"})
    h = hashlib.sha256()
    size = 0
    async with (
        httpx.AsyncClient(timeout=120.0, follow_redirects=True) as client,
        client.stream("GET", url) as resp,
    ):
        if resp.status_code >= 400:
            raise AppError("SERVICE_UNAVAILABLE", 503, {"field": "source_url"})
        with dest.open("wb") as fh:
            async for chunk in resp.aiter_bytes():
                size += len(chunk)
                if size > _MAX_BYTES:
                    dest.unlink(missing_ok=True)
                    raise AppError(
                        "VALIDATION_ERROR", 422, {"field": "package", "reason": "too_large"}
                    )
                fh.write(chunk)
                h.update(chunk)
    return h.hexdigest(), size


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
    upload_bytes: bytes | None,
) -> dict[str, Any]:
    if not _SLUG.fullmatch(slug):
        raise AppError("VALIDATION_ERROR", 422, {"field": "slug"})
    store = package_store(settings)

    if upload_bytes is not None and upload_name:
        filename = _safe_filename(upload_name)
        dest = store / filename
        if len(upload_bytes) > _MAX_BYTES:
            raise AppError("VALIDATION_ERROR", 422, {"field": "package", "reason": "too_large"})
        dest.write_bytes(upload_bytes)
        sha256, size = _sha256_file(dest)
        # Agent resolves basename under SENTINEL_PACKAGE_DIR (cached path).
        source_reference = f"https://packages.sentineldesk.local/{filename}"
    elif source_url:
        filename = _safe_filename(Path(urlparse(source_url).path).name or "package.pkg")
        dest = store / filename
        sha256, size = await _download_url(source_url, dest)
        source_reference = source_url
    else:
        raise AppError("VALIDATION_ERROR", 422, {"field": "package", "reason": "missing_source"})

    existing = await db.scalar(select(CatalogueSoftware).where(CatalogueSoftware.slug == slug))
    if existing is None:
        software = await create_software(
            db,
            CreateSoftware(
                slug=slug,
                display_name=display_name,
                description=f"Ingested package {filename}",
                publisher=publisher,
                category="developer-tools",
                risk_level=RiskLevel.LOW,
                aliases=aliases,
            ),
        )
    else:
        software = existing

    await create_version(
        db,
        CreateVersion(
            software_id=software.id,
            version=version,
            os_family=OsFamily.MACOS,
            architecture=architecture,
            minimum_os_version=minimum_os_version,
            minimum_memory_bytes=512 * 1024**2,
            minimum_disk_bytes=200 * 1024**2,
            installer_type=InstallerType.MACOS_PKG,
            source_type=SourceType.INTERNAL_ARTIFACT_STORE,
            source_reference=source_reference,
            package_identifier=package_identifier,
            verification_method=VerificationMethod.MACOS_PKG_RECEIPT,
            sha256=sha256,
            signature_publisher=publisher,
            signature_required=True,
            package_size_bytes=size,
            release_status=LifecycleStatus.ACTIVE,
        ),
    )
    software.lifecycle_status = LifecycleStatus.ACTIVE.value

    policy_row = await db.scalar(
        select(SoftwarePolicy).where(
            SoftwarePolicy.software_id == software.id,
            SoftwarePolicy.effective_to.is_(None),
        )
    )
    if policy_row is None:
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
                auto_approve_eligible=not require_approval and decision == PolicyDecision.ALLOW,
                policy_revision=(latest or 0) + 1,
                reason="Ingested via admin wizard (production default: require approval).",
                created_by=actor_id,
            )
        )

    pin_digest(settings, sha256)
    detail = await software_detail(db, software)
    return {
        "software": detail,
        "staged_path": str(dest),
        "sha256": sha256,
        "package_size_bytes": size,
        "filename": filename,
        "source_reference": source_reference,
        "policy": "REQUIRE_APPROVAL" if require_approval else "ALLOW",
    }
