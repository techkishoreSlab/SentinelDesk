"""Synthetic demo catalogue (spec section 19).

Digests are SHA-256 of fixed demo labels, not real package bytes.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.catalogue.models import CatalogueSoftware, CatalogueVersion, SoftwareAlias
from app.catalogue.normalize import normalize_alias
from app.db.enums import (
    Architecture,
    InstallerType,
    LifecycleStatus,
    OsFamily,
    RiskLevel,
    SourceType,
    VerificationMethod,
)


def demo_digest(label: str) -> str:
    return hashlib.sha256(f"sentineldesk-demo::{label}".encode()).hexdigest()


@dataclass(frozen=True)
class SeedVersion:
    version: str
    os_family: OsFamily
    architecture: Architecture
    minimum_os_version: str
    minimum_memory_bytes: int
    minimum_disk_bytes: int
    installer_type: InstallerType
    source_type: SourceType
    source_reference: str
    package_identifier: str
    verification_method: VerificationMethod
    digest_label: str
    signature_publisher: str
    package_size_bytes: int
    release_status: LifecycleStatus = LifecycleStatus.ACTIVE
    # When set, used as catalogue sha256 instead of demo_digest(digest_label).
    sha256_hex: str | None = None


@dataclass(frozen=True)
class SeedSoftware:
    slug: str
    display_name: str
    description: str
    publisher: str
    category: str
    risk_level: RiskLevel
    lifecycle_status: LifecycleStatus
    aliases: tuple[str, ...]
    versions: tuple[SeedVersion, ...]


DEMO_CATALOGUE: tuple[SeedSoftware, ...] = (
    SeedSoftware(
        slug="visual-studio-code",
        display_name="Visual Studio Code",
        description="Approved editor for the SentinelDesk demo (synthetic package metadata).",
        publisher="Microsoft",
        category="developer-tools",
        risk_level=RiskLevel.LOW,
        lifecycle_status=LifecycleStatus.ACTIVE,
        aliases=("visual studio code", "vscode", "vs code", "code"),
        versions=(
            SeedVersion(
                version="1.138.0",
                os_family=OsFamily.MACOS,
                architecture=Architecture.X86_64,
                minimum_os_version="13.0",
                minimum_memory_bytes=2 * 1024**3,
                minimum_disk_bytes=500 * 1024**2,
                installer_type=InstallerType.MACOS_PKG,
                source_type=SourceType.INTERNAL_ARTIFACT_STORE,
                source_reference="artifact://demo/vscode/1.138.0/macos-x86_64",
                package_identifier="com.microsoft.VSCode",
                verification_method=VerificationMethod.MACOS_APP_BUNDLE,
                digest_label="vscode-1.138.0-macos-x86_64",
                signature_publisher="Developer ID Application: Microsoft Corporation",
                package_size_bytes=200 * 1024**2,
            ),
            SeedVersion(
                version="1.138.0",
                os_family=OsFamily.MACOS,
                architecture=Architecture.ARM64,
                minimum_os_version="13.0",
                minimum_memory_bytes=2 * 1024**3,
                minimum_disk_bytes=500 * 1024**2,
                installer_type=InstallerType.MACOS_PKG,
                source_type=SourceType.INTERNAL_ARTIFACT_STORE,
                source_reference="artifact://demo/vscode/1.138.0/macos-arm64",
                package_identifier="com.microsoft.VSCode",
                verification_method=VerificationMethod.MACOS_APP_BUNDLE,
                digest_label="vscode-1.138.0-macos-arm64",
                signature_publisher="Developer ID Application: Microsoft Corporation",
                package_size_bytes=190 * 1024**2,
            ),
        ),
    ),
    SeedSoftware(
        slug="git",
        display_name="Git",
        description="Distributed version control. Demo policy will require approval in Phase 5.",
        publisher="Software Freedom Conservancy",
        category="developer-tools",
        risk_level=RiskLevel.LOW,
        lifecycle_status=LifecycleStatus.ACTIVE,
        aliases=("git", "git scm"),
        versions=(
            SeedVersion(
                version="2.50.0",
                os_family=OsFamily.MACOS,
                architecture=Architecture.X86_64,
                minimum_os_version="12.0",
                minimum_memory_bytes=512 * 1024**2,
                minimum_disk_bytes=100 * 1024**2,
                installer_type=InstallerType.MACOS_PKG,
                source_type=SourceType.INTERNAL_ARTIFACT_STORE,
                source_reference="artifact://demo/git/2.50.0/macos-x86_64",
                package_identifier="com.git.Git",
                verification_method=VerificationMethod.MACOS_PKG_RECEIPT,
                digest_label="git-2.50.0-macos-x86_64",
                signature_publisher="Developer ID Application: Git Project",
                package_size_bytes=50 * 1024**2,
            ),
        ),
    ),
    SeedSoftware(
        slug="github-cli",
        display_name="GitHub CLI",
        description="Official GitHub CLI macOS universal pkg (Phase 8 real-install candidate).",
        publisher="GitHub, Inc.",
        category="developer-tools",
        risk_level=RiskLevel.LOW,
        lifecycle_status=LifecycleStatus.ACTIVE,
        aliases=("github cli", "gh", "github-cli"),
        versions=(
            SeedVersion(
                version="2.104.0",
                os_family=OsFamily.MACOS,
                architecture=Architecture.UNIVERSAL,
                minimum_os_version="12.0",
                minimum_memory_bytes=512 * 1024**2,
                minimum_disk_bytes=100 * 1024**2,
                installer_type=InstallerType.MACOS_PKG,
                source_type=SourceType.INTERNAL_ARTIFACT_STORE,
                source_reference=(
                    "https://github.com/cli/cli/releases/download/v2.104.0/"
                    "gh_2.104.0_macOS_universal.pkg"
                ),
                package_identifier="com.github.cli",
                verification_method=VerificationMethod.MACOS_PKG_RECEIPT,
                digest_label="gh-2.104.0-macos-universal",
                signature_publisher="Developer ID Installer: GitHub, Inc.",
                package_size_bytes=28_841_135,
                sha256_hex="5a4dd756bd3dea06c39edcc8c97653d85198774d9991790b7221f08b42281df6",
            ),
        ),
    ),
    SeedSoftware(
        slug="golang",
        display_name="Go",
        description=(
            "Official Go toolchain macOS Intel pkg (go1.27.4). "
            "pkgutil receipt version is go1.27.4 (org.golang.go)."
        ),
        publisher="Google LLC",
        category="developer-tools",
        risk_level=RiskLevel.LOW,
        lifecycle_status=LifecycleStatus.ACTIVE,
        aliases=("go", "golang", "go lang"),
        versions=(
            SeedVersion(
                # Must match `pkgutil --pkg-info org.golang.go` → version: go1.27.4
                version="go1.27.4",
                os_family=OsFamily.MACOS,
                architecture=Architecture.X86_64,
                minimum_os_version="12.0",
                minimum_memory_bytes=512 * 1024**2,
                minimum_disk_bytes=200 * 1024**2,
                installer_type=InstallerType.MACOS_PKG,
                source_type=SourceType.INTERNAL_ARTIFACT_STORE,
                source_reference="https://go.dev/dl/go1.27.4.darwin-amd64.pkg",
                package_identifier="org.golang.go",
                verification_method=VerificationMethod.MACOS_PKG_RECEIPT,
                digest_label="go-1.27.4-macos-amd64",
                signature_publisher="Developer ID Installer: Google LLC",
                package_size_bytes=73_214_562,
                sha256_hex="98b6668684006873a3befee5cf155a110f79c3156ac718ddf45f59e4043a16b9",
            ),
        ),
    ),
    SeedSoftware(
        slug="restricted-remote-access",
        display_name="Restricted Remote Access Tool",
        description="Synthetic remote-access entry used to demonstrate organisational bans.",
        publisher="SentinelDesk Demo Fixtures",
        category="remote-access",
        risk_level=RiskLevel.HIGH,
        lifecycle_status=LifecycleStatus.ACTIVE,
        aliases=("restricted remote access tool", "demo remote access"),
        versions=(
            SeedVersion(
                version="9.9.9",
                os_family=OsFamily.MACOS,
                architecture=Architecture.X86_64,
                minimum_os_version="12.0",
                minimum_memory_bytes=512 * 1024**2,
                minimum_disk_bytes=50 * 1024**2,
                installer_type=InstallerType.MACOS_PKG,
                source_type=SourceType.INTERNAL_ARTIFACT_STORE,
                source_reference="artifact://demo/restricted-remote-access/9.9.9",
                package_identifier="com.sentineldesk.demo.RestrictedRemoteAccess",
                verification_method=VerificationMethod.MACOS_APP_BUNDLE,
                digest_label="restricted-remote-access-9.9.9",
                signature_publisher="Developer ID Application: SentinelDesk Demo",
                package_size_bytes=20 * 1024**2,
            ),
        ),
    ),
    SeedSoftware(
        slug="contoso-notepad-win",
        display_name="Contoso Notepad for Windows",
        description="Windows-only package used to demonstrate OS incompatibility on this Mac.",
        publisher="Contoso Demo",
        category="utilities",
        risk_level=RiskLevel.LOW,
        lifecycle_status=LifecycleStatus.ACTIVE,
        aliases=("contoso notepad", "contoso notepad for windows"),
        versions=(
            SeedVersion(
                version="1.0.0",
                os_family=OsFamily.WINDOWS,
                architecture=Architecture.X86_64,
                minimum_os_version="10.0",
                minimum_memory_bytes=512 * 1024**2,
                minimum_disk_bytes=50 * 1024**2,
                installer_type=InstallerType.MSI,
                source_type=SourceType.INTERNAL_ARTIFACT_STORE,
                source_reference="artifact://demo/contoso-notepad/1.0.0/win-x64",
                package_identifier="Contoso.Notepad",
                verification_method=VerificationMethod.WINGET_LIST,
                digest_label="contoso-notepad-1.0.0-win-x64",
                signature_publisher="Contoso Demo Publisher",
                package_size_bytes=10 * 1024**2,
            ),
        ),
    ),
    SeedSoftware(
        slug="demo-incomplete-editor",
        display_name="Demo Incomplete Editor",
        description="PENDING_REVIEW package; must never become installable as-is.",
        publisher="SentinelDesk Demo Fixtures",
        category="utilities",
        risk_level=RiskLevel.MEDIUM,
        lifecycle_status=LifecycleStatus.PENDING_REVIEW,
        aliases=("demo incomplete editor",),
        versions=(
            SeedVersion(
                version="0.0.1",
                os_family=OsFamily.MACOS,
                architecture=Architecture.X86_64,
                minimum_os_version="12.0",
                minimum_memory_bytes=512 * 1024**2,
                minimum_disk_bytes=50 * 1024**2,
                installer_type=InstallerType.MACOS_PKG,
                source_type=SourceType.INTERNAL_ARTIFACT_STORE,
                source_reference="artifact://demo/incomplete/0.0.1",
                package_identifier="com.sentineldesk.demo.IncompleteEditor",
                verification_method=VerificationMethod.MACOS_APP_BUNDLE,
                digest_label="incomplete-0.0.1",
                signature_publisher="SentinelDesk Demo",
                package_size_bytes=5 * 1024**2,
                release_status=LifecycleStatus.PENDING_REVIEW,
            ),
        ),
    ),
)


async def seed_catalogue(db: AsyncSession) -> dict[str, int]:
    created_software = created_versions = created_aliases = 0
    for item in DEMO_CATALOGUE:
        software = await db.scalar(
            select(CatalogueSoftware).where(CatalogueSoftware.slug == item.slug)
        )
        if software is None:
            software = CatalogueSoftware(
                slug=item.slug,
                display_name=item.display_name,
                description=item.description,
                publisher=item.publisher,
                category=item.category,
                lifecycle_status=item.lifecycle_status.value,
                risk_level=item.risk_level.value,
            )
            db.add(software)
            await db.flush()
            created_software += 1
        for alias_raw in item.aliases:
            alias = normalize_alias(alias_raw)
            exists = await db.scalar(
                select(SoftwareAlias).where(SoftwareAlias.alias_normalized == alias)
            )
            if exists is None:
                db.add(SoftwareAlias(software_id=software.id, alias_normalized=alias))
                created_aliases += 1
        for ver in item.versions:
            exists = await db.scalar(
                select(CatalogueVersion).where(
                    CatalogueVersion.software_id == software.id,
                    CatalogueVersion.version == ver.version,
                    CatalogueVersion.os_family == ver.os_family.value,
                    CatalogueVersion.architecture == ver.architecture.value,
                )
            )
            if exists is not None:
                continue
            db.add(
                CatalogueVersion(
                    software_id=software.id,
                    version=ver.version,
                    os_family=ver.os_family.value,
                    architecture=ver.architecture.value,
                    minimum_os_version=ver.minimum_os_version,
                    minimum_memory_bytes=ver.minimum_memory_bytes,
                    minimum_disk_bytes=ver.minimum_disk_bytes,
                    installer_type=ver.installer_type.value,
                    source_type=ver.source_type.value,
                    source_reference=ver.source_reference,
                    package_identifier=ver.package_identifier,
                    verification_method=ver.verification_method.value,
                    sha256=(ver.sha256_hex or demo_digest(ver.digest_label)).lower(),
                    signature_publisher=ver.signature_publisher,
                    signature_required=True,
                    package_size_bytes=ver.package_size_bytes,
                    release_status=ver.release_status.value,
                )
            )
            created_versions += 1
    await db.commit()
    return {
        "software": created_software,
        "versions": created_versions,
        "aliases": created_aliases,
    }
