"""Deterministic device/package compatibility (spec section 8.2 steps 1-8).

Security checks and approval policy are Phase 5 and are intentionally not evaluated here.
A hard failure returns the first blocking reason; successes may still note ALREADY_INSTALLED.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from app.catalogue.versions import meets_minimum
from app.db.enums import DeviceStatus, LifecycleStatus

# Ordered evaluation codes from spec §8.2.
REASON_DEVICE_NOT_ENROLLED = "DEVICE_NOT_ENROLLED"
REASON_DEVICE_NOT_ACTIVE = "DEVICE_NOT_ACTIVE"
REASON_DEVICE_STALE = "DEVICE_STALE"
REASON_OS_UNSUPPORTED = "OS_UNSUPPORTED"
REASON_ARCH_UNSUPPORTED = "ARCH_UNSUPPORTED"
REASON_OS_VERSION_TOO_OLD = "OS_VERSION_TOO_OLD"
REASON_INSUFFICIENT_MEMORY = "INSUFFICIENT_MEMORY"
REASON_INSUFFICIENT_DISK = "INSUFFICIENT_DISK"
REASON_PACKAGE_NOT_APPROVED = "PACKAGE_NOT_APPROVED"
REASON_PACKAGE_METADATA_INCOMPLETE = "PACKAGE_METADATA_INCOMPLETE"
REASON_ALREADY_INSTALLED = "ALREADY_INSTALLED"
REASON_COMPATIBLE = "COMPATIBLE"


@dataclass(frozen=True, slots=True)
class DeviceSnapshot:
    """Facts needed for compatibility. Ownership is enforced by the caller."""

    enrolled: bool
    status: str | None
    last_seen_at: datetime | None
    os_family: str | None
    os_version: str | None
    architecture: str | None
    memory_total_bytes: int | None
    disk_free_bytes: int | None
    installed_software: list[dict[str, Any]] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class PackageSnapshot:
    software_lifecycle: str
    release_status: str
    os_family: str
    architecture: str
    minimum_os_version: str | None
    minimum_memory_bytes: int | None
    minimum_disk_bytes: int | None
    installer_type: str | None
    source_type: str | None
    source_reference: str | None
    sha256: str | None
    signature_publisher: str | None
    signature_required: bool
    verification_method: str | None
    package_identifier: str | None
    version: str


@dataclass(frozen=True, slots=True)
class CompatibilityResult:
    compatible: bool
    reason_code: str
    details: dict[str, Any] = field(default_factory=dict)


def mandatory_fields_complete(package: PackageSnapshot) -> bool:
    """Every field in spec §8.1 that makes a package installable."""
    if package.release_status != LifecycleStatus.ACTIVE.value:
        return False
    if package.software_lifecycle != LifecycleStatus.ACTIVE.value:
        return False
    required: list[object] = [
        package.os_family,
        package.architecture,
        package.minimum_os_version,
        package.installer_type,
        package.source_type,
        package.source_reference,
        package.sha256,
        package.signature_publisher,
        package.verification_method,
        package.package_identifier,
        package.version,
    ]
    if any(v is None or v == "" for v in required):
        return False
    if package.minimum_memory_bytes is None or package.minimum_disk_bytes is None:
        return False
    return not (package.signature_required and not package.signature_publisher)


def _installed_match(package: PackageSnapshot, installed: list[dict[str, Any]]) -> bool:
    if not package.package_identifier:
        return False
    target = package.package_identifier.casefold()
    for item in installed:
        identifier = item.get("identifier")
        version = item.get("version")
        if not isinstance(identifier, str) or not isinstance(version, str):
            continue
        if identifier.casefold() == target and version == package.version:
            return True
    return False


def evaluate(
    device: DeviceSnapshot,
    package: PackageSnapshot,
    *,
    now: datetime | None = None,
    stale_after: timedelta,
) -> CompatibilityResult:
    now = now or datetime.now(UTC)

    if not device.enrolled or device.status is None:
        return CompatibilityResult(False, REASON_DEVICE_NOT_ENROLLED)
    if device.status != DeviceStatus.ACTIVE.value:
        return CompatibilityResult(
            False, REASON_DEVICE_NOT_ACTIVE, {"device_status": device.status}
        )
    if device.last_seen_at is None or now - device.last_seen_at > stale_after:
        return CompatibilityResult(False, REASON_DEVICE_STALE)

    if not mandatory_fields_complete(package):
        return CompatibilityResult(False, REASON_PACKAGE_METADATA_INCOMPLETE)
    if (
        package.release_status != LifecycleStatus.ACTIVE.value
        or package.software_lifecycle != LifecycleStatus.ACTIVE.value
    ):
        return CompatibilityResult(False, REASON_PACKAGE_NOT_APPROVED)

    if device.os_family != package.os_family:
        return CompatibilityResult(
            False,
            REASON_OS_UNSUPPORTED,
            {"device": device.os_family, "package": package.os_family},
        )

    # universal package architecture matches any device arch of the same OS family.
    if package.architecture != "universal" and device.architecture != package.architecture:
        return CompatibilityResult(
            False,
            REASON_ARCH_UNSUPPORTED,
            {"device": device.architecture, "package": package.architecture},
        )

    if package.minimum_os_version:
        ok = meets_minimum(device.os_version or "", package.minimum_os_version)
        if ok is not True:
            return CompatibilityResult(
                False,
                REASON_OS_VERSION_TOO_OLD,
                {
                    "device": device.os_version,
                    "minimum": package.minimum_os_version,
                    "unparseable": ok is None,
                },
            )

    if package.minimum_memory_bytes is not None and (
        device.memory_total_bytes is None
        or device.memory_total_bytes < package.minimum_memory_bytes
    ):
        return CompatibilityResult(
            False,
            REASON_INSUFFICIENT_MEMORY,
            {
                "device": device.memory_total_bytes,
                "minimum": package.minimum_memory_bytes,
            },
        )

    if package.minimum_disk_bytes is not None and (
        device.disk_free_bytes is None or device.disk_free_bytes < package.minimum_disk_bytes
    ):
        return CompatibilityResult(
            False,
            REASON_INSUFFICIENT_DISK,
            {"device": device.disk_free_bytes, "minimum": package.minimum_disk_bytes},
        )

    if _installed_match(package, device.installed_software):
        return CompatibilityResult(
            False,
            REASON_ALREADY_INSTALLED,
            {"package_identifier": package.package_identifier, "version": package.version},
        )

    return CompatibilityResult(True, REASON_COMPATIBLE)
