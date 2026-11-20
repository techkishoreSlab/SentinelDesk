"""Catalogue normalization, version compare and compatibility evaluator (no DB)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.catalogue.compatibility import (
    REASON_ALREADY_INSTALLED,
    REASON_ARCH_UNSUPPORTED,
    REASON_COMPATIBLE,
    REASON_DEVICE_NOT_ACTIVE,
    REASON_DEVICE_STALE,
    REASON_INSUFFICIENT_DISK,
    REASON_OS_UNSUPPORTED,
    REASON_OS_VERSION_TOO_OLD,
    REASON_PACKAGE_METADATA_INCOMPLETE,
    DeviceSnapshot,
    PackageSnapshot,
    evaluate,
    mandatory_fields_complete,
)
from app.catalogue.normalize import normalize_alias, slug_candidate
from app.catalogue.versions import meets_minimum, parse_version


def _pkg(**overrides: object) -> PackageSnapshot:
    base = {
        "software_lifecycle": "ACTIVE",
        "release_status": "ACTIVE",
        "os_family": "macos",
        "architecture": "x86_64",
        "minimum_os_version": "13.0",
        "minimum_memory_bytes": 2 * 1024**3,
        "minimum_disk_bytes": 500 * 1024**2,
        "installer_type": "MACOS_PKG",
        "source_type": "INTERNAL_ARTIFACT_STORE",
        "source_reference": "artifact://demo/x",
        "sha256": "a" * 64,
        "signature_publisher": "Demo Publisher",
        "signature_required": True,
        "verification_method": "MACOS_APP_BUNDLE",
        "package_identifier": "com.example.App",
        "version": "1.0.0",
    }
    base.update(overrides)
    return PackageSnapshot(**base)  # type: ignore[arg-type]


def _device(**overrides: object) -> DeviceSnapshot:
    base = {
        "enrolled": True,
        "status": "ACTIVE",
        "last_seen_at": datetime.now(UTC),
        "os_family": "macos",
        "os_version": "26.5",
        "architecture": "x86_64",
        "memory_total_bytes": 16 * 1024**3,
        "disk_free_bytes": 80 * 1024**3,
        "installed_software": [],
    }
    base.update(overrides)
    return DeviceSnapshot(**base)  # type: ignore[arg-type]


def test_normalize_alias_collapses_punctuation_and_case() -> None:
    assert normalize_alias("Visual Studio Code") == "visual studio code"
    assert normalize_alias("  VS-Code!! ") == "vs code"
    assert normalize_alias("Git") == "git"
    assert slug_candidate("Visual Studio Code") == "visual-studio-code"


def test_version_compare() -> None:
    assert parse_version("26.5") == (26, 5)
    assert parse_version("1.138.0") == (1, 138, 0)
    assert parse_version("1.0-beta") is None
    assert meets_minimum("26.5", "13.0") is True
    assert meets_minimum("12.9", "13.0") is False
    assert meets_minimum("bad", "13.0") is None


def test_mandatory_fields_reject_incomplete_packages() -> None:
    assert mandatory_fields_complete(_pkg()) is True
    assert mandatory_fields_complete(_pkg(sha256=None)) is False
    assert mandatory_fields_complete(_pkg(release_status="PENDING_REVIEW")) is False
    assert mandatory_fields_complete(_pkg(source_reference="")) is False


def test_compatibility_happy_path() -> None:
    result = evaluate(_device(), _pkg(), stale_after=timedelta(minutes=15))
    assert result.compatible is True
    assert result.reason_code == REASON_COMPATIBLE


def test_compatibility_blocks_in_spec_order() -> None:
    stale = evaluate(
        _device(last_seen_at=datetime.now(UTC) - timedelta(hours=2)),
        _pkg(),
        stale_after=timedelta(minutes=15),
    )
    assert stale.reason_code == REASON_DEVICE_STALE

    quarantined = evaluate(_device(status="QUARANTINED"), _pkg(), stale_after=timedelta(minutes=15))
    assert quarantined.reason_code == REASON_DEVICE_NOT_ACTIVE

    incomplete = evaluate(
        _device(), _pkg(sha256=None, release_status="ACTIVE"), stale_after=timedelta(minutes=15)
    )
    assert incomplete.reason_code == REASON_PACKAGE_METADATA_INCOMPLETE

    os_miss = evaluate(_device(), _pkg(os_family="windows"), stale_after=timedelta(minutes=15))
    assert os_miss.reason_code == REASON_OS_UNSUPPORTED

    arch = evaluate(_device(), _pkg(architecture="arm64"), stale_after=timedelta(minutes=15))
    assert arch.reason_code == REASON_ARCH_UNSUPPORTED

    universal = evaluate(
        _device(), _pkg(architecture="universal"), stale_after=timedelta(minutes=15)
    )
    assert universal.compatible is True

    old = evaluate(_device(os_version="12.0"), _pkg(), stale_after=timedelta(minutes=15))
    assert old.reason_code == REASON_OS_VERSION_TOO_OLD

    disk = evaluate(
        _device(disk_free_bytes=10),
        _pkg(minimum_disk_bytes=1000),
        stale_after=timedelta(minutes=15),
    )
    assert disk.reason_code == REASON_INSUFFICIENT_DISK

    installed = evaluate(
        _device(
            installed_software=[
                {"identifier": "com.example.App", "version": "1.0.0", "source": "app_bundle"}
            ]
        ),
        _pkg(),
        stale_after=timedelta(minutes=15),
    )
    assert installed.reason_code == REASON_ALREADY_INSTALLED
    assert installed.compatible is False
