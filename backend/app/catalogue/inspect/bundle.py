"""Shared .app bundle reading for ZIP and DMG containers."""

from __future__ import annotations

import plistlib
from collections.abc import Callable
from typing import Any
from xml.parsers.expat import ExpatError

from app.catalogue.inspect.macho import parse_macho
from app.catalogue.inspect.result import (
    IDENTIFIER_RE,
    InspectError,
    Inspection,
    clean_min_os,
    clean_text,
    clean_version,
)
from app.catalogue.schemas import PAYLOAD_NAME

MAX_PLIST_BYTES = 1024 * 1024
MAX_EXECUTABLE_BYTES = 64 * 1024 * 1024

# Reads one member by its path relative to the container root. Returns None when missing.
Reader = Callable[[str, int], bytes | None]


def parse_info_plist(raw: bytes | None) -> dict[str, Any]:
    if raw is None:
        raise InspectError("APP_INFO_MISSING")
    try:
        data = plistlib.loads(raw)
    except (plistlib.InvalidFileException, ExpatError, ValueError, OverflowError) as exc:
        raise InspectError("APP_INFO_UNREADABLE") from exc
    if not isinstance(data, dict):
        raise InspectError("APP_INFO_UNREADABLE")
    return data


def bundle_version(info: dict[str, Any]) -> str | None:
    """Same precedence the endpoint uses: short version, then build version."""
    return clean_version(info.get("CFBundleShortVersionString")) or clean_version(
        info.get("CFBundleVersion")
    )


def inspect_app(app_name: str, kind: str, read: Reader, prefix: str = "") -> Inspection:
    if not PAYLOAD_NAME.fullmatch(app_name) or not app_name.endswith(".app"):
        raise InspectError("PAYLOAD_NAME_REJECTED")
    base = f"{prefix}{app_name}/Contents"
    info = parse_info_plist(read(f"{base}/Info.plist", MAX_PLIST_BYTES))
    warnings: list[str] = []

    identifier = clean_text(info.get("CFBundleIdentifier"), 200)
    if not IDENTIFIER_RE.fullmatch(identifier):
        raise InspectError("IDENTIFIER_UNREADABLE")
    version = bundle_version(info)
    if version is None:
        raise InspectError("VERSION_UNREADABLE")
    name = (
        clean_text(info.get("CFBundleDisplayName"), 120)
        or clean_text(info.get("CFBundleName"), 120)
        or app_name.removesuffix(".app")
    )
    min_os = clean_min_os(info.get("LSMinimumSystemVersion"), warnings)

    executable = clean_text(info.get("CFBundleExecutable"), 200)
    if not executable or "/" in executable or executable.startswith("."):
        raise InspectError("APP_EXECUTABLE_MISSING")
    binary = read(f"{base}/MacOS/{executable}", MAX_EXECUTABLE_BYTES)
    if binary is None:
        raise InspectError("APP_EXECUTABLE_MISSING")
    macho = parse_macho(binary)
    if macho is None or macho.architecture is None:
        raise InspectError("ARCH_UNREADABLE")
    if macho.adhoc or macho.team_id is None:
        raise InspectError("UNSIGNED_APP")

    signer = macho.signer
    if signer is None:
        warnings.append("SIGNER_CERT_UNREADABLE")
    elif signer.team_id != macho.team_id:
        raise InspectError("TEAM_ID_MISMATCH")
    elif not signer.developer_id:
        warnings.append("NOT_DEVELOPER_ID")

    return Inspection(
        kind=kind,
        name=name,
        version=version,
        identifier=identifier,
        architecture=macho.architecture,
        minimum_os_version=min_os,
        team_id=macho.team_id,
        publisher=signer.organisation if signer else "",
        signer=signer.common_name if signer else f"Developer ID Application ({macho.team_id})",
        payload_path=app_name,
        warnings=warnings,
    )
