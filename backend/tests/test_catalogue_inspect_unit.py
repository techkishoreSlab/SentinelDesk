"""Unit tests for DMG / ZIP / pkg inspection, the draft store, SSRF guards and presets (no DB)."""

from __future__ import annotations

import io
import plistlib
import stat
import struct
import time
import uuid
import zipfile
import zlib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from app.catalogue.compatibility import (
    REASON_ALREADY_INSTALLED,
    REASON_COMPATIBLE,
    REASON_INSTALLER_UNSUPPORTED,
    REASON_NEWER_VERSION_INSTALLED,
    REASON_PACKAGE_METADATA_INCOMPLETE,
    SATISFIED_REASONS,
    DeviceSnapshot,
    PackageSnapshot,
    evaluate,
)
from app.catalogue.inspect.detect import detect_container, extension_for
from app.catalogue.inspect.dmg import check_udif
from app.catalogue.inspect.macho import parse_macho
from app.catalogue.inspect.messages import HINTS, hint_for
from app.catalogue.inspect.pkg_xar import _safe_xml, inspect_pkg_stream
from app.catalogue.inspect.result import InspectError, Inspection
from app.catalogue.inspect.zip_app import inspect_zip
from app.catalogue.presets import PRESETS, get_preset, preset_url
from app.catalogue.store import (
    Draft,
    _blocked_ip,
    check_url_shape,
    commit_artifact,
    find_artifact,
    load_draft,
    new_draft_dir,
    purge_expired_drafts,
)
from app.jobs.service import build_envelope

TEAM = "W72HKFW6P5"

# ------------------------------------------------------------------ fixtures


def _code_directory(team: str | None, flags: int = 0) -> bytes:
    """Minimal CodeDirectory (version 0x20200) with an optional team identifier."""
    header_len = 52
    team_bytes = (team.encode() + b"\x00") if team else b""
    length = header_len + len(team_bytes)
    cd = bytearray(header_len)
    struct.pack_into(">IIII", cd, 0, 0xFADE0C02, length, 0x20200, flags)
    struct.pack_into(">I", cd, 48, header_len if team else 0)
    return bytes(cd) + team_bytes


def _superblob(team: str | None, flags: int = 0) -> bytes:
    cd = _code_directory(team, flags)
    offset = 12 + 8
    return struct.pack(">IIIII", 0xFADE0CC0, offset + len(cd), 1, 0, offset) + cd


def thin_macho(cputype: int, team: str | None = TEAM, flags: int = 0) -> bytes:
    sig = _superblob(team, flags)
    lc = struct.pack("<IIII", 0x1D, 16, 0, 0)
    header_len = 32 + len(lc)
    sig_off = header_len
    lc = struct.pack("<IIII", 0x1D, 16, sig_off, len(sig))
    header = struct.pack("<IiiIIIII", 0xFEEDFACF, cputype, 0, 2, 1, len(lc), 0, 0)
    return header + lc + sig


def fat_macho(*slices: bytes, cputypes: tuple[int, ...]) -> bytes:
    count = len(slices)
    offset = 8 + 20 * count
    table = b""
    body = b""
    for cpu, data in zip(cputypes, slices, strict=True):
        table += struct.pack(">iiIII", cpu, 0, offset + len(body), len(data), 0)
        body += data
    return struct.pack(">II", 0xCAFEBABE, count) + table + body


X86 = 0x01000007
ARM = 0x0100000C


def info_plist(**extra: Any) -> bytes:
    data = {
        "CFBundleIdentifier": "com.example.netron",
        "CFBundleShortVersionString": "9.0.8",
        "CFBundleExecutable": "Netron",
        "CFBundleName": "Netron",
        "LSMinimumSystemVersion": "12.0",
        **extra,
    }
    return plistlib.dumps(data)


def make_zip(path: Path, entries: dict[str, bytes], links: dict[str, str] | None = None) -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
        for name, target in (links or {}).items():
            info = zipfile.ZipInfo(name)
            info.create_system = 3
            info.external_attr = (stat.S_IFLNK | 0o755) << 16
            zf.writestr(info, target)
    return path


def app_entries(binary: bytes, app: str = "Netron.app") -> dict[str, bytes]:
    return {
        f"{app}/Contents/Info.plist": info_plist(),
        f"{app}/Contents/MacOS/Netron": binary,
    }


def make_xar(toc_xml: bytes, heap: bytes = b"") -> bytes:
    toc = zlib.compress(toc_xml)
    header = struct.pack(">4sHHQQI", b"xar!", 28, 1, len(toc), len(toc_xml), 1)
    return header + toc + heap


def make_udif(path: Path, *, license_prompt: bool = False) -> Path:
    forks: dict[str, Any] = {"blkx": []}
    if license_prompt:
        forks["LPic"] = [{"Data": b"\x00\x00", "ID": "5000"}]
    xml = plistlib.dumps({"resource-fork": forks})
    body = b"\x00" * 64
    trailer = bytearray(512)
    trailer[:4] = b"koly"
    struct.pack_into(">QQ", trailer, 216, len(body), len(xml))
    path.write_bytes(body + xml + bytes(trailer))
    return path


# ------------------------------------------------------------------ detection


def test_detect_container_uses_magic_not_extension(tmp_path: Path) -> None:
    pkg = tmp_path / "a.pkg"
    pkg.write_bytes(make_xar(b"<xar><toc/></xar>"))
    assert detect_container(pkg, "a.pkg") == "pkg"
    with pytest.raises(InspectError) as exc:
        detect_container(pkg, "renamed.dmg")
    assert exc.value.code == "TYPE_MISMATCH"

    zipped = make_zip(tmp_path / "a.zip", {"x.txt": b"hello world" * 10})
    assert detect_container(zipped) == "zip"
    assert detect_container(make_udif(tmp_path / "a.dmg")) == "dmg"

    junk = tmp_path / "evil.pkg"
    junk.write_bytes(b"#!/bin/sh\nrm -rf /\n" * 4)
    with pytest.raises(InspectError) as exc:
        detect_container(junk, "evil.pkg")
    assert exc.value.code == "UNSUPPORTED_TYPE"


def test_extension_for_kinds() -> None:
    assert extension_for("MACOS_PKG") == "pkg"
    assert extension_for("MACOS_ZIP_APP") == "zip"
    assert extension_for("MACOS_DMG_APP") == "dmg"
    assert extension_for("MACOS_DMG_PKG") == "dmg"


# ------------------------------------------------------------------ Mach-O


def test_macho_thin_and_fat_architecture_and_team() -> None:
    arm = parse_macho(thin_macho(ARM))
    assert arm is not None and arm.architecture == "arm64" and arm.team_id == TEAM
    fat = parse_macho(fat_macho(thin_macho(X86), thin_macho(ARM), cputypes=(X86, ARM)))
    assert fat is not None and fat.architecture == "universal" and fat.team_id == TEAM
    assert not fat.adhoc


def test_macho_adhoc_and_unsigned() -> None:
    adhoc = parse_macho(thin_macho(X86, team=None, flags=0x2))
    assert adhoc is not None and adhoc.adhoc and adhoc.team_id is None
    assert parse_macho(b"\x00" * 64) is None


# ------------------------------------------------------------------ ZIP


def test_zip_app_reads_metadata(tmp_path: Path) -> None:
    binary = fat_macho(thin_macho(X86), thin_macho(ARM), cputypes=(X86, ARM))
    result = inspect_zip(make_zip(tmp_path / "n.zip", app_entries(binary)))
    assert result.kind == "MACOS_ZIP_APP"
    assert result.identifier == "com.example.netron"
    assert result.version == "9.0.8"
    assert result.architecture == "universal"
    assert result.team_id == TEAM
    assert result.payload_path == "Netron.app"
    assert result.minimum_os_version == "12.0"


@pytest.mark.parametrize(
    ("entries", "links", "code"),
    [
        ({"../evil.app/Contents/Info.plist": b"x"}, None, "ZIP_PATH_REJECTED"),
        ({"/abs.app/Contents/Info.plist": b"x"}, None, "ZIP_PATH_REJECTED"),
        ({"readme.txt": b"x"}, None, "NO_APP_FOUND"),
        (
            {"A.app/Contents/Info.plist": b"x", "B.app/Contents/Info.plist": b"x"},
            None,
            "AMBIGUOUS_PAYLOAD",
        ),
        ({"A.app/Contents/Info.plist": b"x"}, {"A.app/escape": "../../etc"}, "ZIP_PATH_REJECTED"),
        ({"A.app/Contents/Info.plist": b"x"}, {"A.app/abs": "/etc/passwd"}, "ZIP_PATH_REJECTED"),
    ],
)
def test_zip_rejections(
    tmp_path: Path, entries: dict[str, bytes], links: dict[str, str] | None, code: str
) -> None:
    with pytest.raises(InspectError) as exc:
        inspect_zip(make_zip(tmp_path / "x.zip", entries, links))
    assert exc.value.code == code


def test_zip_allows_links_inside_its_own_bundle(tmp_path: Path) -> None:
    entries = app_entries(thin_macho(ARM))
    links = {"Netron.app/Contents/Frameworks/F.framework/Versions/Current": "A"}
    assert inspect_zip(make_zip(tmp_path / "ok.zip", entries, links)).architecture == "arm64"


def test_zip_rejects_unsigned_app(tmp_path: Path) -> None:
    entries = app_entries(thin_macho(ARM, team=None, flags=0x2))
    with pytest.raises(InspectError) as exc:
        inspect_zip(make_zip(tmp_path / "u.zip", entries))
    assert exc.value.code == "UNSIGNED_APP"


def test_zip_rejects_bomb_like_members(tmp_path: Path) -> None:
    entries = app_entries(thin_macho(ARM) + b"\x00" * (8 * 1024 * 1024))
    with pytest.raises(InspectError) as exc:
        inspect_zip(make_zip(tmp_path / "b.zip", entries))
    assert exc.value.code == "ZIP_BOMB_SUSPECTED"


# ------------------------------------------------------------------ xar / pkg


def test_pkg_rejects_dtd_and_entities() -> None:
    with pytest.raises(InspectError):
        _safe_xml(b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "b">]><x>&a;</x>')


def test_unsigned_pkg_is_rejected() -> None:
    data = make_xar(b"<xar><toc></toc></xar>")
    with pytest.raises(InspectError) as exc:
        inspect_pkg_stream(io.BytesIO(data).read, "MACOS_PKG", None)
    assert exc.value.code == "UNSIGNED_PACKAGE"


def test_bad_xar_header() -> None:
    with pytest.raises(InspectError) as exc:
        inspect_pkg_stream(io.BytesIO(b"nope" * 10).read, "MACOS_PKG", None)
    assert exc.value.code == "PKG_UNREADABLE"


# ------------------------------------------------------------------ DMG (UDIF trailer)


def test_dmg_volume_prefixed_app_paths_round_trip() -> None:
    """Regression: volume folder + inspect_app prefix must not double up (Slack-style DMGs)."""
    from app.catalogue.inspect.dmg import _Item, _payload_root

    items = [
        _Item("Slack", True, 0, False),
        _Item("Slack/Slack.app", True, 0, False),
        _Item("Slack/Slack.app/Contents/Info.plist", False, 100, False),
        _Item("Slack/Applications", False, 13, True),
    ]
    root, top = _payload_root(items)
    assert root == "Slack/"
    apps = [i.path[len(root) :] for i in top if i.path.endswith(".app")]
    assert apps == ["Slack.app"]
    # Reader contract: member from inspect_app (no prefix) + root == archive path.
    member = f"{apps[0]}/Contents/Info.plist"
    assert f"{root}{member}" == "Slack/Slack.app/Contents/Info.plist"
    assert f"{root}{root}{member}" != "Slack/Slack.app/Contents/Info.plist"


def test_dmg_license_prompt_and_encryption(tmp_path: Path) -> None:
    check_udif(make_udif(tmp_path / "plain.dmg"))
    with pytest.raises(InspectError) as exc:
        check_udif(make_udif(tmp_path / "sla.dmg", license_prompt=True))
    assert exc.value.code == "DMG_LICENSE_PROMPT"

    enc = tmp_path / "enc.dmg"
    enc.write_bytes(b"encrcdsa" + b"\x00" * 1024)
    with pytest.raises(InspectError) as exc:
        check_udif(enc)
    assert exc.value.code == "DMG_ENCRYPTED"


# ------------------------------------------------------------------ result validation


def test_inspection_from_dict_revalidates() -> None:
    good = {
        "kind": "MACOS_DMG_APP",
        "name": "Slack\x07",
        "version": "4.47.69",
        "identifier": "com.tinyspeck.slackmacgap",
        "architecture": "universal",
        "minimum_os_version": "not-a-version",
        "team_id": "BQR82RBBHL",
        "publisher": "",
        "signer": "Developer ID Application: Slack",
        "payload_path": "Slack.app",
    }
    parsed = Inspection.from_dict(good)
    assert parsed.name == "Slack"
    assert parsed.minimum_os_version == "11.0"
    assert parsed.publisher == "BQR82RBBHL"
    with pytest.raises(InspectError):
        Inspection.from_dict({**good, "team_id": "../../etc"})
    with pytest.raises(InspectError):
        Inspection.from_dict({**good, "architecture": "ppc"})


def test_every_rejection_code_has_a_hint() -> None:
    for code in (
        "UNSIGNED_APP",
        "UNSIGNED_PACKAGE",
        "TEAM_ID_MISMATCH",
        "DMG_LICENSE_PROMPT",
        "DMG_ENCRYPTED",
        "AMBIGUOUS_PAYLOAD",
        "NO_APP_FOUND",
        "ZIP_PATH_REJECTED",
        "URL_REJECTED",
        "PACKAGE_TOO_LARGE",
    ):
        assert code in HINTS, code
    assert hint_for("SOMETHING_UNKNOWN")


# ------------------------------------------------------------------ SSRF


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com/a.dmg",
        "https://user:pw@example.com/a.dmg",
        "https://127.0.0.1/a.dmg",
        "https://10.0.0.5/a.dmg",
        "https://169.254.169.254/latest/meta-data",
        "https://[::1]/a.dmg",
        "https://[::ffff:127.0.0.1]/a.dmg",
        "https://metadata.google.internal/x",
        "https://printer.local/a.dmg",
        "https://example.com:22/a.dmg",
        "ftp://example.com/a.dmg",
    ],
)
def test_url_shape_rejections(url: str) -> None:
    with pytest.raises(InspectError) as exc:
        check_url_shape(url)
    assert exc.value.code == "URL_REJECTED"


def test_url_shape_accepts_public_https() -> None:
    assert check_url_shape("https://downloads.slack-edge.com/a.dmg") == (
        "downloads.slack-edge.com",
        443,
    )
    assert not _blocked_ip("93.184.216.34")
    assert _blocked_ip("100.64.0.1")
    assert _blocked_ip("not-an-ip")


# ------------------------------------------------------------------ drafts and store


def _settings(tmp_path: Path) -> Any:
    return SimpleNamespace(
        package_store_dir=str(tmp_path / "store"), catalogue_draft_ttl_seconds=60
    )


def _draft(settings: Any, *, expires_in: float, sha: str = "c" * 64) -> Draft:
    draft_id, directory = new_draft_dir(settings)
    (directory / "package.bin").write_bytes(b"payload")
    now = time.time()
    draft = Draft(
        draft_id=draft_id,
        directory=directory,
        created_at=now,
        expires_at=now + expires_in,
        actor_id=str(uuid.uuid4()),
        sha256=sha,
        size=7,
        filename_hint="Slack.dmg",
        source_url=None,
        preset_id="slack",
        inspection={},
    )
    draft.save()
    return draft


def test_draft_round_trip_commit_and_lookup(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    draft = _draft(settings, expires_in=60)
    loaded = load_draft(settings, draft.draft_id)
    assert loaded.preset_id == "slack"
    path = commit_artifact(settings, loaded, "dmg")
    assert path.name == f"{'c' * 64}.dmg"
    assert find_artifact(settings, "c" * 64) == path
    assert find_artifact(settings, "../../etc/passwd") is None


def test_draft_expiry_and_bad_ids(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    expired = _draft(settings, expires_in=-1)
    with pytest.raises(InspectError) as exc:
        load_draft(settings, expired.draft_id)
    assert exc.value.code == "DRAFT_EXPIRED"
    for bad in ("../x", "A" * 32, ""):
        with pytest.raises(InspectError) as exc:
            load_draft(settings, bad)
        assert exc.value.code == "DRAFT_NOT_FOUND"


def test_purge_expired_drafts(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    keep = _draft(settings, expires_in=600)
    _draft(settings, expires_in=-5)
    assert purge_expired_drafts(settings) == 1
    assert load_draft(settings, keep.draft_id).draft_id == keep.draft_id


# ------------------------------------------------------------------ presets


def test_presets_are_well_formed() -> None:
    assert len({p.id for p in PRESETS}) == len(PRESETS)
    for preset in PRESETS:
        assert len(preset.team_id) == 10 and preset.team_id.isalnum()
        assert preset.kind in {"MACOS_PKG", "MACOS_DMG_APP", "MACOS_DMG_PKG", "MACOS_ZIP_APP"}
        for url in preset.urls.values():
            check_url_shape(url)
    slack = get_preset("slack")
    assert slack is not None and slack.team_id == "BQR82RBBHL"
    postman = get_preset("postman")
    assert postman is not None
    assert preset_url(postman, "x86_64")[0] == "x86_64"
    assert preset_url(postman, None)[0] == next(iter(postman.urls))
    assert get_preset("../etc") is None


# ------------------------------------------------------------------ compatibility


def _device(**kw: Any) -> DeviceSnapshot:
    base: dict[str, Any] = {
        "enrolled": True,
        "status": "ACTIVE",
        "last_seen_at": datetime.now(UTC),
        "os_family": "macos",
        "os_version": "15.1",
        "architecture": "arm64",
        "memory_total_bytes": 16 << 30,
        "disk_free_bytes": 100 << 30,
        "installed_software": [],
        "supported_installers": ("MACOS_PKG", "MACOS_DMG_APP", "MACOS_DMG_PKG", "MACOS_ZIP_APP"),
    }
    base.update(kw)
    return DeviceSnapshot(**base)


def _package(**kw: Any) -> PackageSnapshot:
    base: dict[str, Any] = {
        "software_lifecycle": "ACTIVE",
        "release_status": "ACTIVE",
        "os_family": "macos",
        "architecture": "universal",
        "minimum_os_version": "12.0",
        "minimum_memory_bytes": 512 << 20,
        "minimum_disk_bytes": 1 << 30,
        "installer_type": "MACOS_DMG_APP",
        "source_type": "CONTROLLED_UPLOAD",
        "source_reference": "artifact://sha256/x.dmg",
        "sha256": "d" * 64,
        "signature_publisher": "Slack Technologies, LLC",
        "signature_required": True,
        "verification_method": "APP_BUNDLE",
        "package_identifier": "com.tinyspeck.slackmacgap",
        "version": "4.47.69",
        "expected_team_id": "BQR82RBBHL",
        "payload_path": "Slack.app",
    }
    base.update(kw)
    return PackageSnapshot(**base)


def _eval(device: DeviceSnapshot, package: PackageSnapshot) -> str:
    return evaluate(device, package, stale_after=timedelta(minutes=10)).reason_code


def test_archive_compatibility_reasons() -> None:
    assert _eval(_device(), _package()) == REASON_COMPATIBLE
    legacy = _device(supported_installers=None)
    assert _eval(legacy, _package()) == REASON_INSTALLER_UNSUPPORTED
    assert _eval(legacy, _package(installer_type="MACOS_PKG")) == REASON_COMPATIBLE
    assert _eval(_device(), _package(expected_team_id=None)) == REASON_PACKAGE_METADATA_INCOMPLETE
    assert _eval(_device(), _package(payload_path=None)) == REASON_PACKAGE_METADATA_INCOMPLETE


def test_installed_and_newer_versions_are_satisfied() -> None:
    def with_installed(version: str) -> DeviceSnapshot:
        item = {"identifier": "com.tinyspeck.slackmacgap", "version": version}
        return _device(installed_software=[item])

    assert _eval(with_installed("4.47.69"), _package()) == REASON_ALREADY_INSTALLED
    assert _eval(with_installed("4.48.1"), _package()) == REASON_NEWER_VERSION_INSTALLED
    assert _eval(with_installed("4.40.0"), _package()) == REASON_COMPATIBLE
    assert {REASON_ALREADY_INSTALLED, REASON_NEWER_VERSION_INSTALLED} == SATISFIED_REASONS


# ------------------------------------------------------------------ envelope


def _envelope(installer_type: str) -> dict[str, Any]:
    now = datetime.now(UTC)
    job = SimpleNamespace(
        id=uuid.uuid4(),
        device_id=uuid.uuid4(),
        job_nonce="n",
        issued_at=now,
        expires_at=now,
        catalogue_version_id=uuid.uuid4(),
        request_id=uuid.uuid4(),
    )
    version = SimpleNamespace(
        sha256="E" * 64,
        installer_type=installer_type,
        source_type="CONTROLLED_UPLOAD",
        source_reference="artifact://sha256/x",
        package_identifier="com.example",
        version="1.0",
        os_family="macos",
        architecture="universal",
        signature_publisher="Example",
        verification_method="APP_BUNDLE",
        package_size_bytes=10,
        expected_team_id="BQR82RBBHL",
        payload_path="Example.app",
    )
    request = SimpleNamespace(policy_revision=1)
    return build_envelope(job=job, request=request, version=version, binding_hash="h")  # type: ignore[arg-type]


def test_pkg_envelope_keys_unchanged_and_archive_adds_two() -> None:
    legacy_keys = {
        "job_id",
        "device_id",
        "nonce",
        "issued_at",
        "expires_at",
        "package_digest",
        "catalogue_version_id",
        "policy_revision",
        "request_binding_hash",
        "request_id",
        "installer_type",
        "source_type",
        "source_reference",
        "package_identifier",
        "package_version",
        "os_family",
        "architecture",
        "signature_publisher",
        "verification_method",
        "package_size_bytes",
    }
    pkg = _envelope("MACOS_PKG")
    assert set(pkg) == legacy_keys
    assert pkg["package_digest"] == "e" * 64
    dmg = _envelope("MACOS_DMG_APP")
    assert set(dmg) == legacy_keys | {"expected_team_id", "payload_path"}
    assert dmg["expected_team_id"] == "BQR82RBBHL"
