"""Flat installer package (xar) reader: identifier, version, min OS, arch and signer.

Reads sequentially so the same code works on a file or on a pipe (a .pkg inside a DMG).
The TOC and the few small metadata files are decompressed with hard size caps.
"""

from __future__ import annotations

import base64
import bz2
import struct
import zlib
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import IO
from xml.etree import ElementTree as ET

from app.catalogue.inspect.certs import signer_from_der_list
from app.catalogue.inspect.result import (
    IDENTIFIER_RE,
    InspectError,
    Inspection,
    clean_min_os,
    clean_text,
    clean_version,
)

_HEADER = struct.Struct(">4sHHQQI")
MAX_TOC_COMPRESSED = 16 * 1024 * 1024
MAX_TOC_BYTES = 32 * 1024 * 1024
MAX_META_BYTES = 4 * 1024 * 1024
_WANTED = ("Distribution", "PackageInfo")


@dataclass(slots=True)
class _Entry:
    path: str
    offset: int
    length: int
    size: int
    encoding: str


@dataclass(slots=True)
class _Component:
    identifier: str
    version: str
    install_kbytes: int = 0
    app_bundles: list[tuple[str, str | None]] = field(default_factory=list)


def _safe_xml(raw: bytes) -> ET.Element:
    # Installer XML never needs a DTD; refusing one rules out entity expansion and XXE.
    upper = raw.upper()
    if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
        raise InspectError("PKG_UNREADABLE", reason="dtd_rejected")
    try:
        return ET.fromstring(raw)  # noqa: S314 - DTDs rejected above
    except ET.ParseError as exc:
        raise InspectError("PKG_UNREADABLE") from exc


def _inflate(data: bytes, encoding: str, limit: int) -> bytes:
    if "gzip" in encoding or "zlib" in encoding:
        d = zlib.decompressobj()
        out = d.decompress(data, limit + 1)
    elif "bzip2" in encoding:
        out = bz2.BZ2Decompressor().decompress(data, max_length=limit + 1)
    else:
        out = data
    if len(out) > limit:
        raise InspectError("PKG_UNREADABLE", reason="metadata_too_large")
    return out


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _walk(node: ET.Element, prefix: str, out: list[_Entry]) -> None:
    for child in node:
        if _local(child.tag) != "file":
            continue
        name = (child.findtext("name") or "").strip()
        if not name or "/" in name or name in {".", ".."}:
            continue
        path = f"{prefix}{name}"
        data = child.find("data")
        if data is not None and name in _WANTED:
            enc = data.find("encoding")
            try:
                out.append(
                    _Entry(
                        path=path,
                        offset=int(data.findtext("offset") or "-1"),
                        length=int(data.findtext("length") or "-1"),
                        size=int(data.findtext("size") or "-1"),
                        encoding=(enc.get("style", "") if enc is not None else ""),
                    )
                )
            except ValueError:
                continue
        _walk(child, f"{path}/", out)


def _certificates(toc: ET.Element) -> list[bytes]:
    blobs: list[bytes] = []
    for sig in toc:
        if _local(sig.tag) not in {"signature", "x-signature"}:
            continue
        for el in sig.iter():
            if _local(el.tag) == "X509Certificate" and el.text:
                try:
                    blobs.append(base64.b64decode("".join(el.text.split()), validate=True))
                except ValueError:
                    continue
        if blobs:
            break
    return blobs


class _Sequential:
    def __init__(self, read: Callable[[int], bytes]) -> None:
        self._read = read
        self.position = 0

    def take(self, n: int) -> bytes:
        chunks: list[bytes] = []
        remaining = n
        while remaining > 0:
            chunk = self._read(min(remaining, 1024 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        self.position += len(data)
        return data

    def skip_to(self, target: int) -> None:
        while self.position < target:
            if not self.take(min(target - self.position, 1024 * 1024)):
                raise InspectError("PKG_UNREADABLE", reason="truncated")


def inspect_pkg_stream(read: Callable[[int], bytes], kind: str, payload: str | None) -> Inspection:
    stream = _Sequential(read)
    header = stream.take(_HEADER.size)
    if len(header) < _HEADER.size:
        raise InspectError("PKG_UNREADABLE")
    magic, header_size, _version, toc_len, toc_raw_len, _alg = _HEADER.unpack(header)
    if magic != b"xar!" or header_size < _HEADER.size or header_size > 4096:
        raise InspectError("PKG_UNREADABLE")
    if toc_len > MAX_TOC_COMPRESSED or toc_raw_len > MAX_TOC_BYTES:
        raise InspectError("PKG_UNREADABLE", reason="toc_too_large")
    stream.skip_to(header_size)
    toc_xml = _inflate(stream.take(toc_len), "zlib", MAX_TOC_BYTES)
    root = _safe_xml(toc_xml)
    toc = root.find("toc")
    if toc is None:
        raise InspectError("PKG_UNREADABLE")

    heap = header_size + toc_len
    entries: list[_Entry] = []
    _walk(toc, "", entries)
    files: dict[str, bytes] = {}
    for entry in sorted(entries, key=lambda e: e.offset):
        if entry.offset < 0 or entry.length < 0 or entry.length > MAX_META_BYTES:
            continue
        start = heap + entry.offset
        if start < stream.position:
            continue
        stream.skip_to(start)
        files[entry.path] = _inflate(stream.take(entry.length), entry.encoding, MAX_META_BYTES)

    signer = signer_from_der_list(_certificates(toc))
    if signer is None:
        raise InspectError("UNSIGNED_PACKAGE")
    return _summarise(files, signer.team_id, signer.common_name, signer.organisation, kind, payload)


def inspect_pkg_file(
    fh: IO[bytes], kind: str = "MACOS_PKG", payload: str | None = None
) -> Inspection:
    return inspect_pkg_stream(fh.read, kind, payload)


def _component_from_info(raw: bytes) -> _Component | None:
    node = _safe_xml(raw)
    if _local(node.tag) != "pkg-info":
        return None
    identifier = clean_text(node.get("identifier"), 200)
    version = clean_version(node.get("version"))
    if not IDENTIFIER_RE.fullmatch(identifier) or version is None:
        return None
    comp = _Component(identifier=identifier, version=version)
    payload = node.find("payload")
    if payload is not None:
        try:
            comp.install_kbytes = int(payload.get("installKBytes") or "0")
        except ValueError:
            comp.install_kbytes = 0
    location = (node.get("install-location") or "/").rstrip("/")
    for bundle in node.iter("bundle"):
        path = (bundle.get("path") or "").removeprefix("./")
        if path.endswith(".app") and path.count("/") == 0:
            full = f"{location}/{path}" if location else f"/{path}"
            if full.startswith("/Applications/") and full.count("/") == 2:
                comp.app_bundles.append(
                    (path, clean_version(bundle.get("CFBundleShortVersionString")))
                )
    return comp


def _summarise(
    files: dict[str, bytes],
    team_id: str,
    signer_cn: str,
    organisation: str,
    kind: str,
    payload: str | None,
) -> Inspection:
    warnings: list[str] = []
    components = [
        comp
        for path, raw in files.items()
        if path.endswith("PackageInfo") and (comp := _component_from_info(raw)) is not None
    ]
    distribution = files.get("Distribution")
    title = ""
    min_os = None
    arch_attr = ""
    if distribution is not None:
        dist = _safe_xml(distribution)
        title = clean_text(dist.findtext("title"), 120)
        options = dist.find("options")
        if options is not None:
            arch_attr = options.get("hostArchitectures") or ""
        for os_version in dist.iter("os-version"):
            min_os = os_version.get("min")
            break
        if not components:
            for ref in dist.iter("pkg-ref"):
                ident = clean_text(ref.get("id"), 200)
                ver = clean_version(ref.get("version"))
                if IDENTIFIER_RE.fullmatch(ident) and ver:
                    kb = ref.get("installKBytes") or "0"
                    components.append(_Component(ident, ver, int(kb) if kb.isdigit() else 0))
    if not components:
        raise InspectError("IDENTIFIER_UNREADABLE")

    # The component that drops an .app into /Applications is what the user asked for;
    # otherwise take the largest payload.
    with_app = [c for c in components if c.app_bundles]
    main = (with_app or sorted(components, key=lambda c: c.install_kbytes, reverse=True))[0]
    if len({c.identifier for c in components}) > 1:
        warnings.append("MULTIPLE_COMPONENTS")
    name = title or (main.app_bundles[0][0].removesuffix(".app") if main.app_bundles else "")

    archs = {a.strip() for a in arch_attr.split(",") if a.strip()}
    if {"x86_64", "arm64"} <= archs:
        architecture = "universal"
    elif archs == {"arm64"}:
        architecture = "arm64"
    elif archs == {"x86_64"}:
        architecture = "x86_64"
        warnings.append("INTEL_ONLY_PACKAGE")
    else:
        architecture = "universal"
        warnings.append("ARCH_NOT_DECLARED")

    return Inspection(
        kind=kind,
        name=name or main.identifier,
        version=main.version,
        identifier=main.identifier,
        architecture=architecture,
        minimum_os_version=clean_min_os(min_os, warnings),
        team_id=team_id,
        publisher=organisation,
        signer=signer_cn or f"Developer ID Installer ({team_id})",
        payload_path=payload,
        warnings=warnings,
    )
