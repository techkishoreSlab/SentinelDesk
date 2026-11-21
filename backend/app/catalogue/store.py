"""Content-addressed package store, inspection drafts and guarded downloads.

Layout under ``PACKAGE_STORE_DIR``:

* ``<sha256>.<pkg|dmg|zip>``: committed packages (immutable; the agent cache-hits by name).
* ``.incoming/<draft_id>/package.bin`` + ``draft.json``: inspected, not yet committed (1 h TTL).
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import ipaddress
import json
import os
import re
import shutil
import socket
import time
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx

from app.catalogue.inspect.result import InspectError
from app.core.config import Settings

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ARTIFACT_NAME_RE = re.compile(r"^([0-9a-f]{64})\.(pkg|dmg|zip)$")
_DRAFT_ID_RE = re.compile(r"^[0-9a-f]{32}$")
CHUNK = 1024 * 1024
MAX_REDIRECTS = 5
CONNECT_TIMEOUT = 30.0
# Idle gaps between streamed chunks (CDN stalls). Wall clock for a large DMG can be many minutes.
READ_TIMEOUT = 600.0
WRITE_TIMEOUT = 600.0
# Browser-like UA: some vendor CDNs throttle or stall unknown bot agents.
_DOWNLOAD_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) SentinelDesk-Catalogue/1.0"
)
_METADATA_HOSTS = {"metadata.google.internal", "metadata", "instance-data"}


def store_root(settings: Settings) -> Path:
    path = Path(settings.package_store_dir)
    path.mkdir(parents=True, exist_ok=True)
    return path


def incoming_root(settings: Settings) -> Path:
    path = store_root(settings) / ".incoming"
    path.mkdir(mode=0o700, exist_ok=True)
    return path


def artifact_path(settings: Settings, sha256: str, ext: str) -> Path:
    if not SHA256_RE.fullmatch(sha256) or ext not in {"pkg", "dmg", "zip"}:
        raise ValueError("invalid artifact name")
    return store_root(settings) / f"{sha256}.{ext}"


def find_artifact(settings: Settings, sha256: str) -> Path | None:
    if not SHA256_RE.fullmatch(sha256):
        return None
    for ext in ("pkg", "dmg", "zip"):
        candidate = store_root(settings) / f"{sha256}.{ext}"
        if candidate.is_file() and not candidate.is_symlink():
            return candidate
    return None


# ---------------------------------------------------------------- drafts


@dataclass(slots=True)
class Draft:
    draft_id: str
    directory: Path
    created_at: float
    expires_at: float
    actor_id: str
    sha256: str
    size: int
    filename_hint: str | None
    source_url: str | None
    preset_id: str | None
    inspection: dict[str, Any]

    @property
    def package(self) -> Path:
        return self.directory / "package.bin"

    def save(self) -> None:
        data = {
            "draft_id": self.draft_id,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "actor_id": self.actor_id,
            "sha256": self.sha256,
            "size": self.size,
            "filename_hint": self.filename_hint,
            "source_url": self.source_url,
            "preset_id": self.preset_id,
            "inspection": self.inspection,
        }
        tmp = self.directory / "draft.json.tmp"
        tmp.write_text(json.dumps(data), encoding="utf-8")
        os.replace(tmp, self.directory / "draft.json")


def new_draft_dir(settings: Settings) -> tuple[str, Path]:
    draft_id = uuid.uuid4().hex
    directory = incoming_root(settings) / draft_id
    directory.mkdir(mode=0o700)
    return draft_id, directory


def load_draft(settings: Settings, draft_id: str) -> Draft:
    if not _DRAFT_ID_RE.fullmatch(draft_id):
        raise InspectError("DRAFT_NOT_FOUND")
    directory = incoming_root(settings) / draft_id
    meta = directory / "draft.json"
    if not meta.is_file():
        raise InspectError("DRAFT_NOT_FOUND")
    try:
        data = json.loads(meta.read_text(encoding="utf-8"))
        draft = Draft(
            draft_id=str(data["draft_id"]),
            directory=directory,
            created_at=float(data["created_at"]),
            expires_at=float(data["expires_at"]),
            actor_id=str(data["actor_id"]),
            sha256=str(data["sha256"]),
            size=int(data["size"]),
            filename_hint=data.get("filename_hint"),
            source_url=data.get("source_url"),
            preset_id=data.get("preset_id"),
            inspection=dict(data["inspection"]),
        )
    except (ValueError, KeyError, TypeError) as exc:
        raise InspectError("DRAFT_NOT_FOUND") from exc
    if draft.draft_id != draft_id or draft.expires_at <= time.time():
        discard_draft(settings, draft_id)
        raise InspectError("DRAFT_EXPIRED")
    if not draft.package.is_file():
        raise InspectError("DRAFT_NOT_FOUND")
    return draft


def discard_draft(settings: Settings, draft_id: str) -> None:
    if not _DRAFT_ID_RE.fullmatch(draft_id):
        return
    shutil.rmtree(incoming_root(settings) / draft_id, ignore_errors=True)


def purge_expired_drafts(settings: Settings, *, now: float | None = None) -> int:
    """Remove expired or orphaned drafts. Safe to run repeatedly."""
    clock = now or time.time()
    root = Path(settings.package_store_dir) / ".incoming"
    if not root.is_dir():
        return 0
    removed = 0
    grace = settings.catalogue_draft_ttl_seconds * 2
    for entry in root.iterdir():
        if not entry.is_dir() or not _DRAFT_ID_RE.fullmatch(entry.name):
            continue
        meta = entry / "draft.json"
        expired = False
        try:
            if meta.is_file():
                expired = float(json.loads(meta.read_text())["expires_at"]) <= clock
            else:
                expired = entry.stat().st_mtime + grace <= clock
        except (OSError, ValueError, KeyError, TypeError):
            expired = True
        if expired:
            shutil.rmtree(entry, ignore_errors=True)
            removed += 1
    return removed


def commit_artifact(settings: Settings, draft: Draft, ext: str) -> Path:
    """Move a draft's file to its content-addressed name. Same digest = same file."""
    dest = artifact_path(settings, draft.sha256, ext)
    if dest.is_file() and not dest.is_symlink():
        draft.package.unlink(missing_ok=True)
    else:
        os.chmod(draft.package, 0o644)
        os.replace(draft.package, dest)
    return dest


# ------------------------------------------------------------ streaming


class _Sink:
    def __init__(self, path: Path, max_bytes: int) -> None:
        self.path = path
        self.max_bytes = max_bytes
        self.hash = hashlib.sha256()
        self.size = 0
        self._fh = path.open("xb")

    def write(self, chunk: bytes) -> None:
        self.size += len(chunk)
        if self.size > self.max_bytes:
            raise InspectError("PACKAGE_TOO_LARGE", limit=str(self.max_bytes))
        self.hash.update(chunk)
        self._fh.write(chunk)

    def close(self) -> None:
        self._fh.close()


async def save_stream(chunks: AsyncIterator[bytes], dest: Path, max_bytes: int) -> tuple[str, int]:
    sink = _Sink(dest, max_bytes)
    try:
        async for chunk in chunks:
            if chunk:
                sink.write(chunk)
    except BaseException:
        sink.close()
        dest.unlink(missing_ok=True)
        raise
    sink.close()
    if sink.size == 0:
        dest.unlink(missing_ok=True)
        raise InspectError("PACKAGE_EMPTY")
    return sink.hash.hexdigest(), sink.size


# ------------------------------------------------------------------ SSRF


def _blocked_ip(raw: str) -> bool:
    try:
        ip = ipaddress.ip_address(raw.split("%", 1)[0])
    except ValueError:
        return True
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        or not ip.is_global
    )


def check_url_shape(url: str) -> tuple[str, int]:
    """https only, a real host name, default-ish port, no credentials."""
    if len(url) > 2000:
        raise InspectError("URL_REJECTED", reason="too_long")
    parts = urlsplit(url)
    if parts.scheme != "https":
        raise InspectError("URL_REJECTED", reason="https_required")
    if parts.username or parts.password:
        raise InspectError("URL_REJECTED", reason="credentials")
    host = (parts.hostname or "").rstrip(".").casefold()
    if not host or host in _METADATA_HOSTS or host.endswith((".local", ".internal", ".localhost")):
        raise InspectError("URL_REJECTED", reason="host")
    port = parts.port or 443
    if port not in {443, 8443}:
        raise InspectError("URL_REJECTED", reason="port")
    with contextlib.suppress(ValueError):
        if _blocked_ip(str(ipaddress.ip_address(host))):
            raise InspectError("URL_REJECTED", reason="private_address")
    return host, port


async def check_host_public(host: str, port: int) -> None:
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise InspectError("URL_UNREACHABLE", reason="dns") from exc
    addresses = {str(info[4][0]) for info in infos}
    if not addresses or any(_blocked_ip(a) for a in addresses):
        raise InspectError("URL_REJECTED", reason="private_address")


def _peer_ip(response: httpx.Response) -> str | None:
    stream = response.extensions.get("network_stream")
    if stream is None:
        return None
    addr = stream.get_extra_info("server_addr")
    if isinstance(addr, tuple) and addr:
        return str(addr[0])
    return None


async def download_url(url: str, dest: Path, max_bytes: int) -> tuple[str, int, str]:
    """Fetch an https URL with SSRF guards on every hop. Returns (sha256, size, final_url)."""
    timeout = httpx.Timeout(
        connect=CONNECT_TIMEOUT,
        read=READ_TIMEOUT,
        write=WRITE_TIMEOUT,
        pool=CONNECT_TIMEOUT,
    )
    current = url
    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=False,
        trust_env=False,
        headers={"User-Agent": _DOWNLOAD_UA, "Accept": "*/*"},
    ) as client:
        for _hop in range(MAX_REDIRECTS + 1):
            host, port = check_url_shape(current)
            await check_host_public(host, port)
            try:
                async with client.stream("GET", current) as resp:
                    # Re-check the address actually connected to (DNS rebinding).
                    peer = _peer_ip(resp)
                    if peer is not None and _blocked_ip(peer):
                        raise InspectError("URL_REJECTED", reason="private_address")
                    if resp.status_code in {301, 302, 303, 307, 308}:
                        location = resp.headers.get("location")
                        if not location:
                            raise InspectError("URL_UNREACHABLE", reason="bad_redirect")
                        current = urljoin(current, location)
                        continue
                    if resp.status_code != 200:
                        raise InspectError("URL_UNREACHABLE", status=str(resp.status_code))
                    declared = resp.headers.get("content-length")
                    if declared and declared.isdigit() and int(declared) > max_bytes:
                        raise InspectError("PACKAGE_TOO_LARGE", limit=str(max_bytes))
                    sha, size = await save_stream(resp.aiter_bytes(CHUNK), dest, max_bytes)
                    return sha, size, current
            except httpx.TimeoutException as exc:
                raise InspectError("URL_UNREACHABLE", reason="timeout") from exc
            except httpx.HTTPError as exc:
                raise InspectError(
                    "URL_UNREACHABLE", reason="network", detail=type(exc).__name__
                ) from exc
    raise InspectError("URL_UNREACHABLE", reason="too_many_redirects")


def filename_from_url(url: str) -> str | None:
    name = urlsplit(url).path.rsplit("/", 1)[-1]
    return name if re.fullmatch(r"[A-Za-z0-9._+\-]{1,200}", name) else None
