"""ZIP containing exactly one top-level .app (for example Visual Studio Code)."""

from __future__ import annotations

import posixpath
import stat
import zipfile
from pathlib import Path

from app.catalogue.inspect.bundle import inspect_app
from app.catalogue.inspect.result import InspectError, Inspection

MAX_ENTRIES = 200_000
MAX_RATIO = 200
_IGNORED_TOP = {"__MACOSX", ".DS_Store"}


def _check_name(name: str) -> list[str]:
    if not name or name.startswith("/") or "\\" in name or "\x00" in name:
        raise InspectError("ZIP_PATH_REJECTED")
    parts = [p for p in name.split("/") if p]
    if any(p == ".." for p in parts):
        raise InspectError("ZIP_PATH_REJECTED")
    return parts


def _is_symlink(info: zipfile.ZipInfo) -> bool:
    return info.create_system == 3 and stat.S_ISLNK(info.external_attr >> 16)


def inspect_zip(path: Path) -> Inspection:
    try:
        archive = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, OSError) as exc:
        raise InspectError("ZIP_UNREADABLE") from exc
    with archive:
        infos = archive.infolist()
        if len(infos) > MAX_ENTRIES:
            raise InspectError("ZIP_TOO_MANY_ENTRIES")
        if any(i.flag_bits & 0x1 for i in infos):
            raise InspectError("ZIP_ENCRYPTED")

        tops: set[str] = set()
        by_name: dict[str, zipfile.ZipInfo] = {}
        for info in infos:
            parts = _check_name(info.filename)
            if not parts or parts[0] in _IGNORED_TOP:
                continue
            tops.add(parts[0])
            by_name["/".join(parts)] = info
            if _is_symlink(info):
                # A link may point within its own bundle (framework Versions/Current) only.
                target = archive.read(info)[:1024].decode("utf-8", "replace")
                if target.startswith("/"):
                    raise InspectError("ZIP_PATH_REJECTED", reason="absolute_symlink")
                resolved = posixpath.normpath(
                    posixpath.join(posixpath.dirname(info.filename), target)
                )
                if resolved.startswith("..") or resolved.split("/", 1)[0] != parts[0]:
                    raise InspectError("ZIP_PATH_REJECTED", reason="symlink_escape")

        apps = sorted(t for t in tops if t.endswith(".app"))
        if not apps:
            raise InspectError("NO_APP_FOUND")
        if len(apps) > 1:
            raise InspectError("AMBIGUOUS_PAYLOAD", items=apps[:5])

        def read(member: str, limit: int) -> bytes | None:
            info = by_name.get(member)
            if info is None or info.is_dir() or _is_symlink(info):
                return None
            if info.file_size > limit:
                raise InspectError("APP_MEMBER_TOO_LARGE")
            if info.compress_size and info.file_size / info.compress_size > MAX_RATIO:
                raise InspectError("ZIP_BOMB_SUSPECTED")
            with archive.open(info) as fh:
                data = fh.read(limit + 1)
            if len(data) > limit:
                raise InspectError("APP_MEMBER_TOO_LARGE")
            return data

        return inspect_app(apps[0], "MACOS_ZIP_APP", read)
