"""Apple disk image (UDIF) reader using a pinned 7-Zip build.

Nothing is mounted. The UDIF trailer and resource map are parsed in Python to detect licence
(SLA) prompts; 7-Zip lists the filesystem and streams only the few members we need to stdout,
so no image content is written to disk.
"""

from __future__ import annotations

import os
import plistlib
import struct
import subprocess
from dataclasses import dataclass
from pathlib import Path
from xml.parsers.expat import ExpatError

from app.catalogue.inspect.bundle import inspect_app
from app.catalogue.inspect.pkg_xar import inspect_pkg_stream
from app.catalogue.inspect.result import InspectError, Inspection
from app.catalogue.schemas import PAYLOAD_NAME

MAX_XML_BYTES = 32 * 1024 * 1024
LIST_TIMEOUT = 120
READ_TIMEOUT = 300
_IGNORED = {
    ".background",
    ".DS_Store",
    ".Trashes",
    ".fseventsd",
    "Applications",
    ".VolumeIcon.icns",
}


@dataclass(frozen=True, slots=True)
class _Item:
    path: str
    folder: bool
    size: int
    symlink: bool


def seven_zip() -> str:
    path = os.environ.get("SENTINEL_7ZZ", "/usr/local/bin/7zz")
    if not Path(path).is_file():
        raise InspectError("DMG_TOOL_UNAVAILABLE")
    return path


def check_udif(path: Path) -> None:
    size = path.stat().st_size
    with path.open("rb") as fh:
        if fh.read(8) in (b"encrcdsa", b"cdsaencr"):
            raise InspectError("DMG_ENCRYPTED")
        fh.seek(size - 512)
        trailer = fh.read(512)
        if trailer[:4] != b"koly":
            raise InspectError("DMG_UNREADABLE")
        (xml_offset, xml_length) = struct.unpack_from(">QQ", trailer, 216)
        if xml_length == 0:
            return
        if xml_length > MAX_XML_BYTES or xml_offset + xml_length > size:
            raise InspectError("DMG_UNREADABLE", reason="resource_map")
        fh.seek(xml_offset)
        raw = fh.read(xml_length)
    try:
        plist = plistlib.loads(raw)
    except (plistlib.InvalidFileException, ExpatError, ValueError) as exc:
        raise InspectError("DMG_UNREADABLE", reason="resource_map") from exc
    forks = plist.get("resource-fork") if isinstance(plist, dict) else None
    if isinstance(forks, dict) and "LPic" in forks:
        raise InspectError("DMG_LICENSE_PROMPT")


def _run(args: list[str], timeout: int) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(  # noqa: S603 - fixed argv, pinned binary, no shell
            args,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=timeout,
            check=False,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
        )
    except subprocess.TimeoutExpired as exc:
        raise InspectError("INSPECT_TIMEOUT") from exc


def _list(tool: str, path: Path) -> list[_Item]:
    proc = _run(
        [tool, "l", "-slt", "-ba", "-bd", "-p-", "-sccUTF-8", "--", str(path)], LIST_TIMEOUT
    )
    text = proc.stdout.decode("utf-8", "replace")
    if proc.returncode != 0:
        err = (proc.stderr + proc.stdout).decode("utf-8", "replace").casefold()
        if "password" in err or "encrypted" in err:
            raise InspectError("DMG_ENCRYPTED")
        raise InspectError("DMG_UNREADABLE")
    items: list[_Item] = []
    for block in text.split("\n\n"):
        fields: dict[str, str] = {}
        for line in block.splitlines():
            key, sep, value = line.partition(" = ")
            if sep:
                fields[key.strip()] = value
        name = fields.get("Path")
        if not name:
            continue
        mode = fields.get("Mode", "")
        if not mode:
            attrs = fields.get("Attributes", "")
            mode = attrs.split(" ", 1)[1] if " " in attrs else attrs
        items.append(
            _Item(
                path=name,
                folder=fields.get("Folder") == "+" or mode.startswith("d"),
                size=int(fields.get("Size") or "0") if (fields.get("Size") or "0").isdigit() else 0,
                symlink=mode.startswith("l") or bool(fields.get("Symbolic Link")),
            )
        )
        if len(items) > 500_000:
            raise InspectError("DMG_TOO_MANY_ENTRIES")
    return items


def _payload_root(items: list[_Item]) -> tuple[str, list[_Item]]:
    """Directory holding the shallowest installable item, and the items directly in it."""
    candidates = [
        i
        for i in items
        if (i.path.endswith(".app") and i.folder) or (i.path.endswith(".pkg") and not i.folder)
    ]
    if not candidates:
        raise InspectError("NO_APP_FOUND")
    depth = min(c.path.count("/") for c in candidates)
    top = [c for c in candidates if c.path.count("/") == depth]
    root = top[0].path.rsplit("/", 1)[0] + "/" if "/" in top[0].path else ""
    return root, [c for c in top if c.path.startswith(root)]


def inspect_dmg(path: Path) -> Inspection:
    check_udif(path)
    tool = seven_zip()
    items = _list(tool, path)
    by_path = {i.path: i for i in items}
    root, top = _payload_root(items)
    apps = sorted(i.path[len(root) :] for i in top if i.path.endswith(".app"))
    pkgs = sorted(i.path[len(root) :] for i in top if i.path.endswith(".pkg"))
    apps = [a for a in apps if a not in _IGNORED]

    def stream(member: str) -> subprocess.Popen[bytes]:
        return subprocess.Popen(  # noqa: S603 - fixed argv, pinned binary, no shell
            [tool, "x", "-so", "-bd", "-p-", "-spd", "-sccUTF-8", "--", str(path), member],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
        )

    def read(member: str, limit: int) -> bytes | None:
        # ``member`` is relative to the payload root (e.g. Slack.app/Contents/Info.plist).
        # Prepend the volume folder here once — do not also pass ``prefix=root`` to
        # ``inspect_app`` or the path becomes Slack/Slack/... and every read misses.
        full = f"{root}{member}"
        item = by_path.get(full)
        if item is None or item.folder:
            return None
        if item.symlink:
            raise InspectError("SYMLINK_REJECTED")
        if item.size > limit:
            raise InspectError("APP_MEMBER_TOO_LARGE")
        proc = stream(full)
        assert proc.stdout is not None
        try:
            # -so appends extended-attribute streams after the data fork; keep the file only.
            data = proc.stdout.read(item.size)
        finally:
            proc.kill()
            proc.wait(timeout=10)
        if len(data) != item.size:
            raise InspectError("DMG_UNREADABLE", reason="short_read")
        return data

    if len(apps) > 1:
        raise InspectError("AMBIGUOUS_PAYLOAD", items=apps[:5])
    if apps:
        if not PAYLOAD_NAME.fullmatch(apps[0]):
            raise InspectError("PAYLOAD_NAME_REJECTED")
        info = inspect_app(apps[0], "MACOS_DMG_APP", read)
        if pkgs:
            info.warnings.append("EXTRA_PKG_IGNORED")
        return info
    if len(pkgs) > 1:
        raise InspectError("AMBIGUOUS_PAYLOAD", items=pkgs[:5])
    pkg = pkgs[0]
    if not PAYLOAD_NAME.fullmatch(pkg) or by_path[f"{root}{pkg}"].symlink:
        raise InspectError("PAYLOAD_NAME_REJECTED")
    proc = stream(f"{root}{pkg}")
    assert proc.stdout is not None
    try:
        return inspect_pkg_stream(proc.stdout.read, "MACOS_DMG_PKG", pkg)
    finally:
        proc.kill()
        proc.wait(timeout=10)
