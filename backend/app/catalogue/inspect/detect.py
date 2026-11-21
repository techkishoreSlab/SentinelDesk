"""Container type from magic bytes. The file extension is only cross-checked, never trusted."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from app.catalogue.inspect.result import InspectError

Container = Literal["pkg", "zip", "dmg"]
_EXT: dict[str, Container] = {".pkg": "pkg", ".mpkg": "pkg", ".zip": "zip", ".dmg": "dmg"}
UDIF_TRAILER = 512


def detect_container(path: Path, filename_hint: str | None = None) -> Container:
    size = path.stat().st_size
    if size < 32:
        raise InspectError("UNSUPPORTED_TYPE")
    with path.open("rb") as fh:
        head = fh.read(8)
        tail = b""
        if size >= UDIF_TRAILER:
            fh.seek(size - UDIF_TRAILER)
            tail = fh.read(4)

    kind: Container
    if head.startswith(b"xar!"):
        kind = "pkg"
    elif head.startswith(b"PK\x03\x04"):
        kind = "zip"
    elif tail == b"koly" or head in (b"encrcdsa", b"cdsaencr"):
        kind = "dmg"
    else:
        raise InspectError("UNSUPPORTED_TYPE")

    if filename_hint:
        claimed = _EXT.get(Path(filename_hint).suffix.casefold())
        if claimed is not None and claimed != kind:
            raise InspectError("TYPE_MISMATCH", claimed=claimed, detected=kind)
    return kind


def extension_for(kind: str) -> str:
    """File extension used in the content-addressed store for each installer kind."""
    if kind in {"MACOS_PKG"}:
        return "pkg"
    if kind == "MACOS_ZIP_APP":
        return "zip"
    return "dmg"
