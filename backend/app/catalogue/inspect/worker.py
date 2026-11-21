"""Inspection worker: runs in a child process with resource limits and no network.

Usage: ``python -m app.catalogue.inspect.worker <file> [filename-hint]``. Prints one JSON object
on stdout. Untrusted parsing never runs inside the API process.
"""

from __future__ import annotations

import json
import socket
import sys
from pathlib import Path
from typing import Any, NoReturn

CPU_SECONDS = 240
MEMORY_BYTES = 2 * 1024**3
FILE_BYTES = 64 * 1024**2
OPEN_FILES = 128


def _limit() -> None:
    import resource

    for name, value in (
        ("RLIMIT_CPU", CPU_SECONDS),
        ("RLIMIT_AS", MEMORY_BYTES),
        ("RLIMIT_FSIZE", FILE_BYTES),
        ("RLIMIT_NOFILE", OPEN_FILES),
        ("RLIMIT_CORE", 0),
    ):
        limit = getattr(resource, name, None)
        if limit is None:
            continue
        try:
            resource.setrlimit(limit, (value, value))
        except (ValueError, OSError):
            # macOS refuses some limits (RLIMIT_AS); the container build is the target.
            continue


def _no_network() -> None:
    def refuse(*_args: Any, **_kwargs: Any) -> NoReturn:
        raise OSError("network disabled in inspection worker")

    socket.socket = refuse  # type: ignore[assignment,misc]
    socket.create_connection = refuse
    socket.getaddrinfo = refuse


def inspect_local(path: Path, hint: str | None) -> dict[str, Any]:
    from app.catalogue.inspect.detect import detect_container
    from app.catalogue.inspect.dmg import inspect_dmg
    from app.catalogue.inspect.pkg_xar import inspect_pkg_file
    from app.catalogue.inspect.result import InspectError
    from app.catalogue.inspect.zip_app import inspect_zip

    try:
        container = detect_container(path, hint)
        if container == "pkg":
            with path.open("rb") as fh:
                result = inspect_pkg_file(fh)
        elif container == "zip":
            result = inspect_zip(path)
        else:
            result = inspect_dmg(path)
        result.validate()
        return {"ok": True, "result": result.to_dict()}
    except InspectError as exc:
        return {"ok": False, "code": exc.code, "detail": _safe_detail(exc.detail)}


def _safe_detail(detail: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in list(detail.items())[:5]:
        if isinstance(value, str):
            out[key] = value[:120]
        elif isinstance(value, list):
            out[key] = [str(v)[:120] for v in value[:5]]
    return out


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        return 2
    _limit()
    _no_network()
    path = Path(argv[1])
    hint = argv[2] if len(argv) > 2 and argv[2] else None
    try:
        payload = inspect_local(path, hint)
    except MemoryError:
        payload = {"ok": False, "code": "INSPECT_RESOURCE_LIMIT", "detail": {}}
    except Exception:  # noqa: BLE001 - every parser failure becomes one safe code
        payload = {"ok": False, "code": "INSPECT_FAILED", "detail": {}}
    sys.stdout.write(json.dumps(payload))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
