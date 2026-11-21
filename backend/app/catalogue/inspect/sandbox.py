"""Run the inspection worker as a child process and validate what it returns."""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import sys
from pathlib import Path

from app.catalogue.inspect.result import InspectError, Inspection

_BACKEND_ROOT = Path(__file__).resolve().parents[3]
MAX_OUTPUT = 64 * 1024
WALL_SECONDS = 300


async def inspect_sandboxed(
    path: Path,
    filename_hint: str | None,
    *,
    seven_zip_path: str,
    timeout: float = WALL_SECONDS,
) -> Inspection:
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(path.parent),
        "LANG": "C.UTF-8",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONPATH": str(_BACKEND_ROOT),
        "MALLOC_ARENA_MAX": "2",
        "SENTINEL_7ZZ": seven_zip_path,
    }
    proc = await asyncio.create_subprocess_exec(
        sys.executable,
        "-B",
        "-m",
        "app.catalogue.inspect.worker",
        str(path),
        filename_hint or "",
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
        cwd=str(path.parent),
        env=env,
        start_new_session=True,
    )
    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except TimeoutError as exc:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(proc.pid, 9)
        await proc.wait()
        raise InspectError("INSPECT_TIMEOUT") from exc
    if proc.returncode != 0 or not stdout or len(stdout) > MAX_OUTPUT:
        # Killed by a resource limit (CPU, memory) or crashed.
        raise InspectError("INSPECT_RESOURCE_LIMIT")
    try:
        payload = json.loads(stdout)
    except ValueError as exc:
        raise InspectError("INSPECT_FAILED") from exc
    if not isinstance(payload, dict):
        raise InspectError("INSPECT_FAILED")
    if not payload.get("ok"):
        detail = payload.get("detail") if isinstance(payload.get("detail"), dict) else {}
        raise InspectError(str(payload.get("code") or "INSPECT_FAILED")[:60], **(detail or {}))
    result = payload.get("result")
    if not isinstance(result, dict):
        raise InspectError("INSPECT_FAILED")
    try:
        return Inspection.from_dict(result)
    except (KeyError, TypeError) as exc:
        raise InspectError("INSPECT_FAILED") from exc
