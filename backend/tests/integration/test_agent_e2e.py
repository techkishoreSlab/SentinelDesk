"""Cross-component test: the real Rust agent binary against the backend over pinned TLS.

The backend runs in a background uvicorn server with a throwaway dev CA. The agent uses the
file credential store inside a temp directory, so nothing touches the user's Keychain.
Requires the agent binary (`cargo build` in endpoint/, or SENTINEL_AGENT_BIN).
"""

from __future__ import annotations

import json
import os
import socket
import stat
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
import uvicorn
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncEngine

from app.core.config import Settings
from app.db.session import Database
from app.devices.models import Device, DeviceCredential
from app.devtools import certs
from app.main import create_app
from tests.integration.conftest import BACKEND_DIR, SeededUser, csrf_headers
from tests.integration.test_agent_api import new_token, people  # noqa: F401

DEFAULT_BIN = BACKEND_DIR.parent / "endpoint" / "target" / "debug" / "sentinel-agent"


@pytest.fixture(scope="module")
def agent_bin() -> Path:
    configured = os.environ.get("SENTINEL_AGENT_BIN")
    path = Path(configured) if configured else DEFAULT_BIN
    if not path.is_file():
        if configured:
            pytest.fail(f"SENTINEL_AGENT_BIN={configured} does not exist")
        pytest.skip("agent binary not built; run `cargo build` in endpoint/")
    return path


@pytest.fixture(scope="module")
def tls(tmp_path_factory: pytest.TempPathFactory) -> certs.CertPaths:
    return certs.generate(tmp_path_factory.mktemp("tls") / "certs")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port: int = s.getsockname()[1]
        return port


@pytest.fixture
def tls_backend(settings: Settings, tls: certs.CertPaths) -> Iterator[str]:
    port = _free_port()
    app = create_app(settings, Database(settings))
    server = uvicorn.Server(
        uvicorn.Config(
            app,
            host="127.0.0.1",
            port=port,
            ssl_certfile=str(tls.server_cert),
            ssl_keyfile=str(tls.server_key),
            log_level="warning",
            proxy_headers=False,
        )
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 15
    while not server.started:
        if time.monotonic() > deadline or not thread.is_alive():
            pytest.fail("TLS backend did not start")
        time.sleep(0.05)
    yield f"https://localhost:{port}"
    server.should_exit = True
    thread.join(timeout=15)


class Agent:
    def __init__(self, binary: Path, home: Path, backend: str, ca: Path) -> None:
        self.binary, self.home, self.backend, self.ca = binary, home, backend, ca
        self.config_dir = home / "agent-config"
        self.transcript: list[str] = []

    def run(self, *args: str, token: str | None = None) -> subprocess.CompletedProcess[str]:
        env = {"PATH": os.environ.get("PATH", ""), "HOME": str(self.home)}
        if token is not None:
            env["SENTINEL_ENROLLMENT_TOKEN"] = token
        proc = subprocess.run(  # noqa: S603 - fixed binary and test-controlled arguments
            [str(self.binary), *args, "--config-dir", str(self.config_dir)],
            env=env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        self.transcript += [proc.stdout, proc.stderr]
        return proc

    def enroll(self, token: str, ca: Path | None = None, *extra: str) -> Any:
        return self.run(
            "enroll",
            "--backend",
            self.backend,
            "--ca-cert",
            str(ca or self.ca),
            "--credential-store",
            "file",
            *extra,
            token=token,
        )


def last_json(output: str) -> dict[str, Any]:
    line = [ln for ln in output.splitlines() if ln.strip()][-1]
    parsed: dict[str, Any] = json.loads(line)
    return parsed


async def allow_next_heartbeat(owner_engine: AsyncEngine) -> None:
    async with owner_engine.begin() as conn:
        await conn.execute(text("UPDATE devices SET last_seen_at = now() - interval '1 minute'"))


async def test_agent_lifecycle_over_pinned_tls(
    client: httpx.AsyncClient,
    people: dict[str, SeededUser],  # noqa: F811
    app_db: Database,
    owner_engine: AsyncEngine,
    agent_bin: Path,
    tls_backend: str,
    tls: certs.CertPaths,
    tmp_path: Path,
) -> None:
    agent = Agent(agent_bin, tmp_path, tls_backend, tls.ca_cert)
    token = await new_token(client, people["owner"])

    # A server certificate from any other CA is rejected, and the token is not consumed.
    rogue = certs.generate(tmp_path / "rogue")
    proc = agent.enroll(token, rogue.ca_cert)
    assert proc.returncode == 1
    assert "TLS verification failed" in proc.stderr
    assert not agent.config_dir.joinpath("agent-state.json").exists()

    proc = agent.enroll(token)
    assert proc.returncode == 0, proc.stderr
    enrolled = last_json(proc.stdout)
    device_id = enrolled["device_id"]
    assert enrolled["credential_store"] == "file"
    assert stat.S_IMODE(agent.config_dir.stat().st_mode) == 0o700
    for f in agent.config_dir.iterdir():
        assert stat.S_IMODE(f.stat().st_mode) == 0o600, f
    cred_file = agent.config_dir / f"device-credential-{device_id}"
    first_credential = cred_file.read_text()
    assert first_credential.startswith("sdc_")

    async with app_db.sessionmaker() as s:
        device = await s.get(Device, device_id)
        assert device is not None
        assert device.device_status == "ACTIVE"
        assert device.os_family == {"darwin": "macos", "win32": "windows"}.get(
            sys.platform, "linux"
        )
        assert device.owner_user_id == people["owner"].id

    # One-time token: a second enrollment with the same token is refused.
    proc = agent.enroll(token, None, "--force")
    assert proc.returncode == 1
    assert "ENROLLMENT_TOKEN_INVALID" in proc.stderr
    # A failed re-enrollment leaves the existing enrollment intact.
    status = last_json(agent.run("status").stdout)
    assert status["device_id"] == device_id
    assert status["credential_present"] is True
    old_cred_file = cred_file

    proc = agent.enroll(await new_token(client, people["owner"]), None, "--force")
    assert proc.returncode == 0, proc.stderr
    device_id = last_json(proc.stdout)["device_id"]
    assert not old_cred_file.exists()
    cred_file = agent.config_dir / f"device-credential-{device_id}"
    first_credential = cred_file.read_text()

    await allow_next_heartbeat(owner_engine)
    proc = agent.run("heartbeat")
    assert proc.returncode == 0, proc.stderr
    hb = last_json(proc.stdout)
    assert hb["device_status"] == "ACTIVE"
    assert hb["device_id"] == device_id

    await allow_next_heartbeat(owner_engine)
    proc = agent.run("rotate-credential")
    assert proc.returncode == 0, proc.stderr
    second_credential = cred_file.read_text()
    assert second_credential != first_credential
    async with app_db.sessionmaker() as s:
        creds = (
            await s.scalars(select(DeviceCredential).where(DeviceCredential.device_id == device_id))
        ).all()
        assert sum(c.revoked_at is None for c in creds) == 1

    status = last_json(agent.run("status").stdout)
    assert status["credential_present"] is True
    assert status["device_id"] == device_id

    # Quarantine revokes the credential; the long-running loop stops with exit code 3.
    resp = await client.post(
        f"/api/v1/admin/devices/{device_id}/quarantine",
        json={"reason": "SUSPECTED_COMPROMISE"},
        headers=csrf_headers(client),
    )
    assert resp.status_code == 204, resp.text
    await allow_next_heartbeat(owner_engine)
    proc = agent.run("run", "--max-cycles", "3")
    assert proc.returncode == 3, proc.stderr
    assert "agent_auth_revoked" in proc.stderr

    proc = agent.run("forget", "--yes")
    assert proc.returncode == 0, proc.stderr
    assert not any(agent.config_dir.iterdir())

    # Secrets never appear in agent output.
    output = "\n".join(agent.transcript)
    for secret in (token, first_credential, second_credential):
        assert secret not in output
    assert "sdc_" not in output
    assert "sde_" not in output
