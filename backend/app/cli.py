"""Developer CLI. `python -m app.cli seed-dev` creates synthetic local accounts.

Passwords are random per account and written once to a git-ignored, mode-600 file; they are
never logged or printed. Refuses to run in production.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import secrets
import sys
from pathlib import Path

from sqlalchemy import select

from app.audit import service as audit
from app.auth.passwords import hash_password
from app.core.config import REPO_ENV_FILE, get_settings
from app.db.enums import ActorType, AuditResult, IdentityProvider, RoleName
from app.db.session import Database
from app.users.models import LocalCredential, Role, User, UserRole

DEFAULT_OUTPUT = REPO_ENV_FILE.parent / "secrets" / "dev-accounts.txt"
DEFAULT_CERT_DIR = REPO_ENV_FILE.parent / "dev-certs"

DEV_ACCOUNTS: list[tuple[str, str, list[RoleName]]] = [
    ("employee.one@sentinel.test", "Employee One (synthetic)", [RoleName.EMPLOYEE]),
    ("employee.two@sentinel.test", "Employee Two (synthetic)", [RoleName.EMPLOYEE]),
    ("approver@sentinel.test", "Approver (synthetic)", [RoleName.EMPLOYEE, RoleName.APPROVER]),
    (
        "software.admin@sentinel.test",
        "Software Admin (synthetic)",
        [RoleName.EMPLOYEE, RoleName.SOFTWARE_ADMIN],
    ),
    (
        "security.admin@sentinel.test",
        "Security Admin (synthetic)",
        [RoleName.EMPLOYEE, RoleName.SECURITY_ADMIN],
    ),
    ("auditor@sentinel.test", "Auditor (synthetic)", [RoleName.AUDITOR]),
    (
        "platform.admin@sentinel.test",
        "Platform Admin (synthetic)",
        [RoleName.EMPLOYEE, RoleName.PLATFORM_ADMIN],
    ),
]


async def seed_dev(output: Path, reset_passwords: bool) -> int:
    settings = get_settings()
    if settings.is_production:
        print("refusing to seed development accounts in production", file=sys.stderr)
        return 2
    db = Database(settings)
    created: list[tuple[str, str]] = []
    try:
        async with db.sessionmaker() as session:
            role_ids = dict((await session.execute(select(Role.name, Role.id))).all())
            for email, display_name, roles in DEV_ACCOUNTS:
                user = await session.scalar(select(User).where(User.email == email))
                password = secrets.token_urlsafe(18)
                if user is None:
                    user = User(
                        email=email,
                        display_name=display_name,
                        identity_provider=IdentityProvider.LOCAL,
                        is_active=True,
                    )
                    session.add(user)
                    await session.flush()
                    session.add(
                        LocalCredential(user_id=user.id, password_hash=hash_password(password))
                    )
                    for role in roles:
                        session.add(UserRole(user_id=user.id, role_id=role_ids[role.value]))
                    action = "DEV_USER_SEEDED"
                elif reset_passwords:
                    credential = await session.get(LocalCredential, user.id)
                    if credential is None:
                        continue
                    credential.password_hash = hash_password(password)
                    action = "DEV_PASSWORD_RESET"
                else:
                    continue
                await audit.record(
                    session,
                    action=action,
                    resource_type="user",
                    resource_id=user.id,
                    result=AuditResult.SUCCESS,
                    actor_type=ActorType.SYSTEM,
                    metadata={"roles": [r.value for r in roles]},
                )
                created.append((email, password))
            await session.commit()
    finally:
        await db.dispose()

    if not created:
        print("No accounts created or reset (use --reset-passwords to rotate).")
        return 0
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write("# Synthetic SentinelDesk development accounts. Do not reuse these passwords.\n")
        for email, password in created:
            fh.write(f"{email}\t{password}\n")
    print(f"Wrote {len(created)} account credential(s) to {output} (mode 600).")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="python -m app.cli")
    sub = parser.add_subparsers(dest="command", required=True)
    seed = sub.add_parser("seed-dev", help="Create synthetic local development accounts")
    seed.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    seed.add_argument("--reset-passwords", action="store_true")
    certs = sub.add_parser("dev-certs", help="Create a development CA and loopback TLS cert")
    certs.add_argument("--dir", type=Path, default=DEFAULT_CERT_DIR)
    certs.add_argument("--force", action="store_true", help="Replace existing files")
    sub.add_parser(
        "seed-catalogue",
        help="Insert synthetic demo catalogue entries (VS Code, Git, incompatible Windows package)",
    )
    sub.add_parser(
        "seed-security",
        help="Seed bans, software policies and the synthetic demo-malware-sample fixture",
    )
    sub.add_parser(
        "purge-expired",
        help="Purge expired sessions/OIDC/throttle/tokens and expire abandoned jobs (Phase 9)",
    )
    args = parser.parse_args()
    if args.command == "seed-dev":
        return asyncio.run(seed_dev(args.output, args.reset_passwords))
    if args.command == "dev-certs":
        return dev_certs(args.dir, args.force)
    if args.command == "seed-catalogue":
        return asyncio.run(seed_catalogue())
    if args.command == "seed-security":
        return asyncio.run(seed_security())
    if args.command == "purge-expired":
        return asyncio.run(purge_expired_cmd())
    return 1


async def seed_catalogue() -> int:
    from app.catalogue.seed import seed_catalogue as run_seed

    settings = get_settings()
    if settings.is_production:
        print("refusing to seed development catalogue in production", file=sys.stderr)
        return 2
    db = Database(settings)
    try:
        async with db.sessionmaker() as session:
            counts = await run_seed(session)
    finally:
        await db.dispose()
    print(
        "Catalogue seed complete: "
        f"{counts['software']} software, {counts['versions']} versions, "
        f"{counts['aliases']} aliases created "
        "(existing rows left unchanged)."
    )
    return 0


async def seed_security() -> int:
    from app.security.seed import seed_security as run_seed

    settings = get_settings()
    if settings.is_production:
        print("refusing to seed development security fixtures in production", file=sys.stderr)
        return 2
    db = Database(settings)
    try:
        async with db.sessionmaker() as session:
            counts = await run_seed(session)
    finally:
        await db.dispose()
    print(
        "Security seed complete: "
        f"{counts.get('bans', 0)} bans, {counts.get('policies', 0)} policies, "
        f"{counts.get('malware_sample', 0)} malware fixture "
        "(existing rows left unchanged)."
    )
    return 0


async def purge_expired_cmd() -> int:
    from app.ops.retention import purge_expired, summarize

    settings = get_settings()
    db = Database(settings)
    try:
        async with db.sessionmaker() as session:
            counts = await purge_expired(session)
    finally:
        await db.dispose()
    print(f"purge-expired complete: {summarize(counts)}")
    return 0


def dev_certs(directory: Path, force: bool) -> int:
    from app.devtools.certs import generate

    if os.environ.get("APP_ENV") == "production":
        print("refusing to create development certificates in production", file=sys.stderr)
        return 2
    try:
        paths = generate(directory, force=force)
    except FileExistsError as exc:
        print(f"{exc}", file=sys.stderr)
        return 0
    print(f"Wrote dev CA {paths.ca_cert} and server certificate for localhost/127.0.0.1/::1.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
