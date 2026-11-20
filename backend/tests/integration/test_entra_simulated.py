"""Entra OIDC callback flow against a SIMULATED identity provider.

The token and JWKS endpoints are served by an in-process mock transport using RSA keys
generated in the test. This proves our state/nonce/PKCE/JIT handling, not interoperability
with Microsoft; the live tenant test is a separate manual step.
"""

from __future__ import annotations

import time
from collections.abc import AsyncIterator
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm
from sqlalchemy import func, select

from app.audit.models import AuditEvent
from app.auth.entra import pkce_challenge
from app.core.config import Settings
from app.db.enums import RoleName
from app.db.session import Database
from app.main import create_app
from app.users.models import User
from tests.conftest import make_settings
from tests.integration.conftest import WEB_ORIGIN

TENANT = "11111111-2222-3333-4444-555555555555"
CLIENT_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
OID = "00000000-0000-0000-0000-0000000000aa"


class FakeIdp:
    def __init__(self) -> None:
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.challenge: str | None = None
        self.nonce: str | None = None
        self.claim_overrides: dict[str, Any] = {}
        self.token_requests = 0

    def jwks(self) -> dict[str, Any]:
        jwk: dict[str, Any] = RSAAlgorithm.to_jwk(self.key.public_key(), as_dict=True)
        jwk.update({"kid": "sim-1", "use": "sig", "alg": "RS256"})
        return {"keys": [jwk]}

    def id_token(self) -> str:
        now = int(time.time())
        claims: dict[str, Any] = {
            "iss": f"https://login.microsoftonline.com/{TENANT}/v2.0",
            "aud": CLIENT_ID,
            "iat": now,
            "exp": now + 600,
            "nonce": self.nonce,
            "tid": TENANT,
            "oid": OID,
            "preferred_username": "new.person@contoso.test",
            "name": "New Person",
        }
        claims.update(self.claim_overrides)
        return jwt.encode(claims, self.key, algorithm="RS256", headers={"kid": "sim-1"})

    def handler(self, request: httpx.Request) -> httpx.Response:
        if request.url.path == f"/{TENANT}/discovery/v2.0/keys":
            return httpx.Response(200, json=self.jwks())
        if request.url.path == f"/{TENANT}/oauth2/v2.0/token":
            self.token_requests += 1
            form = parse_qs(request.content.decode())
            verifier = form["code_verifier"][0]
            if pkce_challenge(verifier) != self.challenge or form["code"] != ["good-code"]:
                return httpx.Response(400, json={"error": "invalid_grant"})
            return httpx.Response(200, json={"id_token": self.id_token()})
        return httpx.Response(404)


@pytest.fixture
def idp() -> FakeIdp:
    return FakeIdp()


@pytest.fixture
def entra_settings(migrated_database: tuple[str, str]) -> Settings:
    return make_settings(
        database_url=migrated_database[0],
        cors_allowed_origins=WEB_ORIGIN,
        web_base_url=WEB_ORIGIN,
        entra_tenant_id=TENANT,
        entra_client_id=CLIENT_ID,
        entra_client_secret="simulated-not-a-secret",
    )


@pytest.fixture
async def entra_client(
    entra_settings: Settings, idp: FakeIdp
) -> AsyncIterator[tuple[httpx.AsyncClient, Database]]:
    db = Database(entra_settings)
    outbound = httpx.AsyncClient(transport=httpx.MockTransport(idp.handler))
    app = create_app(entra_settings, db, http_client=outbound)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    ) as c:
        yield c, db
    await outbound.aclose()
    await db.dispose()


async def _start(client: httpx.AsyncClient, idp: FakeIdp) -> str:
    resp = await client.get("/api/v1/auth/entra/login")
    assert resp.status_code == 302
    location = urlparse(resp.headers["location"])
    assert location.netloc == "login.microsoftonline.com"
    params = parse_qs(location.query)
    assert params["redirect_uri"] == [f"{WEB_ORIGIN}/api/v1/auth/callback"]
    idp.challenge, idp.nonce = params["code_challenge"][0], params["nonce"][0]
    return params["state"][0]


async def _reasons(db: Database) -> list[str | None]:
    async with db.sessionmaker() as s:
        rows = await s.scalars(
            select(AuditEvent.reason_code)
            .where(AuditEvent.action == "LOGIN_FAILED")
            .order_by(AuditEvent.seq)
        )
        return list(rows.all())


async def test_simulated_callback_provisions_employee_and_rejects_replay(
    entra_client: tuple[httpx.AsyncClient, Database], idp: FakeIdp
) -> None:
    client, db = entra_client
    assert (await client.get("/api/v1/auth/providers")).json()["entra"] is True
    state = await _start(client, idp)

    cb = await client.get(f"/api/v1/auth/callback?code=good-code&state={state}")
    assert cb.status_code == 302
    assert cb.headers["location"] == f"{WEB_ORIGIN}/"
    me = (await client.get("/api/v1/me")).json()
    assert me["identity_provider"] == "entra"
    assert me["roles"] == [RoleName.EMPLOYEE.value]
    assert me["email"] == "new.person@contoso.test"

    replay = await client.get(f"/api/v1/auth/callback?code=good-code&state={state}")
    assert replay.headers["location"] == f"{WEB_ORIGIN}/?login_error=LOGIN_FAILED"
    assert idp.token_requests == 1
    assert await _reasons(db) == ["STATE_INVALID"]

    # A second login with the same tid:oid reuses the account even if the email changed.
    idp.claim_overrides = {"preferred_username": "renamed@contoso.test"}
    state = await _start(client, idp)
    await client.get(f"/api/v1/auth/callback?code=good-code&state={state}")
    async with db.sessionmaker() as s:
        assert await s.scalar(select(func.count()).select_from(User)) == 1


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"nonce": "attacker-nonce"}, "ID_TOKEN_NONCE_MISMATCH"),
        ({"tid": "99999999-2222-3333-4444-555555555555"}, "ID_TOKEN_ISSUER_INVALID"),
        ({"aud": "someone-else"}, "ID_TOKEN_AUDIENCE_INVALID"),
        ({"exp": int(time.time()) - 3600}, "ID_TOKEN_EXPIRED"),
    ],
)
async def test_simulated_callback_rejects_bad_tokens(
    entra_client: tuple[httpx.AsyncClient, Database],
    idp: FakeIdp,
    overrides: dict[str, Any],
    reason: str,
) -> None:
    client, db = entra_client
    state = await _start(client, idp)
    idp.claim_overrides = overrides
    if "tid" in overrides:
        idp.claim_overrides["iss"] = f"https://login.microsoftonline.com/{overrides['tid']}/v2.0"
    cb = await client.get(f"/api/v1/auth/callback?code=good-code&state={state}")
    assert cb.headers["location"] == f"{WEB_ORIGIN}/?login_error=LOGIN_FAILED"
    assert "sd_session" not in cb.headers.get("set-cookie", "")
    assert await _reasons(db) == [reason]


async def test_simulated_callback_wrong_code_and_idp_error(
    entra_client: tuple[httpx.AsyncClient, Database], idp: FakeIdp
) -> None:
    client, db = entra_client
    state = await _start(client, idp)
    bad = await client.get(f"/api/v1/auth/callback?code=stolen-code&state={state}")
    assert bad.headers["location"].endswith("login_error=LOGIN_FAILED")
    denied = await client.get("/api/v1/auth/callback?error=access_denied&state=x")
    assert denied.headers["location"].endswith("login_error=LOGIN_FAILED")
    assert await _reasons(db) == ["TOKEN_EXCHANGE_REJECTED", "IDP_ERROR"]


async def test_simulated_callback_email_conflict_requires_linking(
    entra_client: tuple[httpx.AsyncClient, Database], idp: FakeIdp, make_user
) -> None:
    client, db = entra_client
    await make_user("new.person@contoso.test", [RoleName.PLATFORM_ADMIN])
    state = await _start(client, idp)
    cb = await client.get(f"/api/v1/auth/callback?code=good-code&state={state}")
    assert cb.headers["location"] == f"{WEB_ORIGIN}/?login_error=ACCOUNT_LINK_REQUIRED"
    async with db.sessionmaker() as s:
        assert await s.scalar(select(func.count()).select_from(User)) == 1
    assert await _reasons(db) == ["EMAIL_ALREADY_LINKED"]
