"""Microsoft Entra ID OIDC: authorization code flow with PKCE (spec §13.1).

Validates issuer, audience, signature (tenant JWKS, RS256 only), expiry, nonce and tenant.
The stable identity key is `tid:oid`; email is never used to identify a user.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

import httpx
import jwt

from app.core.config import Settings

AUTHORITY = "https://login.microsoftonline.com"
SCOPES = "openid profile email"
_JWKS_TTL_SECONDS = 3600
_CLOCK_SKEW_SECONDS = 60
_HTTP_TIMEOUT = httpx.Timeout(10.0)


class EntraError(Exception):
    """Login failed. `code` is an internal reason for audit; users see a generic message."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class EntraIdentity:
    external_subject: str
    email: str
    display_name: str


def pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def authorization_url(settings: Settings, *, state: str, nonce: str, code_verifier: str) -> str:
    params = {
        "client_id": settings.entra_client_id,
        "response_type": "code",
        "redirect_uri": settings.effective_entra_redirect_uri,
        "response_mode": "query",
        "scope": SCOPES,
        "state": state,
        "nonce": nonce,
        "code_challenge": pkce_challenge(code_verifier),
        "code_challenge_method": "S256",
        "prompt": "select_account",
    }
    return f"{AUTHORITY}/{settings.entra_tenant_id}/oauth2/v2.0/authorize?{urlencode(params)}"


class JwksCache:
    def __init__(self) -> None:
        self._keys: jwt.PyJWKSet | None = None
        self._fetched_at = 0.0

    async def get(
        self, client: httpx.AsyncClient, tenant_id: str, *, refresh: bool
    ) -> jwt.PyJWKSet:
        stale = time.monotonic() - self._fetched_at > _JWKS_TTL_SECONDS
        if self._keys is None or stale or refresh:
            url = f"{AUTHORITY}/{tenant_id}/discovery/v2.0/keys"
            try:
                resp = await client.get(url, timeout=_HTTP_TIMEOUT)
                resp.raise_for_status()
                self._keys = jwt.PyJWKSet.from_dict(resp.json())
            except (httpx.HTTPError, ValueError, jwt.PyJWKSetError) as exc:
                raise EntraError("JWKS_UNAVAILABLE") from exc
            self._fetched_at = time.monotonic()
        return self._keys


async def exchange_code(
    client: httpx.AsyncClient, settings: Settings, *, code: str, code_verifier: str
) -> str:
    if settings.entra_client_secret is None:
        raise EntraError("NOT_CONFIGURED")
    url = f"{AUTHORITY}/{settings.entra_tenant_id}/oauth2/v2.0/token"
    data = {
        "client_id": settings.entra_client_id or "",
        "client_secret": settings.entra_client_secret.get_secret_value(),
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": settings.effective_entra_redirect_uri,
        "code_verifier": code_verifier,
        "scope": SCOPES,
    }
    try:
        resp = await client.post(url, data=data, timeout=_HTTP_TIMEOUT)
    except httpx.HTTPError as exc:
        raise EntraError("TOKEN_ENDPOINT_UNAVAILABLE") from exc
    if resp.status_code != 200:
        raise EntraError("TOKEN_EXCHANGE_REJECTED")
    try:
        id_token = resp.json()["id_token"]
    except (ValueError, KeyError, TypeError) as exc:
        raise EntraError("TOKEN_RESPONSE_INVALID") from exc
    if not isinstance(id_token, str) or len(id_token) > 16_384:
        raise EntraError("TOKEN_RESPONSE_INVALID")
    return id_token


def validate_id_token(
    id_token: str, keys: jwt.PyJWKSet, settings: Settings, *, expected_nonce: str
) -> dict[str, Any]:
    try:
        header = jwt.get_unverified_header(id_token)
    except jwt.PyJWTError as exc:
        raise EntraError("ID_TOKEN_MALFORMED") from exc
    if header.get("alg") != "RS256":
        raise EntraError("ID_TOKEN_ALG_NOT_ALLOWED")
    kid = header.get("kid")
    key = next((k for k in keys.keys if k.key_id == kid), None)
    if key is None:
        raise EntraError("ID_TOKEN_KEY_UNKNOWN")
    try:
        claims: dict[str, Any] = jwt.decode(
            id_token,
            key=key,
            algorithms=["RS256"],
            audience=settings.entra_client_id,
            issuer=settings.entra_issuer,
            leeway=_CLOCK_SKEW_SECONDS,
            options={"require": ["exp", "iat", "iss", "aud", "nonce", "tid", "oid"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise EntraError("ID_TOKEN_EXPIRED") from exc
    except jwt.InvalidAudienceError as exc:
        raise EntraError("ID_TOKEN_AUDIENCE_INVALID") from exc
    except jwt.InvalidIssuerError as exc:
        raise EntraError("ID_TOKEN_ISSUER_INVALID") from exc
    except jwt.PyJWTError as exc:
        raise EntraError("ID_TOKEN_INVALID") from exc
    if not hmac.compare_digest(str(claims["nonce"]), expected_nonce):
        raise EntraError("ID_TOKEN_NONCE_MISMATCH")
    if claims["tid"] != settings.entra_tenant_id:
        raise EntraError("TENANT_NOT_ALLOWED")
    return claims


def identity_from_claims(claims: dict[str, Any]) -> EntraIdentity:
    email = str(claims.get("email") or claims.get("preferred_username") or "").strip().lower()
    if not email or "@" not in email or len(email) > 254:
        raise EntraError("EMAIL_CLAIM_MISSING")
    name = str(claims.get("name") or email).strip()[:120]
    return EntraIdentity(
        external_subject=f"{claims['tid']}:{claims['oid']}", email=email, display_name=name
    )


async def complete_login(
    client: httpx.AsyncClient,
    jwks: JwksCache,
    settings: Settings,
    *,
    code: str,
    code_verifier: str,
    expected_nonce: str,
) -> EntraIdentity:
    if settings.entra_tenant_id is None:
        raise EntraError("NOT_CONFIGURED")
    id_token = await exchange_code(client, settings, code=code, code_verifier=code_verifier)
    keys = await jwks.get(client, settings.entra_tenant_id, refresh=False)
    try:
        claims = validate_id_token(id_token, keys, settings, expected_nonce=expected_nonce)
    except EntraError as exc:
        if exc.code != "ID_TOKEN_KEY_UNKNOWN":
            raise
        # Signing keys rotate; refetch once before failing.
        keys = await jwks.get(client, settings.entra_tenant_id, refresh=True)
        claims = validate_id_token(id_token, keys, settings, expected_nonce=expected_nonce)
    return identity_from_claims(claims)
