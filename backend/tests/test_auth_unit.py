"""Unit tests for password hashing, RBAC, audit hashing and Entra ID-token validation.

Entra tests use RSA keys generated locally in the test; no Microsoft endpoint is contacted.
"""

from __future__ import annotations

import time
import uuid
from datetime import UTC, datetime
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from app.audit.models import AuditEvent
from app.audit.service import GENESIS_HASH, _validate_metadata, compute_event_hash
from app.auth import entra
from app.auth.passwords import hash_password, needs_rehash, verify_password
from app.auth.rbac import ROLE_PERMISSIONS, Permission, permissions_for
from app.auth.schemas import LoginRequest
from app.auth.tokens import hash_token, new_token, pseudonymize, token_matches
from app.db.enums import RoleName
from tests.conftest import make_settings

# --- passwords -----------------------------------------------------------------------------


def test_password_hash_roundtrip_and_rejects_wrong_password() -> None:
    stored = hash_password("correct horse battery")
    assert stored.startswith("$argon2id$")
    assert verify_password(stored, "correct horse battery")
    assert not verify_password(stored, "correct horse batterY")
    assert not needs_rehash(stored)


def test_password_length_bounds() -> None:
    with pytest.raises(ValueError):
        hash_password("short")
    with pytest.raises(ValueError):
        hash_password("x" * 257)
    assert not verify_password(hash_password("y" * 20), "y" * 300)


def test_missing_account_never_verifies() -> None:
    assert not verify_password(None, "sentineldesk-timing-equaliser-not-a-password")


def test_invalid_stored_hash_fails_closed() -> None:
    assert not verify_password("not-a-hash", "whatever-password")


# --- tokens and input --------------------------------------------------------------------


def test_tokens_are_random_and_compared_by_hash() -> None:
    a, b = new_token(), new_token()
    assert a != b
    assert len(hash_token(a)) == 64
    assert token_matches(a, hash_token(a))
    assert not token_matches(b, hash_token(a))
    assert pseudonymize("A@x.test") == pseudonymize("A@x.test")
    assert "x.test" not in pseudonymize("A@x.test")


def test_login_email_is_normalized_and_validated() -> None:
    assert LoginRequest(email="  Alice@Example.TEST ", password="p").email == "alice@example.test"
    with pytest.raises(ValueError):
        LoginRequest(email="no-at-sign", password="p")
    with pytest.raises(ValueError):
        LoginRequest(email="a@b.test", password="p", extra="x")  # type: ignore[call-arg]


# --- RBAC ----------------------------------------------------------------------------------


def test_every_role_has_permissions() -> None:
    assert set(ROLE_PERMISSIONS) == {r.value for r in RoleName}


def test_auditor_is_read_only() -> None:
    perms = permissions_for(frozenset({RoleName.AUDITOR.value}))
    assert perms == frozenset({Permission.AUDIT_READ})


def test_employee_cannot_administer() -> None:
    perms = permissions_for(frozenset({RoleName.EMPLOYEE.value}))
    assert Permission.REQUEST_CREATE in perms
    for admin in (Permission.ROLE_ASSIGN, Permission.AUDIT_READ, Permission.APPROVAL_DECIDE):
        assert admin not in perms


def test_unknown_role_grants_nothing() -> None:
    assert permissions_for(frozenset({"SUPERUSER"})) == frozenset()


def test_permissions_union_across_roles() -> None:
    perms = permissions_for(frozenset({RoleName.EMPLOYEE.value, RoleName.APPROVER.value}))
    assert {Permission.REQUEST_CREATE, Permission.APPROVAL_DECIDE} <= perms


# --- audit hashing -------------------------------------------------------------------------


def _event(**overrides: Any) -> AuditEvent:
    values: dict[str, Any] = {
        "id": uuid.UUID(int=1),
        "occurred_at": datetime(2026, 1, 1, tzinfo=UTC),
        "actor_type": "USER",
        "actor_id": uuid.UUID(int=2),
        "action": "LOGIN_SUCCEEDED",
        "resource_type": "session",
        "resource_id": "abc",
        "correlation_id": None,
        "source_ip": "127.0.0.1",
        "result": "SUCCESS",
        "reason_code": None,
        "metadata_": {"provider": "local"},
    }
    values.update(overrides)
    return AuditEvent(**values)


def test_event_hash_is_deterministic_and_chained() -> None:
    h1 = compute_event_hash(GENESIS_HASH, _event())
    assert h1 == compute_event_hash(GENESIS_HASH, _event())
    assert h1 != compute_event_hash("1" * 64, _event())


@pytest.mark.parametrize(
    "change",
    [
        {"action": "LOGIN_FAILED"},
        {"result": "DENIED"},
        {"actor_id": uuid.UUID(int=3)},
        {"metadata_": {"provider": "entra"}},
        {"occurred_at": datetime(2026, 1, 1, 0, 0, 1, tzinfo=UTC)},
    ],
)
def test_any_field_change_alters_hash(change: dict[str, Any]) -> None:
    assert compute_event_hash(GENESIS_HASH, _event()) != compute_event_hash(
        GENESIS_HASH, _event(**change)
    )


@pytest.mark.parametrize(
    "metadata",
    [
        {"password": "x"},
        {"session_token": "x"},
        {"gemini_prompt": "x"},
        {"Bad-Key": "x"},
        {"nested": {"a": 1}},
        {f"k{i}": i for i in range(21)},
    ],
)
def test_audit_metadata_rejects_sensitive_or_unbounded(metadata: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        _validate_metadata(metadata)


def test_audit_metadata_truncates_strings() -> None:
    clean = _validate_metadata({"note": "x" * 500, "roles": ["a"] * 50})
    assert clean["note"] == "x" * 200
    assert clean["roles"] == ["a"] * 20


# --- Entra ID-token validation -------------------------------------------------------------

TENANT = "11111111-2222-3333-4444-555555555555"
CLIENT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


@pytest.fixture(scope="module")
def rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _jwks(key: rsa.RSAPrivateKey, kid: str = "k1") -> jwt.PyJWKSet:
    jwk: dict[str, Any] = RSAAlgorithm.to_jwk(key.public_key(), as_dict=True)
    jwk.update({"kid": kid, "use": "sig", "alg": "RS256"})
    return jwt.PyJWKSet.from_dict({"keys": [jwk]})


def _token(key: rsa.RSAPrivateKey, kid: str = "k1", alg: str = "RS256", **claims: Any) -> str:
    now = int(time.time())
    payload: dict[str, Any] = {
        "iss": f"https://login.microsoftonline.com/{TENANT}/v2.0",
        "aud": CLIENT,
        "iat": now,
        "nbf": now,
        "exp": now + 600,
        "nonce": "n-123",
        "tid": TENANT,
        "oid": "00000000-0000-0000-0000-00000000abcd",
        "preferred_username": "Person@Contoso.TEST",
        "name": "Test Person",
    }
    payload.update(claims)
    payload = {k: v for k, v in payload.items() if v is not None}
    return jwt.encode(payload, key, algorithm=alg, headers={"kid": kid})


def _entra_settings() -> Any:
    return make_settings(
        entra_tenant_id=TENANT, entra_client_id=CLIENT, entra_client_secret="test-not-a-secret"
    )


def test_valid_id_token_yields_tid_oid_identity(rsa_key: rsa.RSAPrivateKey) -> None:
    claims = entra.validate_id_token(
        _token(rsa_key), _jwks(rsa_key), _entra_settings(), expected_nonce="n-123"
    )
    identity = entra.identity_from_claims(claims)
    assert identity.external_subject == f"{TENANT}:00000000-0000-0000-0000-00000000abcd"
    assert identity.email == "person@contoso.test"


@pytest.mark.parametrize(
    ("claims", "code"),
    [
        ({"aud": "other-client"}, "ID_TOKEN_AUDIENCE_INVALID"),
        ({"iss": "https://login.microsoftonline.com/other/v2.0"}, "ID_TOKEN_ISSUER_INVALID"),
        ({"exp": int(time.time()) - 3600}, "ID_TOKEN_EXPIRED"),
        ({"nonce": "attacker"}, "ID_TOKEN_NONCE_MISMATCH"),
        ({"tid": "99999999-2222-3333-4444-555555555555"}, "TENANT_NOT_ALLOWED"),
        ({"oid": None}, "ID_TOKEN_INVALID"),
        ({"nonce": None}, "ID_TOKEN_INVALID"),
    ],
)
def test_id_token_rejections(rsa_key: rsa.RSAPrivateKey, claims: dict[str, Any], code: str) -> None:
    with pytest.raises(entra.EntraError) as exc:
        entra.validate_id_token(
            _token(rsa_key, **claims), _jwks(rsa_key), _entra_settings(), expected_nonce="n-123"
        )
    assert exc.value.code == code


def test_id_token_signed_by_other_key_rejected(rsa_key: rsa.RSAPrivateKey) -> None:
    attacker = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(entra.EntraError) as exc:
        entra.validate_id_token(
            _token(attacker), _jwks(rsa_key), _entra_settings(), expected_nonce="n-123"
        )
    assert exc.value.code == "ID_TOKEN_INVALID"


def test_id_token_unknown_kid_and_hs256_rejected(rsa_key: rsa.RSAPrivateKey) -> None:
    settings = _entra_settings()
    with pytest.raises(entra.EntraError) as exc:
        entra.validate_id_token(
            _token(rsa_key, kid="rotated"), _jwks(rsa_key), settings, expected_nonce="n-123"
        )
    assert exc.value.code == "ID_TOKEN_KEY_UNKNOWN"
    hs = jwt.encode({"sub": "x"}, "k" * 32, algorithm="HS256", headers={"kid": "k1"})
    with pytest.raises(entra.EntraError) as exc:
        entra.validate_id_token(hs, _jwks(rsa_key), settings, expected_nonce="n-123")
    assert exc.value.code == "ID_TOKEN_ALG_NOT_ALLOWED"


def test_authorization_url_uses_pkce_s256(rsa_key: rsa.RSAPrivateKey) -> None:
    url = entra.authorization_url(_entra_settings(), state="s", nonce="n", code_verifier="v" * 43)
    assert url.startswith(f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/authorize?")
    assert "code_challenge_method=S256" in url
    assert f"code_challenge={entra.pkce_challenge('v' * 43)}" in url
    assert "v" * 43 not in url
