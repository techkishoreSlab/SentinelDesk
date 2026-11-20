"""Opaque high-entropy tokens. Only SHA-256 digests are persisted."""

from __future__ import annotations

import hashlib
import hmac
import secrets


def new_token(num_bytes: int = 32) -> str:
    return secrets.token_urlsafe(num_bytes)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def token_matches(token: str, expected_hash: str) -> bool:
    return hmac.compare_digest(hash_token(token), expected_hash)


def pseudonymize(value: str) -> str:
    """Stable, non-reversible identifier for audit/throttle keys (e.g. a failed-login email)."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:32]
