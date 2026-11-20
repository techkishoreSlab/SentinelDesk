"""Ed25519 job envelope signing and verification."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from app.core.config import Settings
from app.core.errors import AppError


def canonical_envelope(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def load_private_key(path: Path) -> Ed25519PrivateKey:
    raw = path.read_bytes()
    key = serialization.load_pem_private_key(raw, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise AppError("INTERNAL_ERROR", 500)
    return key


def load_public_key(path: Path) -> Ed25519PublicKey:
    raw = path.read_bytes()
    key = serialization.load_pem_public_key(raw)
    if not isinstance(key, Ed25519PublicKey):
        raise AppError("INTERNAL_ERROR", 500)
    return key


def sign_envelope(settings: Settings, payload: dict[str, Any]) -> str:
    if not settings.job_signing_private_key_path:
        raise AppError("INTEGRATION_NOT_CONFIGURED", 503)
    key = load_private_key(settings.job_signing_private_key_path)
    sig = key.sign(canonical_envelope(payload))
    return base64.b64encode(sig).decode("ascii")


def verify_envelope(settings: Settings, payload: dict[str, Any], signature_b64: str) -> bool:
    if not settings.job_signing_public_key_path:
        return False
    key = load_public_key(settings.job_signing_public_key_path)
    try:
        sig = base64.b64decode(signature_b64, validate=True)
        key.verify(sig, canonical_envelope(payload))
    except Exception:  # noqa: BLE001 — decode/verify failures are treated as invalid
        return False
    return True
