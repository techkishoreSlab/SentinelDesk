"""Unit tests for Ed25519 job envelope signing."""

from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.jobs.signing import sign_envelope, verify_envelope
from tests.conftest import make_settings


def _write_keypair(tmp_path: Path) -> tuple[Path, Path]:
    private = Ed25519PrivateKey.generate()
    priv_path = tmp_path / "job_signing_private.pem"
    pub_path = tmp_path / "job_signing_public.pem"
    priv_path.write_bytes(
        private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    pub_path.write_bytes(
        private.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return priv_path, pub_path


def test_sign_and_verify_round_trip(tmp_path: Path) -> None:
    priv, pub = _write_keypair(tmp_path)
    settings = make_settings(
        job_signing_private_key_path=priv,
        job_signing_public_key_path=pub,
    )
    payload = {
        "job_id": "11111111-1111-1111-1111-111111111111",
        "device_id": "22222222-2222-2222-2222-222222222222",
        "nonce": "abc",
        "package_digest": "a" * 64,
    }
    sig = sign_envelope(settings, payload)
    assert verify_envelope(settings, payload, sig)
    assert not verify_envelope(settings, {**payload, "nonce": "mutated"}, sig)


def test_canonical_envelope_matches_agent_rust_format() -> None:
    from app.jobs.signing import canonical_envelope

    payload = {"b": 2, "a": None, "nested": {"z": True, "y": "x"}}
    assert canonical_envelope(payload) == b'{"a":null,"b":2,"nested":{"y":"x","z":true}}'
