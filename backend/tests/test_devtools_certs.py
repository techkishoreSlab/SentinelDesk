"""Development TLS material: correct chain, names, key usage and file permissions."""

from __future__ import annotations

import ipaddress
import stat
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID

from app.devtools import certs


def _load(path: Path) -> x509.Certificate:
    return x509.load_pem_x509_certificate(path.read_bytes())


def test_generates_ca_and_loopback_server_cert(tmp_path: Path) -> None:
    paths = certs.generate(tmp_path / "dev-certs")
    ca, server = _load(paths.ca_cert), _load(paths.server_cert)

    assert ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is True
    assert ca.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign is True
    assert server.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False
    assert server.issuer == ca.subject
    server.verify_directly_issued_by(ca)

    sans = server.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert sans.get_values_for_type(x509.DNSName) == ["localhost"]
    assert set(sans.get_values_for_type(x509.IPAddress)) == {
        ipaddress.ip_address("127.0.0.1"),
        ipaddress.ip_address("::1"),
    }
    eku = server.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert list(eku) == [ExtendedKeyUsageOID.SERVER_AUTH]
    assert isinstance(server.public_key(), ec.EllipticCurvePublicKey)
    lifetime = server.not_valid_after_utc - server.not_valid_before_utc
    assert lifetime.days <= certs.SERVER_DAYS


def test_file_permissions(tmp_path: Path) -> None:
    paths = certs.generate(tmp_path / "dev-certs")

    def mode(p: Path) -> int:
        return stat.S_IMODE(p.stat().st_mode)

    assert mode(paths.directory) == 0o700
    assert mode(paths.ca_key) == 0o600
    assert mode(paths.ca_cert) == 0o644
    assert not list(paths.directory.glob("*.tmp"))


def test_refuses_to_overwrite_without_force(tmp_path: Path) -> None:
    paths = certs.generate(tmp_path / "dev-certs")
    original = paths.ca_cert.read_bytes()
    with pytest.raises(FileExistsError):
        certs.generate(paths.directory)
    assert paths.ca_cert.read_bytes() == original
    certs.generate(paths.directory, force=True)
    assert paths.ca_cert.read_bytes() != original
