"""Development-only TLS material: a private CA and a loopback server certificate.

The agent pins `ca.pem` (it does not trust the OS store when a CA file is configured), so a
certificate issued by any public CA for localhost would not be accepted. Never use these files
outside local development.
"""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

CA_DAYS = 365
SERVER_DAYS = 90
SERVER_NAMES = ["localhost"]
SERVER_IPS = ["127.0.0.1", "::1"]


@dataclass(frozen=True)
class CertPaths:
    directory: Path

    @property
    def ca_cert(self) -> Path:
        return self.directory / "ca.pem"

    @property
    def ca_key(self) -> Path:
        return self.directory / "ca-key.pem"

    @property
    def server_cert(self) -> Path:
        return self.directory / "server.pem"

    @property
    def server_key(self) -> Path:
        return self.directory / "server-key.pem"


def _write(path: Path, data: bytes, mode: int) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    os.chmod(tmp, mode)
    tmp.replace(path)


def _key_pem(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def generate(directory: Path, *, force: bool = False) -> CertPaths:
    paths = CertPaths(directory)
    if paths.ca_cert.exists() and not force:
        raise FileExistsError(f"{paths.ca_cert} exists; pass --force to replace")
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(directory, 0o700)
    now = datetime.now(UTC)

    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SentinelDesk Dev CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=CA_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), False)
        .sign(ca_key, hashes.SHA256())
    )

    server_key = ec.generate_private_key(ec.SECP256R1())
    sans: list[x509.GeneralName] = [x509.DNSName(n) for n in SERVER_NAMES]
    sans += [x509.IPAddress(ipaddress.ip_address(ip)) for ip in SERVER_IPS]
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
        .issuer_name(ca_name)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=SERVER_DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), False
        )
        .sign(ca_key, hashes.SHA256())
    )

    pem = serialization.Encoding.PEM
    _write(paths.ca_key, _key_pem(ca_key), 0o600)
    _write(paths.ca_cert, ca_cert.public_bytes(pem), 0o644)
    # Readable by the uid-10001 container through the bind-mounted secret; the directory is 0700.
    _write(paths.server_key, _key_pem(server_key), 0o644)
    _write(paths.server_cert, server_cert.public_bytes(pem), 0o644)
    return paths
