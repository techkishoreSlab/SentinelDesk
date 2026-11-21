"""Developer ID certificate helpers (Team ID + signer name from a certificate chain)."""

from __future__ import annotations

import warnings
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID

from app.catalogue.inspect.result import TEAM_ID_RE


@dataclass(frozen=True, slots=True)
class Signer:
    team_id: str
    common_name: str
    organisation: str
    developer_id: bool


def _attr(cert: x509.Certificate, oid: x509.ObjectIdentifier) -> str:
    values = cert.subject.get_attributes_for_oid(oid)
    if not values:
        return ""
    value = values[0].value
    return value if isinstance(value, str) else value.decode("utf-8", "replace")


def signer_from_chain(certs: list[x509.Certificate]) -> Signer | None:
    """Pick the leaf: the certificate whose subject OU is a 10-character Team ID."""
    for cert in certs:
        team = _attr(cert, NameOID.ORGANIZATIONAL_UNIT_NAME)
        if not TEAM_ID_RE.fullmatch(team):
            continue
        cn = _attr(cert, NameOID.COMMON_NAME)
        issuer_cn = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
        issuer = str(issuer_cn[0].value) if issuer_cn else ""
        return Signer(
            team_id=team,
            common_name=cn[:200],
            organisation=_attr(cert, NameOID.ORGANIZATION_NAME)[:120],
            developer_id="Developer ID" in issuer and cn.startswith("Developer ID"),
        )
    return None


def signer_from_der_list(blobs: list[bytes]) -> Signer | None:
    certs: list[x509.Certificate] = []
    for blob in blobs[:10]:
        try:
            certs.append(x509.load_der_x509_certificate(blob))
        except ValueError:
            continue
    return signer_from_chain(certs)


def signer_from_cms(blob: bytes) -> Signer | None:
    try:
        # Apple's CMS blobs are BER; cryptography parses them but warns.
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            certs = pkcs7.load_der_pkcs7_certificates(blob)
    except ValueError:
        return None
    return signer_from_chain(list(certs))
