"""Inspection result and error types shared by the parsers and the sandbox worker."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any

VERSION_RE = re.compile(r"^[A-Za-z0-9._+\-]{1,40}$")
IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9._+\-]{1,200}$")
TEAM_ID_RE = re.compile(r"^[A-Z0-9]{10}$")
MIN_OS_RE = re.compile(r"^\d{1,2}(?:\.\d{1,3}){0,2}$")
DEFAULT_MIN_OS = "11.0"


class InspectError(Exception):
    """A package that cannot be catalogued. ``code`` is stable and shown to admins."""

    def __init__(self, code: str, **detail: Any) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(slots=True)
class Inspection:
    kind: str
    name: str
    version: str
    identifier: str
    architecture: str
    minimum_os_version: str
    team_id: str
    publisher: str
    signer: str
    payload_path: str | None
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Inspection:
        out = cls(
            kind=str(data["kind"]),
            name=str(data["name"]),
            version=str(data["version"]),
            identifier=str(data["identifier"]),
            architecture=str(data["architecture"]),
            minimum_os_version=str(data["minimum_os_version"]),
            team_id=str(data["team_id"]),
            publisher=str(data["publisher"]),
            signer=str(data["signer"]),
            payload_path=None if data.get("payload_path") is None else str(data["payload_path"]),
            warnings=[str(w) for w in data.get("warnings", [])][:20],
        )
        out.validate()
        return out

    def validate(self) -> None:
        """Re-check everything the worker returns; the parent never trusts it blindly."""
        if not VERSION_RE.fullmatch(self.version):
            raise InspectError("VERSION_UNREADABLE")
        if not IDENTIFIER_RE.fullmatch(self.identifier):
            raise InspectError("IDENTIFIER_UNREADABLE")
        if not TEAM_ID_RE.fullmatch(self.team_id):
            raise InspectError("UNSIGNED_PACKAGE")
        if self.architecture not in {"x86_64", "arm64", "universal"}:
            raise InspectError("ARCH_UNREADABLE")
        if not MIN_OS_RE.fullmatch(self.minimum_os_version):
            self.minimum_os_version = DEFAULT_MIN_OS
        self.name = clean_text(self.name, 120) or self.identifier
        self.publisher = clean_text(self.publisher, 120) or self.team_id
        self.signer = clean_text(self.signer, 200)


def clean_text(value: object, limit: int) -> str:
    if not isinstance(value, str):
        return ""
    text = "".join(ch for ch in value if ch.isprintable()).strip()
    return text[:limit]


def clean_version(value: object) -> str | None:
    text = clean_text(value, 40)
    return text if VERSION_RE.fullmatch(text) else None


def clean_min_os(value: object, warnings: list[str]) -> str:
    text = clean_text(value, 20)
    if MIN_OS_RE.fullmatch(text):
        return text
    warnings.append("MIN_OS_UNKNOWN")
    return DEFAULT_MIN_OS
