"""External catalogue connector interface (spec §8.3).

Connectors may enrich metadata. Imported records must enter PENDING_REVIEW and never
become installable until an administrator activates them with complete mandatory fields.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True, slots=True)
class ExternalSoftwareRecord:
    external_id: str
    display_name: str
    publisher: str
    version: str
    os_family: str
    architecture: str


@dataclass(frozen=True, slots=True)
class ExternalPackageMetadata:
    external_id: str
    display_name: str
    publisher: str
    version: str
    os_family: str
    architecture: str
    sha256: str | None
    signature_publisher: str | None
    source_reference: str | None
    package_size_bytes: int | None


class CatalogueConnector(Protocol):
    async def search(self, query: str, platform: str) -> list[ExternalSoftwareRecord]: ...

    async def get_package_metadata(self, external_id: str) -> ExternalPackageMetadata: ...


class NullCatalogueConnector:
    """Default connector: no external catalogues are configured."""

    async def search(self, query: str, platform: str) -> list[ExternalSoftwareRecord]:
        return []

    async def get_package_metadata(self, external_id: str) -> ExternalPackageMetadata:
        raise LookupError(external_id)
