"""Threat-intelligence providers (spec section 9.6-9.7, decision D3).

Order: denied digests -> pinned clean digests -> configured external provider.
If a mandatory check cannot produce a trustworthy verdict, return INDETERMINATE
(fail closed). Never upload binaries; hash lookup only.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Protocol

import httpx

from app.catalogue.seed import demo_digest
from app.core.config import Settings
from app.db.enums import ThreatVerdict

logger = logging.getLogger("sentineldesk.threat")

# Demo-only pins so local validation works without a VirusTotal key. Production
# must configure THREAT_INTEL_* digests / provider explicitly (no silent pins).
_DEMO_PINNED_LABELS = (
    "vscode-1.138.0-macos-x86_64",
    "vscode-1.138.0-macos-arm64",
    "git-2.50.0-macos-x86_64",
    "contoso-notepad-1.0.0-win-x64",
    "restricted-remote-access-9.9.9",
    "incomplete-0.0.1",
    "widget",  # used by integration tests that create a complete package
)
# Real package digests admitted for local Phase 8 demo (official checksums).
_REAL_PINNED_DIGESTS = (
    "5a4dd756bd3dea06c39edcc8c97653d85198774d9991790b7221f08b42281df6",  # gh 2.104.0
    "98b6668684006873a3befee5cf155a110f79c3156ac718ddf45f59e4043a16b9",  # go1.27.4 darwin-amd64
)
_DEMO_DENIED_LABELS = ("demo-malware-sample-1.0.0",)


@dataclass(frozen=True, slots=True)
class ThreatResult:
    verdict: ThreatVerdict
    provider: str
    error_code: str | None = None


class ThreatIntelProvider(Protocol):
    async def check_hash(self, sha256: str) -> ThreatResult: ...


def _parse_digest_list(raw: str) -> set[str]:
    out: set[str] = set()
    for part in raw.split(","):
        item = part.strip().lower()
        if len(item) == 64 and all(c in "0123456789abcdef" for c in item):
            out.add(item)
    return out


class InternalDigestList:
    """Organisation-controlled digest allow/deny list (decision D3)."""

    def __init__(self, settings: Settings) -> None:
        denied = _parse_digest_list(settings.threat_intel_denied_digests)
        pinned = _parse_digest_list(settings.threat_intel_pinned_digests)
        if not settings.is_production:
            denied |= {demo_digest(label) for label in _DEMO_DENIED_LABELS}
            pinned |= {demo_digest(label) for label in _DEMO_PINNED_LABELS}
            pinned |= {d.lower() for d in _REAL_PINNED_DIGESTS}
        try:
            from app.catalogue.ingest import load_store_pins

            pinned |= load_store_pins(settings)
        except OSError:
            pass
        self._denied = denied
        self._pinned = pinned - denied

    async def check_hash(self, sha256: str) -> ThreatResult | None:
        digest = sha256.lower()
        if digest in self._denied:
            return ThreatResult(ThreatVerdict.MALICIOUS, "internal_digest_list")
        if digest in self._pinned:
            return ThreatResult(ThreatVerdict.CLEAN, "internal_digest_list")
        return None


class VirusTotalProvider:
    """VirusTotal v3 file hash lookup. Network failures → INDETERMINATE."""

    def __init__(self, api_key: str, client: httpx.AsyncClient) -> None:
        self._api_key = api_key
        self._client = client

    async def check_hash(self, sha256: str) -> ThreatResult:
        url = f"https://www.virustotal.com/api/v3/files/{sha256.lower()}"
        try:
            response = await self._client.get(url, headers={"x-apikey": self._api_key})
        except httpx.HTTPError:
            logger.warning("virustotal_unreachable")
            return ThreatResult(ThreatVerdict.INDETERMINATE, "virustotal", "PROVIDER_UNREACHABLE")

        if response.status_code == 404:
            # Unknown to VT is not proof of safety when the check is mandatory.
            return ThreatResult(ThreatVerdict.INDETERMINATE, "virustotal", "HASH_UNKNOWN")
        if response.status_code == 401 or response.status_code == 403:
            return ThreatResult(ThreatVerdict.INDETERMINATE, "virustotal", "PROVIDER_UNAUTHORIZED")
        if response.status_code == 429:
            return ThreatResult(ThreatVerdict.INDETERMINATE, "virustotal", "PROVIDER_RATE_LIMITED")
        if response.status_code >= 400:
            return ThreatResult(ThreatVerdict.INDETERMINATE, "virustotal", "PROVIDER_HTTP_ERROR")

        try:
            stats = response.json()["data"]["attributes"]["last_analysis_stats"]
            malicious = int(stats.get("malicious", 0))
            suspicious = int(stats.get("suspicious", 0))
        except (KeyError, TypeError, ValueError, AttributeError):
            return ThreatResult(ThreatVerdict.INDETERMINATE, "virustotal", "PROVIDER_MALFORMED")

        if malicious > 0:
            return ThreatResult(ThreatVerdict.MALICIOUS, "virustotal")
        if suspicious > 0:
            return ThreatResult(ThreatVerdict.SUSPICIOUS, "virustotal")
        return ThreatResult(ThreatVerdict.CLEAN, "virustotal")


class CompositeThreatIntel:
    def __init__(self, settings: Settings, client: httpx.AsyncClient) -> None:
        self._internal = InternalDigestList(settings)
        self._external: ThreatIntelProvider | None = None
        if settings.threat_intel_provider == "virustotal" and settings.threat_intel_api_key:
            self._external = VirusTotalProvider(
                settings.threat_intel_api_key.get_secret_value(), client
            )
        self._mandatory = settings.threat_intel_mandatory

    @property
    def mandatory(self) -> bool:
        return self._mandatory

    @property
    def external_configured(self) -> bool:
        return self._external is not None

    async def check_hash(self, sha256: str) -> ThreatResult:
        if not sha256 or len(sha256) != 64:
            return ThreatResult(ThreatVerdict.INDETERMINATE, "none", "DIGEST_MISSING")
        hit = await self._internal.check_hash(sha256)
        if hit is not None:
            return hit
        if self._external is not None:
            return await self._external.check_hash(sha256)
        return ThreatResult(ThreatVerdict.INDETERMINATE, "none", "PROVIDER_NOT_CONFIGURED")


class StaticThreatIntel:
    """Test double: map digests to fixed verdicts; unknown → INDETERMINATE."""

    def __init__(self, mapping: dict[str, ThreatVerdict] | None = None) -> None:
        self._mapping = {k.lower(): v for k, v in (mapping or {}).items()}

    async def check_hash(self, sha256: str) -> ThreatResult:
        verdict = self._mapping.get(sha256.lower(), ThreatVerdict.INDETERMINATE)
        code = None if verdict != ThreatVerdict.INDETERMINATE else "TEST_DEFAULT"
        return ThreatResult(verdict, "static_test", code)
