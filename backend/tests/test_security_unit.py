"""Threat digest lists and ban/policy helpers without a database."""

from __future__ import annotations

import pytest

from app.catalogue.seed import demo_digest
from app.core.config import Settings
from app.db.enums import ThreatVerdict
from app.security.threat import CompositeThreatIntel, InternalDigestList, StaticThreatIntel
from tests.conftest import make_settings


@pytest.mark.asyncio
async def test_internal_digest_denied_and_pinned() -> None:
    settings = make_settings()
    store = InternalDigestList(settings)
    denied = demo_digest("demo-malware-sample-1.0.0")
    pinned = demo_digest("git-2.50.0-macos-x86_64")
    assert (await store.check_hash(denied)).verdict == ThreatVerdict.MALICIOUS
    assert (await store.check_hash(pinned)).verdict == ThreatVerdict.CLEAN
    assert await store.check_hash("ab" * 32) is None


@pytest.mark.asyncio
async def test_composite_fail_closed_when_unpinned_and_no_provider() -> None:
    import httpx

    settings = make_settings(threat_intel_mandatory=True)
    async with httpx.AsyncClient() as client:
        threat = CompositeThreatIntel(settings, client)
        result = await threat.check_hash("cd" * 32)
    assert result.verdict == ThreatVerdict.INDETERMINATE
    assert result.error_code == "PROVIDER_NOT_CONFIGURED"


@pytest.mark.asyncio
async def test_static_provider_mapping() -> None:
    digest = "11" * 32
    provider = StaticThreatIntel({digest: ThreatVerdict.SUSPICIOUS})
    assert (await provider.check_hash(digest)).verdict == ThreatVerdict.SUSPICIOUS
    assert (await provider.check_hash("22" * 32)).verdict == ThreatVerdict.INDETERMINATE


def test_settings_threat_flags() -> None:
    settings = make_settings(
        threat_intel_provider="virustotal",
        threat_intel_api_key="x" * 32,
        threat_intel_mandatory=True,
    )
    assert settings.integration_status()["threat_intel"] == "configured"
    bare = make_settings()
    assert bare.integration_status()["threat_intel"] == "not_configured"
    assert isinstance(bare, Settings)
