"""Deterministic intent extraction when Gemini is unavailable (spec section 7.4)."""

from __future__ import annotations

import re

from app.ai.intent import SoftwareIntent
from app.catalogue.normalize import normalize_alias

_PREFIXES = re.compile(
    r"^(please\s+)?(can\s+you\s+|could\s+you\s+)?"
    r"(install|get|add|setup|set\s+up|download)(\s+me)?(\s+|$)",
    re.IGNORECASE,
)
_FILLER = re.compile(r"^(please|thanks|thank you|something|it|that|this)\.?$", re.IGNORECASE)

# Conversational turns must never become INSTALL_SOFTWARE → catalogue lookup.
_CONVERSATIONAL = re.compile(
    r"^\s*("
    r"hi|hello|hey|howdy|yo|sup|"
    r"good\s+(morning|afternoon|evening)|"
    r"thanks|thank\s+you|thx|"
    r"ok|okay|cool|great|nice|"
    r"help|help\s+me|what\s+can\s+you\s+do|how\s+do\s+(you|i)\s+work|"
    r"who\s+are\s+you|what\s+are\s+you|"
    r"what('?s| is)\s+your\s+name|your\s+name\??|"
    r"how\s+are\s+you|what'?s\s+up|"
    # Continuations without a software name must not hit the catalogue.
    r"continue\.?|go\s+on|proceed|retry|try\s+again|do\s+it|do\s+that|"
    r"yes|yep|yeah|sure|go\s+ahead|same\s+again|again"
    r")[\s!.?]*$",
    re.IGNORECASE,
)

_AGENT_CLARIFY = (
    "I'm Sentinel, your organisation's software provisioning agent. "
    "I help install approved software on your enrolled devices. "
    "How may I help you today?"
)


def strip_install_phrasing(raw: str) -> str:
    text = " ".join(raw.strip().split())
    text = _PREFIXES.sub("", text).strip(" .!?")
    if _FILLER.fullmatch(text):
        return ""
    return text


def is_conversational(raw: str) -> bool:
    text = " ".join(raw.strip().split())
    if not text:
        return True
    return _CONVERSATIONAL.fullmatch(text) is not None


def fallback_intent(raw_request: str) -> SoftwareIntent:
    """Build an INSTALL_SOFTWARE intent from literal text for exact alias matching."""
    if is_conversational(raw_request):
        return SoftwareIntent(
            intent="UNKNOWN",
            software_query="unknown",
            clarification_required=True,
            clarification_question=_AGENT_CLARIFY,
            confidence=0.0,
        )

    query = strip_install_phrasing(raw_request)
    if not query:
        return SoftwareIntent(
            intent="UNKNOWN",
            software_query="unknown",
            clarification_required=True,
            clarification_question=_AGENT_CLARIFY,
            confidence=0.0,
        )
    # Keep query short for the schema; alias matching uses normalization separately.
    query = query[:120]
    normalized = normalize_alias(query)
    if not normalized:
        return SoftwareIntent(
            intent="UNKNOWN",
            software_query="unknown",
            clarification_required=True,
            clarification_question=_AGENT_CLARIFY,
            confidence=0.0,
        )
    return SoftwareIntent(
        intent="INSTALL_SOFTWARE",
        software_query=query,
        edition=None,
        requested_version=None,
        platform_preference=None,
        clarification_required=False,
        clarification_question=None,
        confidence=0.4,
    )
