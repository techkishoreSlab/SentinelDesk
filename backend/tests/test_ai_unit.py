"""Unit tests for intent schema, fallback, and Gemini client (mocked HTTP)."""

from __future__ import annotations

import json

import httpx
import pytest
from pydantic import ValidationError

from app.ai.fallback import fallback_intent, is_conversational, strip_install_phrasing
from app.ai.gemini import GeminiClient, GeminiError, StaticIntentExtractor
from app.ai.intent import SoftwareIntent, parse_intent
from tests.conftest import make_settings


def test_intent_rejects_extra_fields_and_urls() -> None:
    with pytest.raises(ValidationError):
        parse_intent(
            {
                "intent": "INSTALL_SOFTWARE",
                "software_query": "vscode",
                "download_url": "https://evil.example",
            }
        )
    with pytest.raises(ValidationError):
        SoftwareIntent(intent="INSTALL_SOFTWARE", software_query="see https://x.com")


def test_fallback_strips_install_phrasing() -> None:
    assert strip_install_phrasing("Please install VS Code") == "VS Code"
    intent = fallback_intent("Install Visual Studio Code")
    assert intent.intent == "INSTALL_SOFTWARE"
    assert intent.software_query == "Visual Studio Code"
    assert intent.clarification_required is False


def test_fallback_unknown_empty() -> None:
    intent = fallback_intent("please install")
    assert intent.intent == "UNKNOWN"
    assert intent.clarification_required is True


def test_fallback_conversational_never_installs() -> None:
    for raw in (
        "hi",
        "Hello!",
        "what is your name",
        "who are you",
        "help",
        "thanks",
        "continue..",
        "try again",
        "go ahead",
    ):
        assert is_conversational(raw) is True
        intent = fallback_intent(raw)
        assert intent.intent == "UNKNOWN"
        assert "Sentinel" in (intent.clarification_question or "")


@pytest.mark.asyncio
async def test_static_extractor_and_failure() -> None:
    good = SoftwareIntent(intent="INSTALL_SOFTWARE", software_query="git")
    ok = StaticIntentExtractor(good, explanation="Git needs approval.")
    assert (await ok.extract_intent("Install git")).software_query == "git"
    assert await ok.explain("x") == "Git needs approval."

    boom = StaticIntentExtractor(good, fail_code="TIMEOUT")
    with pytest.raises(GeminiError) as exc:
        await boom.extract_intent("Install git")
    assert exc.value.code == "TIMEOUT"


@pytest.mark.asyncio
async def test_gemini_client_parses_schema_and_repairs_once() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        assert "key" not in str(request.url)
        assert request.headers.get("x-goog-api-key") == "k" * 32
        if calls["n"] == 1:
            return httpx.Response(
                200,
                json={"candidates": [{"content": {"parts": [{"text": "not-json"}]}}]},
            )
        payload = {
            "intent": "INSTALL_SOFTWARE",
            "software_query": "vscode",
            "edition": None,
            "requested_version": None,
            "platform_preference": None,
            "clarification_required": False,
            "clarification_question": None,
            "confidence": 0.9,
        }
        return httpx.Response(
            200,
            json={"candidates": [{"content": {"parts": [{"text": json.dumps(payload)}]}}]},
        )

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        gemini = GeminiClient(
            make_settings(gemini_api_key="k" * 32, gemini_model="gemini-3.5-flash-lite"),
            client,
        )
        intent = await gemini.extract_intent("Install vscode")
    assert intent.software_query == "vscode"
    assert calls["n"] == 2


@pytest.mark.asyncio
async def test_gemini_timeout_maps_to_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow")

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        gemini = GeminiClient(
            make_settings(gemini_api_key="k" * 32, gemini_model="gemini-3.5-flash-lite"),
            client,
        )
        with pytest.raises(GeminiError) as exc:
            await gemini.extract_intent("Install git")
    assert exc.value.code == "TIMEOUT"


@pytest.mark.asyncio
async def test_gemini_model_not_found_maps_to_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            404,
            json={"error": {"message": "This model is no longer available."}},
        )

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        gemini = GeminiClient(
            make_settings(gemini_api_key="k" * 32, gemini_model="gemini-2.0-flash"),
            client,
        )
        with pytest.raises(GeminiError) as exc:
            await gemini.extract_intent("Install git")
    assert exc.value.code == "MODEL_NOT_FOUND"
