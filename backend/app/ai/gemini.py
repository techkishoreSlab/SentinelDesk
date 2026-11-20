"""Server-side Gemini client: structured intent only, no tool calling (spec section 7)."""

from __future__ import annotations

import json
import logging
from typing import Any, Protocol

import httpx

from app.ai.intent import GEMINI_RESPONSE_SCHEMA, SoftwareIntent, parse_intent
from app.ai.prompts import (
    SYSTEM_INTENT,
    explanation_system,
    explanation_user_message,
    intent_user_message,
)
from app.core.config import Settings

logger = logging.getLogger("sentineldesk.gemini")

GEMINI_BASE = "https://generativelanguage.googleapis.com/v1beta"


class IntentExtractor(Protocol):
    async def extract_intent(self, raw_request: str) -> SoftwareIntent: ...

    async def explain(self, decision_summary: str) -> str | None: ...


class GeminiError(Exception):
    def __init__(self, code: str, message: str = "") -> None:
        super().__init__(code)
        self.code = code
        self.message = message


class GeminiClient:
    def __init__(self, settings: Settings, client: httpx.AsyncClient) -> None:
        if not settings.gemini_api_key or not settings.gemini_model:
            raise GeminiError("NOT_CONFIGURED")
        self._key = settings.gemini_api_key.get_secret_value()
        self._model = settings.gemini_model
        self._client = client
        self._timeout = settings.gemini_timeout_seconds
        self._max_tokens = settings.gemini_max_output_tokens

    @property
    def model(self) -> str:
        return self._model

    async def extract_intent(self, raw_request: str) -> SoftwareIntent:
        try:
            return await self._extract_once(raw_request)
        except GeminiError as first:
            if first.code not in {"SCHEMA_INVALID", "MALFORMED_JSON"}:
                raise
            # One constrained repair retry (spec section 7.4).
            return await self._extract_once(
                raw_request,
                repair="Your previous answer was invalid. Return ONLY valid JSON for the schema.",
            )

    async def explain(self, decision_summary: str) -> str | None:
        try:
            text = await self._generate(
                system=explanation_system(),
                user=explanation_user_message(decision_summary),
                schema=None,
                max_tokens=120,
            )
        except GeminiError:
            return None
        cleaned = " ".join(text.split())
        if not cleaned or len(cleaned) > 400:
            return None
        if any(tok in cleaned.casefold() for tok in ("http://", "https://", "`", "$(", "sudo ")):
            return None
        return cleaned

    async def _extract_once(self, raw_request: str, repair: str | None = None) -> SoftwareIntent:
        user = intent_user_message(raw_request)
        if repair:
            user = f"{repair}\n{user}"
        text = await self._generate(
            system=SYSTEM_INTENT,
            user=user,
            schema=GEMINI_RESPONSE_SCHEMA,
            max_tokens=self._max_tokens,
        )
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as exc:
            raise GeminiError("MALFORMED_JSON") from exc
        try:
            return parse_intent(payload)
        except Exception as exc:  # pydantic ValidationError
            raise GeminiError("SCHEMA_INVALID") from exc

    async def _generate(
        self,
        *,
        system: str,
        user: str,
        schema: dict[str, object] | None,
        max_tokens: int,
    ) -> str:
        url = f"{GEMINI_BASE}/models/{self._model}:generateContent"
        generation: dict[str, Any] = {
            "temperature": 0,
            "maxOutputTokens": max_tokens,
        }
        if schema is not None:
            generation["responseMimeType"] = "application/json"
            generation["responseSchema"] = schema
        body = {
            "systemInstruction": {"parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": user}]}],
            "generationConfig": generation,
        }
        # API key in header only — never as a query param (avoids httpx URL logs leaking it).
        headers = {"x-goog-api-key": self._key, "Content-Type": "application/json"}
        try:
            response = await self._client.post(
                url,
                headers=headers,
                json=body,
                timeout=self._timeout,
            )
        except httpx.TimeoutException as exc:
            raise GeminiError("TIMEOUT") from exc
        except httpx.HTTPError as exc:
            raise GeminiError("UNREACHABLE") from exc

        if response.status_code in {401, 403}:
            raise GeminiError("UNAUTHORIZED")
        if response.status_code == 429:
            raise GeminiError("RATE_LIMITED")
        if response.status_code == 503:
            raise GeminiError("UNAVAILABLE")
        if response.status_code == 404:
            raise GeminiError("MODEL_NOT_FOUND", "Update GEMINI_MODEL to a current flash model")
        if response.status_code >= 400:
            detail = _safe_error_detail(response)
            logger.warning(
                "gemini_http_error",
                extra={"status": response.status_code, "detail": detail},
            )
            raise GeminiError("HTTP_ERROR", detail)

        try:
            data = response.json()
            parts = data["candidates"][0]["content"]["parts"]
            # Prefer parts that look like JSON; ignore thought-only fluff if present.
            texts = [str(p.get("text", "")) for p in parts if isinstance(p, dict)]
            text = next((t for t in texts if t.strip().startswith("{")), "")
            if not text:
                text = "".join(texts)
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            raise GeminiError("MALFORMED_RESPONSE") from exc
        if not text.strip():
            raise GeminiError("EMPTY_RESPONSE")
        return text.strip()


def _safe_error_detail(response: httpx.Response) -> str:
    try:
        payload = response.json()
        message = payload.get("error", {}).get("message")
        if isinstance(message, str):
            return message[:240]
    except (ValueError, TypeError, AttributeError):
        pass
    return f"http_{response.status_code}"


class StaticIntentExtractor:
    """Test double: returns a fixed intent / explanation."""

    def __init__(
        self,
        intent: SoftwareIntent,
        *,
        explanation: str | None = None,
        fail_code: str | None = None,
    ) -> None:
        self._intent = intent
        self._explanation = explanation
        self._fail_code = fail_code
        self.model = "static-test"

    async def extract_intent(self, raw_request: str) -> SoftwareIntent:
        if self._fail_code:
            raise GeminiError(self._fail_code)
        return self._intent.model_copy()

    async def explain(self, decision_summary: str) -> str | None:
        return self._explanation
