"""Strict software-intent schema (spec section 7.2). Unknown fields are rejected."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

IntentKind = Literal["INSTALL_SOFTWARE", "UNKNOWN"]


class SoftwareIntent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    intent: IntentKind
    software_query: str = Field(min_length=1, max_length=120)
    edition: str | None = Field(default=None, max_length=60)
    requested_version: str | None = Field(default=None, max_length=40)
    platform_preference: Literal["macos", "windows", "linux"] | None = None
    clarification_required: bool = False
    clarification_question: str | None = Field(default=None, max_length=240)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)

    @field_validator("software_query", "edition", "requested_version", "clarification_question")
    @classmethod
    def _no_control_or_urls(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = "".join(ch for ch in value if ch.isprintable())
        cleaned = cleaned.strip()
        lowered = cleaned.casefold()
        if any(
            token in lowered
            for token in ("http://", "https://", "ftp://", "file:", "`", "$(", "${", "&&", "|", ";")
        ):
            raise ValueError("intent fields must not contain URLs or command fragments")
        return cleaned or None

    @model_validator(mode="after")
    def _clarification_consistency(self) -> SoftwareIntent:
        if self.clarification_required and not self.clarification_question:
            self.clarification_question = "Which approved software would you like to install?"
        if not self.clarification_required:
            self.clarification_question = None
        return self


def parse_intent(raw: object) -> SoftwareIntent:
    return SoftwareIntent.model_validate(raw)


# Gemini generateContent responseSchema uses an OpenAPI-like subset: uppercase types,
# nullable flags, and no additionalProperties (those fields cause HTTP 400).
GEMINI_RESPONSE_SCHEMA: dict[str, object] = {
    "type": "OBJECT",
    "required": [
        "intent",
        "software_query",
        "edition",
        "requested_version",
        "platform_preference",
        "clarification_required",
        "clarification_question",
        "confidence",
    ],
    "properties": {
        "intent": {"type": "STRING", "enum": ["INSTALL_SOFTWARE", "UNKNOWN"]},
        "software_query": {"type": "STRING"},
        "edition": {"type": "STRING", "nullable": True},
        "requested_version": {"type": "STRING", "nullable": True},
        "platform_preference": {
            "type": "STRING",
            "nullable": True,
            "enum": ["macos", "windows", "linux"],
        },
        "clarification_required": {"type": "BOOLEAN"},
        "clarification_question": {"type": "STRING", "nullable": True},
        "confidence": {"type": "NUMBER"},
    },
}
