from __future__ import annotations

import unicodedata
import uuid

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.auth.passwords import MAX_PASSWORD_LENGTH


def normalize_email(value: str) -> str:
    return unicodedata.normalize("NFKC", value).strip().lower()


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=MAX_PASSWORD_LENGTH)

    @field_validator("email")
    @classmethod
    def _normalize(cls, value: str) -> str:
        value = normalize_email(value)
        if "@" not in value or any(c.isspace() or ord(c) < 32 for c in value):
            raise ValueError("invalid email")
        return value


class MeResponse(BaseModel):
    id: uuid.UUID
    email: str
    display_name: str
    identity_provider: str
    roles: list[str]
    permissions: list[str]


class ProvidersResponse(BaseModel):
    local: bool
    entra: bool
