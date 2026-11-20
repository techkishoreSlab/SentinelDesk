"""Liveness and readiness probes (spec §15.3)."""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app import __version__
from app.core.errors import error_response
from app.db.session import Database, get_database

router = APIRouter(prefix="/health", tags=["health"])


class LiveResponse(BaseModel):
    status: Literal["ok"]
    version: str


class ReadyResponse(BaseModel):
    status: Literal["ready"]
    checks: dict[str, Literal["ok"]]


@router.get("/live", response_model=LiveResponse)
async def live() -> LiveResponse:
    return LiveResponse(status="ok", version=__version__)


@router.get("/ready", response_model=ReadyResponse)
async def ready(db: Database = Depends(get_database)) -> ReadyResponse | JSONResponse:  # noqa: B008
    if not await db.ping():
        return error_response("SERVICE_UNAVAILABLE", 503, {"checks": {"database": "unavailable"}})
    return ReadyResponse(status="ready", checks={"database": "ok"})
