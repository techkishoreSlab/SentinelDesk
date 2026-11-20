"""Integration status for administrators (spec §15.3). Never exposes secret values."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from app.auth.dependencies import Principal, get_settings_from, require
from app.auth.rbac import Permission

router = APIRouter(prefix="/api/v1/admin/integrations", tags=["admin"])


@router.get("/status")
async def integration_status(
    request: Request,
    _: Principal = Depends(require(Permission.INTEGRATION_READ)),  # noqa: B008
) -> dict[str, str]:
    return get_settings_from(request).integration_status()
