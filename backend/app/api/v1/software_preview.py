"""Natural-language software request preview (Phase 6 — no persistence)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import Principal, require
from app.auth.rbac import Permission
from app.core.config import Settings
from app.db.session import get_session
from app.orchestration.orchestrator import run_preview
from app.orchestration.schemas import PreviewOut, PreviewRequest
from app.security.threat import CompositeThreatIntel

router = APIRouter(prefix="/api/v1/software", tags=["software"])


def get_settings_from(request: Request) -> Settings:
    settings: Settings = request.app.state.settings
    return settings


def threat_from(request: Request) -> CompositeThreatIntel:
    settings = get_settings_from(request)
    return CompositeThreatIntel(settings, request.app.state.http_client)


@router.post("/preview", response_model=PreviewOut)
async def preview_request(
    body: PreviewRequest,
    request: Request,
    principal: Principal = Depends(require(Permission.REQUEST_CREATE)),  # noqa: B008
    db: AsyncSession = Depends(get_session),  # noqa: B008
) -> PreviewOut:
    result = await run_preview(
        db,
        get_settings_from(request),
        threat_from(request),
        owner_user_id=principal.user_id,
        device_id=body.device_id,
        raw_request=body.raw_request,
        http_client=request.app.state.http_client,
    )
    await db.commit()
    return result
