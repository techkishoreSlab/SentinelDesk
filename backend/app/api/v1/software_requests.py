"""Employee software request APIs (spec §12.1)."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import Principal, require
from app.auth.rbac import Permission
from app.core.config import Settings
from app.db.session import get_session
from app.requests import service as requests_service
from app.requests.schemas import (
    CancelOut,
    CreateSoftwareRequest,
    RequestListOut,
    RequestOut,
)
from app.security.threat import CompositeThreatIntel

router = APIRouter(prefix="/api/v1/software", tags=["software-requests"])


def get_settings_from(request: Request) -> Settings:
    settings: Settings = request.app.state.settings
    return settings


def threat_from(request: Request) -> CompositeThreatIntel:
    return CompositeThreatIntel(get_settings_from(request), request.app.state.http_client)


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


@router.post("/requests", response_model=RequestOut)
async def submit_request(
    body: CreateSoftwareRequest,
    request: Request,
    principal: Principal = Depends(require(Permission.REQUEST_CREATE)),  # noqa: B008
    db: AsyncSession = Depends(get_session),  # noqa: B008
) -> RequestOut:
    payload = await requests_service.create_request(
        db,
        get_settings_from(request),
        threat_from(request),
        requester_id=principal.user_id,
        device_id=body.device_id,
        user_prompt=body.user_prompt,
        idempotency_key=body.idempotency_key,
        http_client=request.app.state.http_client,
        actor_ip=_client_ip(request),
    )
    await db.commit()
    return RequestOut.model_validate(payload)


@router.get("/requests", response_model=RequestListOut)
async def list_requests(
    principal: Principal = Depends(require(Permission.REQUEST_READ_OWN)),  # noqa: B008
    db: AsyncSession = Depends(get_session),  # noqa: B008
) -> RequestListOut:
    items = await requests_service.list_own_requests(db, requester_id=principal.user_id)
    return RequestListOut(items=[RequestOut.model_validate(i) for i in items])


@router.get("/requests/{request_id}", response_model=RequestOut)
async def get_request(
    request_id: uuid.UUID,
    principal: Principal = Depends(require(Permission.REQUEST_READ_OWN)),  # noqa: B008
    db: AsyncSession = Depends(get_session),  # noqa: B008
) -> RequestOut:
    payload = await requests_service.get_own_request(
        db, requester_id=principal.user_id, request_id=request_id
    )
    return RequestOut.model_validate(payload)


@router.post("/requests/{request_id}/cancel", response_model=CancelOut)
async def cancel_request(
    request_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(require(Permission.REQUEST_CANCEL_OWN)),  # noqa: B008
    db: AsyncSession = Depends(get_session),  # noqa: B008
) -> CancelOut:
    payload = await requests_service.cancel_own_request(
        db,
        requester_id=principal.user_id,
        request_id=request_id,
        actor_ip=_client_ip(request),
    )
    await db.commit()
    return CancelOut.model_validate(payload)
