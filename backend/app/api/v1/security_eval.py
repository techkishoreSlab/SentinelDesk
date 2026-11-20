"""Employee-facing policy evaluation against a device + catalogue version."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import Principal, require
from app.auth.rbac import Permission
from app.catalogue import service as catalogue
from app.core.config import Settings
from app.core.errors import AppError
from app.db.session import get_session
from app.devices.models import Device
from app.security.engine import evaluate_install
from app.security.schemas import EvaluateOut, EvaluateRequest
from app.security.threat import CompositeThreatIntel

router = APIRouter(prefix="/api/v1/security", tags=["security"])


def get_settings_from(request: Request) -> Settings:
    settings: Settings = request.app.state.settings
    return settings


def threat_from(request: Request) -> CompositeThreatIntel:
    settings = get_settings_from(request)
    return CompositeThreatIntel(settings, request.app.state.http_client)


@router.post("/evaluate", response_model=EvaluateOut)
async def evaluate_policy(
    body: EvaluateRequest,
    request: Request,
    principal: Principal = Depends(require(Permission.REQUEST_CREATE)),  # noqa: B008
    db: AsyncSession = Depends(get_session),  # noqa: B008
) -> EvaluateOut:
    settings = get_settings_from(request)
    device = await db.scalar(
        select(Device).where(Device.id == body.device_id, Device.owner_user_id == principal.user_id)
    )
    if device is None:
        raise AppError("NOT_FOUND", 404)
    version = await catalogue.get_version(db, body.catalogue_version_id)
    software = await catalogue.get_software(db, version.software_id)
    result = await evaluate_install(
        db,
        settings,
        threat_from(request),
        device=device,
        software=software,
        version=version,
    )
    await db.commit()
    return EvaluateOut(
        outcome=result.outcome,
        reason_code=result.reason_code,
        public_message=result.public_message,
        compatible=result.compatible,
        compatibility_reason=result.compatibility_reason,
        threat_verdict=result.threat_verdict,
        threat_provider=result.threat_provider,
        ban_rule_id=result.ban_rule_id,
        policy_decision=result.policy_decision,
        policy_revision=result.policy_revision,
        auto_approve_eligible=result.auto_approve_eligible,
        software_id=result.software_id,
        software_slug=result.software_slug,
        catalogue_version_id=result.catalogue_version_id,
        details=result.details,
    )
