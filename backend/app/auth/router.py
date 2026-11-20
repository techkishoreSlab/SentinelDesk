"""Authentication routes: local login, logout, Entra OIDC login/callback, current user."""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta

import httpx
from fastapi import APIRouter, Depends, Query, Request, Response
from fastapi.responses import RedirectResponse
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import service as audit
from app.auth import entra, throttle
from app.auth.dependencies import (
    Principal,
    check_origin,
    client_ip,
    get_principal,
    get_settings_from,
    load_role_names,
)
from app.auth.passwords import hash_password, needs_rehash, verify_password
from app.auth.rbac import permissions_for
from app.auth.schemas import LoginRequest, MeResponse, ProvidersResponse
from app.auth.sessions import (
    clear_session_cookies,
    create_session,
    revoke_session,
    set_session_cookies,
)
from app.auth.tokens import hash_token, new_token, pseudonymize
from app.core.errors import AppError
from app.db.enums import ActorType, AuditResult, IdentityProvider, RoleName
from app.db.session import get_session
from app.users.models import LocalCredential, OidcLoginState, Role, User, UserRole

logger = logging.getLogger("sentineldesk.auth")
router = APIRouter(prefix="/api/v1", tags=["auth"])

_OIDC_STATE_TTL = timedelta(minutes=10)


def _me(principal: Principal) -> MeResponse:
    return MeResponse(
        id=principal.user_id,
        email=principal.email,
        display_name=principal.display_name,
        identity_provider=principal.identity_provider,
        roles=sorted(principal.roles),
        permissions=sorted(p.value for p in principal.permissions),
    )


@router.get("/auth/providers", response_model=ProvidersResponse)
async def providers(request: Request) -> ProvidersResponse:
    settings = get_settings_from(request)
    return ProvidersResponse(local=settings.local_auth_enabled, entra=settings.entra_configured)


@router.get("/me", response_model=MeResponse)
async def me(principal: Principal = Depends(get_principal)) -> MeResponse:  # noqa: B008
    return _me(principal)


@router.post("/auth/login", response_model=MeResponse)
async def login(
    body: LoginRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_session),  # noqa: B008
) -> MeResponse:
    settings = get_settings_from(request)
    if not settings.local_auth_enabled:
        raise AppError("LOCAL_AUTH_DISABLED", 403)
    check_origin(request, settings)
    ip = client_ip(request)

    if await throttle.is_locked(db, [throttle.account_key(body.email), throttle.ip_key(ip)]):
        await audit.record(
            db,
            action="LOGIN_FAILED",
            resource_type="session",
            result=AuditResult.DENIED,
            actor_type=ActorType.ANONYMOUS,
            reason_code="RATE_LIMITED",
            source_ip=ip,
            metadata={"provider": "local", "account_ref": pseudonymize(body.email)},
        )
        await db.commit()
        raise AppError("RATE_LIMITED", 429)

    row = (
        await db.execute(
            select(User, LocalCredential)
            .join(LocalCredential, LocalCredential.user_id == User.id)
            .where(User.email == body.email, User.identity_provider == IdentityProvider.LOCAL)
        )
    ).first()
    user, credential = (row[0], row[1]) if row else (None, None)
    password_ok = verify_password(credential.password_hash if credential else None, body.password)

    if user is None or credential is None or not password_ok or not user.is_active:
        reason = "ACCOUNT_DISABLED" if (user and password_ok) else "INVALID_CREDENTIALS"
        await throttle.record_login_failure(db, settings, body.email, ip)
        await audit.record(
            db,
            action="LOGIN_FAILED",
            resource_type="session",
            result=AuditResult.DENIED,
            actor_type=ActorType.ANONYMOUS,
            actor_id=user.id if user else None,
            reason_code=reason,
            source_ip=ip,
            metadata={"provider": "local", "account_ref": pseudonymize(body.email)},
        )
        await db.commit()
        raise AppError("INVALID_CREDENTIALS", 401)

    if needs_rehash(credential.password_hash):
        credential.password_hash = hash_password(body.password)
    await throttle.reset_account(db, body.email)
    issued = await create_session(
        db,
        settings,
        user_id=user.id,
        identity_provider=IdentityProvider.LOCAL,
        source_ip=ip,
        user_agent=request.headers.get("user-agent"),
    )
    await audit.record(
        db,
        action="LOGIN_SUCCEEDED",
        resource_type="session",
        resource_id=issued.session.id,
        result=AuditResult.SUCCESS,
        actor_type=ActorType.USER,
        actor_id=user.id,
        source_ip=ip,
        metadata={"provider": "local"},
    )
    roles = await load_role_names(db, user.id)
    await db.commit()
    set_session_cookies(response, settings, issued)
    return MeResponse(
        id=user.id,
        email=user.email,
        display_name=user.display_name,
        identity_provider=user.identity_provider,
        roles=sorted(roles),
        permissions=sorted(p.value for p in permissions_for(roles)),
    )


@router.post("/auth/logout", status_code=204)
async def logout(
    request: Request,
    response: Response,
    principal: Principal = Depends(get_principal),  # noqa: B008
    db: AsyncSession = Depends(get_session),  # noqa: B008
) -> Response:
    settings = get_settings_from(request)
    await revoke_session(db, principal.session_id)
    await audit.record(
        db,
        action="LOGOUT",
        resource_type="session",
        resource_id=principal.session_id,
        result=AuditResult.SUCCESS,
        actor_type=ActorType.USER,
        actor_id=principal.user_id,
        source_ip=client_ip(request),
    )
    await db.commit()
    response.status_code = 204
    clear_session_cookies(response, settings)
    return response


@router.get("/auth/entra/login")
async def entra_login(
    request: Request,
    db: AsyncSession = Depends(get_session),  # noqa: B008
) -> RedirectResponse:
    settings = get_settings_from(request)
    if not settings.entra_configured:
        raise AppError("INTEGRATION_NOT_CONFIGURED", 503)
    state, nonce, verifier = new_token(), new_token(), new_token(64)
    db.add(
        OidcLoginState(
            state_hash=hash_token(state),
            nonce=nonce,
            code_verifier=verifier,
            expires_at=datetime.now(UTC) + _OIDC_STATE_TTL,
        )
    )
    await db.commit()
    url = entra.authorization_url(settings, state=state, nonce=nonce, code_verifier=verifier)
    return RedirectResponse(url, status_code=302)


def _login_error_redirect(web_base_url: str, code: str) -> RedirectResponse:
    return RedirectResponse(f"{web_base_url}/?login_error={code}", status_code=302)


@router.get("/auth/callback")
async def entra_callback(
    request: Request,
    db: AsyncSession = Depends(get_session),  # noqa: B008
    code: str | None = Query(default=None, max_length=4096),
    state: str | None = Query(default=None, max_length=128),
    error: str | None = Query(default=None, max_length=100),
) -> RedirectResponse:
    settings = get_settings_from(request)
    ip = client_ip(request)
    if not settings.entra_configured:
        raise AppError("INTEGRATION_NOT_CONFIGURED", 503)

    async def fail(reason: str, public_code: str = "LOGIN_FAILED") -> RedirectResponse:
        await db.rollback()
        await audit.record(
            db,
            action="LOGIN_FAILED",
            resource_type="session",
            result=AuditResult.DENIED,
            actor_type=ActorType.ANONYMOUS,
            reason_code=reason,
            source_ip=ip,
            metadata={"provider": "entra"},
        )
        await db.commit()
        return _login_error_redirect(settings.web_base_url, public_code)

    if error or not code or not state:
        return await fail("IDP_ERROR" if error else "CALLBACK_PARAMS_MISSING")

    # Atomically consume the state so a replayed callback cannot succeed.
    consumed = (
        await db.execute(
            update(OidcLoginState)
            .where(
                OidcLoginState.state_hash == hash_token(state),
                OidcLoginState.consumed_at.is_(None),
                OidcLoginState.expires_at > datetime.now(UTC),
            )
            .values(consumed_at=datetime.now(UTC))
            .returning(OidcLoginState.nonce, OidcLoginState.code_verifier)
        )
    ).first()
    if consumed is None:
        return await fail("STATE_INVALID")
    await db.commit()

    client: httpx.AsyncClient = request.app.state.http_client
    try:
        identity = await entra.complete_login(
            client,
            request.app.state.entra_jwks,
            settings,
            code=code,
            code_verifier=consumed.code_verifier,
            expected_nonce=consumed.nonce,
        )
    except entra.EntraError as exc:
        return await fail(exc.code)

    user = await db.scalar(
        select(User).where(
            User.identity_provider == IdentityProvider.ENTRA,
            User.external_subject == identity.external_subject,
        )
    )
    if user is None:
        if not settings.entra_jit_provisioning:
            return await fail("USER_NOT_PROVISIONED")
        if await db.scalar(select(User.id).where(User.email == identity.email)):
            return await fail("EMAIL_ALREADY_LINKED", "ACCOUNT_LINK_REQUIRED")
        user = User(
            email=identity.email,
            display_name=identity.display_name,
            identity_provider=IdentityProvider.ENTRA,
            external_subject=identity.external_subject,
            is_active=True,
        )
        db.add(user)
        await db.flush()
        employee = await db.scalar(select(Role.id).where(Role.name == RoleName.EMPLOYEE))
        db.add(UserRole(user_id=user.id, role_id=employee))
        await audit.record(
            db,
            action="USER_PROVISIONED",
            resource_type="user",
            resource_id=user.id,
            result=AuditResult.SUCCESS,
            actor_type=ActorType.SYSTEM,
            metadata={"provider": "entra", "roles": [RoleName.EMPLOYEE.value]},
        )
    elif not user.is_active:
        return await fail("ACCOUNT_DISABLED", "ACCOUNT_DISABLED")

    issued = await create_session(
        db,
        settings,
        user_id=user.id,
        identity_provider=IdentityProvider.ENTRA,
        source_ip=ip,
        user_agent=request.headers.get("user-agent"),
    )
    await audit.record(
        db,
        action="LOGIN_SUCCEEDED",
        resource_type="session",
        resource_id=issued.session.id,
        result=AuditResult.SUCCESS,
        actor_type=ActorType.USER,
        actor_id=user.id,
        source_ip=ip,
        metadata={"provider": "entra"},
    )
    await db.commit()
    redirect = RedirectResponse(f"{settings.web_base_url}/", status_code=302)
    set_session_cookies(redirect, settings, issued)
    return redirect
