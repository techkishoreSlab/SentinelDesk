"""User and role administration (PLATFORM_ADMIN). Every change is audited."""

from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, ConfigDict
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import service as audit
from app.auth.dependencies import Principal, client_ip, load_role_names, require
from app.auth.rbac import Permission
from app.core.errors import AppError
from app.db.enums import ActorType, AuditResult, RoleName
from app.db.session import get_session
from app.users.models import Role, User, UserRole

router = APIRouter(prefix="/api/v1/admin/users", tags=["admin"])


class UserSummary(BaseModel):
    id: uuid.UUID
    email: str
    display_name: str
    identity_provider: str
    is_active: bool
    roles: list[str]
    created_at: datetime


class UserPage(BaseModel):
    items: list[UserSummary]
    total: int
    limit: int
    offset: int


class RoleAssignment(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role: RoleName


@router.get("", response_model=UserPage)
async def list_users(
    _: Principal = Depends(require(Permission.USER_READ)),  # noqa: B008
    db: AsyncSession = Depends(get_session),  # noqa: B008
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0, le=100_000),
) -> UserPage:
    total = await db.scalar(select(func.count()).select_from(User)) or 0
    users = (await db.scalars(select(User).order_by(User.email).limit(limit).offset(offset))).all()
    role_rows = (
        await db.execute(
            select(UserRole.user_id, Role.name)
            .join(Role, Role.id == UserRole.role_id)
            .where(UserRole.user_id.in_([u.id for u in users]))
        )
    ).all()
    roles: dict[uuid.UUID, list[str]] = {}
    for user_id, name in role_rows:
        roles.setdefault(user_id, []).append(name)
    items = [
        UserSummary(
            id=u.id,
            email=u.email,
            display_name=u.display_name,
            identity_provider=u.identity_provider,
            is_active=u.is_active,
            roles=sorted(roles.get(u.id, [])),
            created_at=u.created_at,
        )
        for u in users
    ]
    return UserPage(items=items, total=total, limit=limit, offset=offset)


async def _audit_role_change(
    db: AsyncSession,
    request: Request,
    principal: Principal,
    *,
    action: str,
    target: uuid.UUID,
    role: RoleName,
    result: AuditResult,
    reason: str | None = None,
) -> None:
    await audit.record(
        db,
        action=action,
        resource_type="user",
        resource_id=target,
        result=result,
        actor_type=ActorType.USER,
        actor_id=principal.user_id,
        reason_code=reason,
        source_ip=client_ip(request),
        metadata={"role": role.value},
    )


async def _target_and_role(
    db: AsyncSession, user_id: uuid.UUID, role: RoleName
) -> tuple[User, Role]:
    # Lock the target row so concurrent role edits on the same user serialize.
    user = await db.scalar(select(User).where(User.id == user_id).with_for_update())
    role_row = await db.scalar(select(Role).where(Role.name == role))
    if user is None or role_row is None:
        raise AppError("NOT_FOUND", 404)
    return user, role_row


@router.post("/{user_id}/roles", response_model=UserSummary)
async def assign_role(
    user_id: uuid.UUID,
    body: RoleAssignment,
    request: Request,
    principal: Principal = Depends(require(Permission.ROLE_ASSIGN)),  # noqa: B008
    db: AsyncSession = Depends(get_session),  # noqa: B008
) -> UserSummary:
    if user_id == principal.user_id:
        await _audit_role_change(
            db,
            request,
            principal,
            action="ROLE_ASSIGN",
            target=user_id,
            role=body.role,
            result=AuditResult.DENIED,
            reason="SELF_ROLE_CHANGE_FORBIDDEN",
        )
        await db.commit()
        raise AppError("SELF_ROLE_CHANGE_FORBIDDEN", 403)
    user, role_row = await _target_and_role(db, user_id, body.role)
    exists = await db.scalar(
        select(UserRole.user_id).where(UserRole.user_id == user.id, UserRole.role_id == role_row.id)
    )
    if not exists:
        db.add(UserRole(user_id=user.id, role_id=role_row.id, assigned_by=principal.user_id))
        await _audit_role_change(
            db,
            request,
            principal,
            action="ROLE_ASSIGN",
            target=user.id,
            role=body.role,
            result=AuditResult.SUCCESS,
        )
    await db.commit()
    return await _summary(db, user)


@router.delete("/{user_id}/roles/{role}", response_model=UserSummary)
async def remove_role(
    user_id: uuid.UUID,
    role: RoleName,
    request: Request,
    principal: Principal = Depends(require(Permission.ROLE_ASSIGN)),  # noqa: B008
    db: AsyncSession = Depends(get_session),  # noqa: B008
) -> UserSummary:
    if user_id == principal.user_id:
        await _audit_role_change(
            db,
            request,
            principal,
            action="ROLE_REMOVE",
            target=user_id,
            role=role,
            result=AuditResult.DENIED,
            reason="SELF_ROLE_CHANGE_FORBIDDEN",
        )
        await db.commit()
        raise AppError("SELF_ROLE_CHANGE_FORBIDDEN", 403)
    user, role_row = await _target_and_role(db, user_id, role)
    if role == RoleName.PLATFORM_ADMIN:
        # Serialize platform-admin removals so two admins cannot remove each other concurrently.
        await db.execute(select(Role.id).where(Role.id == role_row.id).with_for_update())
        admins = await db.scalar(
            select(func.count()).select_from(UserRole).where(UserRole.role_id == role_row.id)
        )
        if (admins or 0) <= 1:
            raise AppError("LAST_PLATFORM_ADMIN", 409)
    deleted = await db.execute(
        delete(UserRole).where(UserRole.user_id == user.id, UserRole.role_id == role_row.id)
    )
    if deleted.rowcount:  # type: ignore[attr-defined]
        await _audit_role_change(
            db,
            request,
            principal,
            action="ROLE_REMOVE",
            target=user.id,
            role=role,
            result=AuditResult.SUCCESS,
        )
    await db.commit()
    return await _summary(db, user)


async def _summary(db: AsyncSession, user: User) -> UserSummary:
    return UserSummary(
        id=user.id,
        email=user.email,
        display_name=user.display_name,
        identity_provider=user.identity_provider,
        is_active=user.is_active,
        roles=sorted(await load_role_names(db, user.id)),
        created_at=user.created_at,
    )
