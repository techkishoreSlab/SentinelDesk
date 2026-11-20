"""Microsoft Graph Outlook adapter — honest not-configured path (spec §10.4)."""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.db.enums import NotificationChannel, NotificationStatus, RoleName
from app.requests.models import Notification
from app.users.models import Role, User, UserRole


async def enqueue_approval_notifications(
    db: AsyncSession,
    settings: Settings,
    *,
    request_id: uuid.UUID,
    exclude_user_id: uuid.UUID,
) -> list[Notification]:
    """Create outbox rows for approvers. Never blocks request state on email failure."""
    role_id = await db.scalar(select(Role.id).where(Role.name == RoleName.APPROVER.value))
    if role_id is None:
        return []
    recipients = (
        await db.scalars(
            select(User)
            .join(UserRole, UserRole.user_id == User.id)
            .where(
                UserRole.role_id == role_id,
                User.is_active.is_(True),
                User.id != exclude_user_id,
            )
        )
    ).all()

    configured = bool(settings.entra_configured and settings.graph_sender)
    created: list[Notification] = []
    for user in recipients:
        existing = await db.scalar(
            select(Notification).where(
                Notification.request_id == request_id,
                Notification.recipient_id == user.id,
                Notification.channel == NotificationChannel.OUTLOOK.value,
            )
        )
        if existing is not None:
            continue
        row = Notification(
            request_id=request_id,
            recipient_id=user.id,
            channel=NotificationChannel.OUTLOOK.value,
            status=(
                NotificationStatus.PENDING.value
                if configured
                else NotificationStatus.NOT_CONFIGURED.value
            ),
            attempt_count=0,
            last_error_code=None if configured else "GRAPH_NOT_CONFIGURED",
        )
        db.add(row)
        created.append(row)
    await db.flush()
    return created
