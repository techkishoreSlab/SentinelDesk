from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.db.columns import created_at, enum_check, updated_at, uuid_pk
from app.db.enums import IdentityProvider, RoleName


class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint("identity_provider", "external_subject"),
        enum_check("identity_provider", IdentityProvider),
        CheckConstraint("email = lower(email)", name="email_normalized"),
        CheckConstraint(
            "(identity_provider = 'local') OR (external_subject IS NOT NULL)",
            name="external_subject_required",
        ),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    email: Mapped[str] = mapped_column(String(254), nullable=False, unique=True)
    display_name: Mapped[str] = mapped_column(String(120), nullable=False)
    identity_provider: Mapped[str] = mapped_column(String(16), nullable=False)
    external_subject: Mapped[str | None] = mapped_column(String(200))
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = created_at()
    updated_at: Mapped[datetime] = updated_at()

    roles: Mapped[list[Role]] = relationship(
        secondary="user_roles",
        primaryjoin="User.id == UserRole.user_id",
        secondaryjoin="Role.id == UserRole.role_id",
        lazy="raise",
        viewonly=True,
    )


class Role(Base):
    __tablename__ = "roles"
    __table_args__ = (enum_check("name", RoleName),)

    id: Mapped[uuid.UUID] = uuid_pk()
    name: Mapped[str] = mapped_column(String(32), nullable=False, unique=True)
    description: Mapped[str] = mapped_column(String(200), nullable=False)


class UserRole(Base):
    __tablename__ = "user_roles"

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="RESTRICT"), primary_key=True
    )
    role_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("roles.id", ondelete="RESTRICT"), primary_key=True
    )
    assigned_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="RESTRICT")
    )
    created_at: Mapped[datetime] = created_at()


class LocalCredential(Base):
    """Password hash for local development accounts only (never for Entra users)."""

    __tablename__ = "local_credentials"

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    password_changed_at: Mapped[datetime] = created_at()
    must_change_password: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class Session(Base):
    __tablename__ = "sessions"
    __table_args__ = (
        Index("ix_sessions_user_active", "user_id", "revoked_at"),
        enum_check("identity_provider", IdentityProvider),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    csrf_token_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    identity_provider: Mapped[str] = mapped_column(String(16), nullable=False)
    last_seen_at: Mapped[datetime] = created_at()
    created_at: Mapped[datetime] = created_at()
    idle_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    absolute_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    source_ip: Mapped[str | None] = mapped_column(String(45))
    user_agent: Mapped[str | None] = mapped_column(String(200))


class AuthThrottle(Base):
    """Failed-login counters keyed by hashed account identifier or client IP."""

    __tablename__ = "auth_throttle"
    __table_args__ = (CheckConstraint("failure_count >= 0", name="failure_count_non_negative"),)

    key: Mapped[str] = mapped_column(String(80), primary_key=True)
    failure_count: Mapped[int] = mapped_column(nullable=False, default=0)
    window_started_at: Mapped[datetime] = created_at()
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class OidcLoginState(Base):
    """Single-use server-side state for an in-flight OIDC authorization-code + PKCE login."""

    __tablename__ = "oidc_login_states"

    id: Mapped[uuid.UUID] = uuid_pk()
    state_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    nonce: Mapped[str] = mapped_column(String(128), nullable=False)
    code_verifier: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = created_at()
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
