"""Role-based permissions (spec §2). Roles are always loaded from the database."""

from __future__ import annotations

from collections.abc import Iterable
from enum import StrEnum

from app.db.enums import RoleName


class Permission(StrEnum):
    REQUEST_CREATE = "request:create"
    REQUEST_READ_OWN = "request:read_own"
    REQUEST_CANCEL_OWN = "request:cancel_own"
    DEVICE_READ_OWN = "device:read_own"
    CATALOGUE_READ = "catalogue:read"
    APPROVAL_READ = "approval:read"
    APPROVAL_DECIDE = "approval:decide"
    CATALOGUE_MANAGE = "catalogue:manage"
    SECURITY_READ = "security:read"
    SECURITY_MANAGE = "security:manage"
    AUDIT_READ = "audit:read"
    USER_READ = "user:read"
    ROLE_ASSIGN = "role:assign"
    DEVICE_MANAGE = "device:manage"
    ENROLLMENT_MANAGE = "enrollment:manage"
    INTEGRATION_READ = "integration:read"


ROLE_PERMISSIONS: dict[RoleName, frozenset[Permission]] = {
    RoleName.EMPLOYEE: frozenset(
        {
            Permission.REQUEST_CREATE,
            Permission.REQUEST_READ_OWN,
            Permission.REQUEST_CANCEL_OWN,
            Permission.DEVICE_READ_OWN,
            Permission.CATALOGUE_READ,
        }
    ),
    RoleName.APPROVER: frozenset({Permission.APPROVAL_READ, Permission.APPROVAL_DECIDE}),
    RoleName.SOFTWARE_ADMIN: frozenset({Permission.CATALOGUE_READ, Permission.CATALOGUE_MANAGE}),
    RoleName.SECURITY_ADMIN: frozenset(
        {
            Permission.SECURITY_READ,
            Permission.SECURITY_MANAGE,
            Permission.AUDIT_READ,
            Permission.INTEGRATION_READ,
        }
    ),
    # Auditors are strictly read-only.
    RoleName.AUDITOR: frozenset({Permission.AUDIT_READ}),
    RoleName.PLATFORM_ADMIN: frozenset(
        {
            Permission.USER_READ,
            Permission.ROLE_ASSIGN,
            Permission.DEVICE_MANAGE,
            Permission.ENROLLMENT_MANAGE,
            Permission.INTEGRATION_READ,
        }
    ),
}


def permissions_for(roles: Iterable[str]) -> frozenset[Permission]:
    granted: set[Permission] = set()
    for name in roles:
        try:
            granted |= ROLE_PERMISSIONS[RoleName(name)]
        except ValueError:
            continue  # Unknown role names grant nothing.
    return frozenset(granted)
