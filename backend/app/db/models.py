"""Import every model module so `Base.metadata` is complete for Alembic and tests."""

from app.audit.models import AuditEvent
from app.catalogue.models import (
    BannedSoftware,
    CatalogueSoftware,
    CatalogueVersion,
    SoftwareAlias,
    SoftwarePolicy,
)
from app.devices.models import Device, DeviceCredential, DeviceFacts, EnrollmentToken
from app.integrations.models import IntegrationConfig
from app.requests.models import (
    Approval,
    InstallationJob,
    InstallationResult,
    Notification,
    SecurityCheck,
    SoftwareRequest,
)
from app.users.models import (
    AuthThrottle,
    LocalCredential,
    OidcLoginState,
    Role,
    Session,
    User,
    UserRole,
)

__all__ = [
    "Approval",
    "AuditEvent",
    "AuthThrottle",
    "BannedSoftware",
    "CatalogueSoftware",
    "CatalogueVersion",
    "Device",
    "DeviceCredential",
    "DeviceFacts",
    "EnrollmentToken",
    "InstallationJob",
    "InstallationResult",
    "IntegrationConfig",
    "LocalCredential",
    "Notification",
    "OidcLoginState",
    "Role",
    "SecurityCheck",
    "Session",
    "SoftwareAlias",
    "SoftwarePolicy",
    "SoftwareRequest",
    "User",
    "UserRole",
]
