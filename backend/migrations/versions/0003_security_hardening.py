"""Security hardening: least-privilege runtime role, append-only audit, role reference data.

Revision ID: 0003
Revises: 0002
Create Date: 2026-11-16

The runtime role is cluster-wide; downgrade revokes its privileges in this database but does
not drop it, because other databases on the same server (for example the test database) may
still use it.
"""

import re
from collections.abc import Sequence

from alembic import op

from app.core.config import get_settings

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

APP_ROLE = "sentinel_app"
# Generated passwords are alphanumeric; anything else is refused rather than escaped into DDL.
_PASSWORD_RE = re.compile(r"^[A-Za-z0-9]{24,128}$")

ROLES = [
    ("EMPLOYEE", "Request software for own enrolled devices and view own requests"),
    ("APPROVER", "Approve or reject requests routed by policy"),
    ("SOFTWARE_ADMIN", "Manage catalogue entries, package metadata and lifecycle"),
    ("SECURITY_ADMIN", "Manage banned software, threat policy and security integrations"),
    ("AUDITOR", "Read audit records and reports"),
    ("PLATFORM_ADMIN", "Manage identity, endpoint enrollment and system configuration"),
]


def _app_password() -> str:
    secret = get_settings().app_db_password
    if secret is None:
        raise RuntimeError("APP_DB_PASSWORD must be set to create the runtime database role")
    value = secret.get_secret_value()
    if not _PASSWORD_RE.match(value):
        raise RuntimeError("APP_DB_PASSWORD must be 24-128 alphanumeric characters")
    return value


def upgrade() -> None:
    password = _app_password()
    op.execute(
        f"""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{APP_ROLE}') THEN
                CREATE ROLE {APP_ROLE} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
            END IF;
        END
        $$;
        """
    )
    op.execute(f"ALTER ROLE {APP_ROLE} WITH LOGIN PASSWORD '{password}'")
    op.execute(
        f"DO $$ BEGIN EXECUTE format('GRANT CONNECT ON DATABASE %I TO {APP_ROLE}', "
        "current_database()); END $$;"
    )
    op.execute(f"GRANT USAGE ON SCHEMA public TO {APP_ROLE}")
    op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {APP_ROLE}")
    op.execute(f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {APP_ROLE}")
    op.execute(
        f"ALTER DEFAULT PRIVILEGES IN SCHEMA public "
        f"GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {APP_ROLE}"
    )
    op.execute(
        f"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO {APP_ROLE}"
    )
    # Application role: audit rows are insert/read only; roles and schema version are read only.
    op.execute(f"REVOKE UPDATE, DELETE, TRUNCATE ON audit_events FROM {APP_ROLE}")
    op.execute(f"REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON roles FROM {APP_ROLE}")
    op.execute(f"REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON alembic_version FROM {APP_ROLE}")

    # Defence in depth: block mutation for every role, including the owner.
    op.execute(
        """
        CREATE FUNCTION audit_events_append_only() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION 'audit_events is append-only' USING ERRCODE = 'insufficient_privilege';
        END
        $$;
        """
    )
    op.execute(
        "CREATE TRIGGER audit_events_no_update_delete BEFORE UPDATE OR DELETE ON audit_events "
        "FOR EACH ROW EXECUTE FUNCTION audit_events_append_only()"
    )
    op.execute(
        "CREATE TRIGGER audit_events_no_truncate BEFORE TRUNCATE ON audit_events "
        "FOR EACH STATEMENT EXECUTE FUNCTION audit_events_append_only()"
    )

    values = ", ".join(f"('{name}', '{desc}')" for name, desc in ROLES)
    op.execute(
        f"INSERT INTO roles (name, description) VALUES {values} ON CONFLICT (name) DO NOTHING"
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS audit_events_no_truncate ON audit_events")
    op.execute("DROP TRIGGER IF EXISTS audit_events_no_update_delete ON audit_events")
    op.execute("DROP FUNCTION IF EXISTS audit_events_append_only()")
    op.execute("DELETE FROM user_roles")
    op.execute("DELETE FROM roles")
    op.execute(
        f"""
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{APP_ROLE}') THEN
                EXECUTE 'ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM {APP_ROLE}';
                EXECUTE 'ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON SEQUENCES FROM {APP_ROLE}';
                EXECUTE 'REVOKE ALL ON ALL TABLES IN SCHEMA public FROM {APP_ROLE}';
                EXECUTE 'REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM {APP_ROLE}';
                EXECUTE 'REVOKE USAGE ON SCHEMA public FROM {APP_ROLE}';
                EXECUTE format('REVOKE CONNECT ON DATABASE %I FROM {APP_ROLE}', current_database());
            END IF;
        END
        $$;
        """
    )
