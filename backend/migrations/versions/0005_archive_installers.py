"""Archive installers (DMG / ZIP) and device installer capabilities.

Revision ID: 0005
Revises: 0004
Create Date: 2026-11-20

Adds MACOS_DMG_APP / MACOS_DMG_PKG / MACOS_ZIP_APP installer kinds, the Team ID and payload
columns they require, and the per-device list of installer kinds the endpoint supports.
Existing MACOS_PKG rows are untouched (new columns stay NULL).
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# Frozen copies of app.catalogue.models constants at this revision.
ARCHIVE_FIELDS_CHECK = (
    "installer_type NOT IN ('MACOS_DMG_APP', 'MACOS_DMG_PKG', 'MACOS_ZIP_APP') "
    "OR (expected_team_id IS NOT NULL AND payload_path IS NOT NULL)"
)
PAYLOAD_PATH_CHECK = (
    "payload_path IS NULL OR ("
    "payload_path !~ '[/\\\\]' AND payload_path !~ '^\\.' AND position('..' in payload_path) = 0 "
    "AND ((installer_type IN ('MACOS_DMG_APP', 'MACOS_ZIP_APP') AND payload_path ~ '\\.app$') "
    "OR (installer_type = 'MACOS_DMG_PKG' AND payload_path ~ '\\.pkg$')))"
)

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TABLE = "catalogue_versions"
OLD_TYPES = "'MACOS_PKG', 'WINGET', 'MSI', 'APT', 'DNF'"
NEW_TYPES = (
    "'MACOS_PKG', 'MACOS_DMG_APP', 'MACOS_DMG_PKG', 'MACOS_ZIP_APP', 'WINGET', 'MSI', 'APT', 'DNF'"
)


def upgrade() -> None:
    op.add_column(TABLE, sa.Column("expected_team_id", sa.String(length=10), nullable=True))
    op.add_column(TABLE, sa.Column("payload_path", sa.String(length=200), nullable=True))
    op.drop_constraint(op.f("ck_catalogue_versions_installer_type_valid"), TABLE, type_="check")
    op.create_check_constraint(
        op.f("ck_catalogue_versions_installer_type_valid"),
        TABLE,
        f"installer_type IN ({NEW_TYPES})",
    )
    op.create_check_constraint(
        op.f("ck_catalogue_versions_expected_team_id_format"),
        TABLE,
        "expected_team_id IS NULL OR expected_team_id ~ '^[A-Z0-9]{10}$'",
    )
    op.create_check_constraint(
        op.f("ck_catalogue_versions_archive_fields_required"), TABLE, ARCHIVE_FIELDS_CHECK
    )
    op.create_check_constraint(
        op.f("ck_catalogue_versions_payload_path_format"), TABLE, PAYLOAD_PATH_CHECK
    )
    op.add_column(
        "devices",
        sa.Column("supported_installers", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )


def downgrade() -> None:
    op.execute(
        "DO $$ BEGIN IF EXISTS (SELECT 1 FROM catalogue_versions WHERE installer_type IN "
        "('MACOS_DMG_APP', 'MACOS_DMG_PKG', 'MACOS_ZIP_APP')) THEN "
        "RAISE EXCEPTION 'archive installer versions exist; refusing to downgrade'; "
        "END IF; END $$;"
    )
    op.drop_column("devices", "supported_installers")
    for name in ("payload_path_format", "archive_fields_required", "expected_team_id_format"):
        op.drop_constraint(op.f(f"ck_catalogue_versions_{name}"), TABLE, type_="check")
    op.drop_constraint(op.f("ck_catalogue_versions_installer_type_valid"), TABLE, type_="check")
    op.create_check_constraint(
        op.f("ck_catalogue_versions_installer_type_valid"),
        TABLE,
        f"installer_type IN ({OLD_TYPES})",
    )
    op.drop_column(TABLE, "payload_path")
    op.drop_column(TABLE, "expected_team_id")
