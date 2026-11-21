"""Installation job progress for employee-facing download % and phase.

Revision ID: 0006
Revises: 0005
Create Date: 2026-11-21

Additive columns only. Agents that never POST progress leave these NULL;
the UI falls back to phase labels + indeterminate animation.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TABLE = "installation_jobs"


def upgrade() -> None:
    op.add_column(TABLE, sa.Column("progress_phase", sa.String(length=16), nullable=True))
    op.add_column(TABLE, sa.Column("progress_bytes_done", sa.BigInteger(), nullable=True))
    op.add_column(TABLE, sa.Column("progress_bytes_total", sa.BigInteger(), nullable=True))
    op.add_column(
        TABLE,
        sa.Column("progress_updated_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_check_constraint(
        "ck_installation_jobs_progress_phase_valid",
        TABLE,
        "progress_phase IS NULL OR progress_phase IN "
        "('DOWNLOADING', 'INSTALLING', 'VERIFYING')",
    )
    op.create_check_constraint(
        "ck_installation_jobs_progress_bytes_non_negative",
        TABLE,
        "(progress_bytes_done IS NULL OR progress_bytes_done >= 0) AND "
        "(progress_bytes_total IS NULL OR progress_bytes_total >= 0)",
    )


def downgrade() -> None:
    op.drop_constraint("ck_installation_jobs_progress_bytes_non_negative", TABLE, type_="check")
    op.drop_constraint("ck_installation_jobs_progress_phase_valid", TABLE, type_="check")
    op.drop_column(TABLE, "progress_updated_at")
    op.drop_column(TABLE, "progress_bytes_total")
    op.drop_column(TABLE, "progress_bytes_done")
    op.drop_column(TABLE, "progress_phase")
