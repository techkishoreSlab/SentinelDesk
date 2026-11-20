"""Widen device_facts byte counters to BIGINT (16 GiB of RAM overflows int32).

Revision ID: 0004
Revises: 0003
Create Date: 2026-11-17
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

COLUMNS = ("memory_total_bytes", "disk_free_bytes")


def upgrade() -> None:
    for column in COLUMNS:
        op.alter_column("device_facts", column, type_=sa.BigInteger(), existing_type=sa.Integer())


def downgrade() -> None:
    # Narrowing would fail (or truncate) real data; refuse instead of losing facts.
    op.execute(
        "DO $$ BEGIN IF EXISTS (SELECT 1 FROM device_facts) THEN "
        "RAISE EXCEPTION 'device_facts is not empty; refusing to narrow to int32'; "
        "END IF; END $$;"
    )
    for column in COLUMNS:
        op.alter_column("device_facts", column, type_=sa.Integer(), existing_type=sa.BigInteger())
