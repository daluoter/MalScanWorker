"""Add password attempts field to jobs table

Revision ID: 003_add_password_attempts_and_status_fields
Revises: 002_add_hierarchical_job_fields
Create Date: 2026-04-01
"""

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "003_add_password_attempts_and_status_fields"
down_revision: Union[str, None] = "002_add_hierarchical_job_fields"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add password_attempts column to jobs table."""
    op.add_column(
        "jobs", sa.Column("password_attempts", sa.Integer(), nullable=False, server_default="0")
    )


def downgrade() -> None:
    """Remove password_attempts column from jobs table."""
    op.drop_column("jobs", "password_attempts")
