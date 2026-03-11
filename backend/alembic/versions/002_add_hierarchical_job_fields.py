"""Add hierarchical analysis fields to jobs table

Revision ID: 002_add_hierarchical_job_fields
Revises: 001_add_job_result
Create Date: 2026-03-11
"""

from typing import Sequence, Union

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "002_add_hierarchical_job_fields"
down_revision: Union[str, None] = "001_add_job_result"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add hierarchical job fields: parent_job_id, depth, and sub-job counters."""
    op.add_column(
        "jobs",
        sa.Column(
            "parent_job_id",
            UUID(as_uuid=True),
            sa.ForeignKey("jobs.id", ondelete="CASCADE"),
            nullable=True,
        ),
    )
    op.add_column("jobs", sa.Column("depth", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("jobs", sa.Column("total_sub", sa.Integer(), nullable=False, server_default="0"))
    op.add_column(
        "jobs", sa.Column("completed_sub", sa.Integer(), nullable=False, server_default="0")
    )
    op.add_column(
        "jobs", sa.Column("malicious_sub", sa.Integer(), nullable=False, server_default="0")
    )
    op.create_index("ix_jobs_parent_job_id", "jobs", ["parent_job_id"])


def downgrade() -> None:
    """Remove hierarchical job fields."""
    op.drop_index("ix_jobs_parent_job_id", table_name="jobs")
    op.drop_column("jobs", "malicious_sub")
    op.drop_column("jobs", "completed_sub")
    op.drop_column("jobs", "total_sub")
    op.drop_column("jobs", "depth")
    op.drop_column("jobs", "parent_job_id")
