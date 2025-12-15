"""Add result JSONB column to jobs table

Revision ID: 001_add_job_result
Revises:
Create Date: 2025-12-15
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

# revision identifiers, used by Alembic.
revision: str = '001_add_job_result'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add result column to jobs table."""
    op.add_column('jobs', sa.Column('result', JSONB, nullable=True))


def downgrade() -> None:
    """Remove result column from jobs table."""
    op.drop_column('jobs', 'result')
