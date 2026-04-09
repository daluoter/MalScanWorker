"""Add risk metadata fields to artifacts.

Revision ID: 005_add_artifact_risk_fields
Revises: 004_add_artifacts_table
"""

from typing import Union

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "005_add_artifact_risk_fields"
down_revision: Union[str, None] = "004_add_artifacts_table"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("artifacts", sa.Column("risk_level", sa.String(length=20), nullable=True))
    op.add_column("artifacts", sa.Column("policy_version", sa.String(length=20), nullable=True))


def downgrade() -> None:
    op.drop_column("artifacts", "policy_version")
    op.drop_column("artifacts", "risk_level")
