"""Add artifacts table and artifact_id FK on jobs.

Revision ID: 004_add_artifacts_table
Revises: 003_add_password_attempts_and_status_fields
"""

from typing import Union

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "004_add_artifacts_table"
down_revision: Union[str, None] = "003_add_password_attempts_and_status_fields"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "artifacts",
        sa.Column(
            "id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")
        ),
        # Tree structure
        sa.Column(
            "parent_id",
            UUID(as_uuid=True),
            sa.ForeignKey("artifacts.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column(
            "root_id",
            UUID(as_uuid=True),
            sa.ForeignKey("artifacts.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("depth", sa.Integer, nullable=False, server_default="0"),
        # File identity
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("md5", sa.String(32), nullable=True),
        sa.Column("sha1", sa.String(40), nullable=True),
        sa.Column("size", sa.BigInteger, nullable=False),
        sa.Column("mime", sa.String(200), nullable=True),
        sa.Column("original_filename", sa.String(500), nullable=False),
        # Extraction provenance
        sa.Column("origin_path", sa.Text, nullable=True),
        sa.Column("extraction_source", sa.String(50), nullable=True),
        sa.Column("archive_type", sa.String(20), nullable=True),
        sa.Column("extraction_note", sa.String(100), nullable=True),
        # Linkage to jobs
        sa.Column(
            "job_id",
            UUID(as_uuid=True),
            sa.ForeignKey("jobs.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "root_job_id",
            UUID(as_uuid=True),
            sa.ForeignKey("jobs.id", ondelete="CASCADE"),
            nullable=True,
        ),
        # Denormalized scan result
        sa.Column("verdict", sa.String(20), nullable=True),
        sa.Column("score", sa.Integer, nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )
    op.create_index("ix_artifacts_parent_id", "artifacts", ["parent_id"])
    op.create_index("ix_artifacts_root_id", "artifacts", ["root_id"])
    op.create_index("ix_artifacts_sha256", "artifacts", ["sha256"])
    op.create_index("ix_artifacts_job_id", "artifacts", ["job_id"])
    op.create_index("ix_artifacts_root_job_id", "artifacts", ["root_job_id"])

    # Add artifact_id FK to jobs table
    op.add_column(
        "jobs",
        sa.Column(
            "artifact_id",
            UUID(as_uuid=True),
            sa.ForeignKey("artifacts.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.create_index("ix_jobs_artifact_id", "jobs", ["artifact_id"])


def downgrade() -> None:
    op.drop_index("ix_jobs_artifact_id", table_name="jobs")
    op.drop_column("jobs", "artifact_id")
    op.drop_index("ix_artifacts_root_job_id", table_name="artifacts")
    op.drop_index("ix_artifacts_job_id", table_name="artifacts")
    op.drop_index("ix_artifacts_sha256", table_name="artifacts")
    op.drop_index("ix_artifacts_root_id", table_name="artifacts")
    op.drop_index("ix_artifacts_parent_id", table_name="artifacts")
    op.drop_table("artifacts")
