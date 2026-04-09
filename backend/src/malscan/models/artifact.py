"""Artifact model for extraction provenance tree."""

import uuid
from datetime import datetime, timezone

from sqlalchemy import BigInteger, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from malscan.models.base import Base


class Artifact(Base):
    __tablename__ = "artifacts"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Tree structure
    parent_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("artifacts.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    root_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("artifacts.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    depth: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # File identity
    sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    md5: Mapped[str | None] = mapped_column(String(32), nullable=True)
    sha1: Mapped[str | None] = mapped_column(String(40), nullable=True)
    size: Mapped[int] = mapped_column(BigInteger, nullable=False)
    mime: Mapped[str | None] = mapped_column(String(200), nullable=True)
    original_filename: Mapped[str] = mapped_column(String(500), nullable=False)

    # Extraction provenance
    origin_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    extraction_source: Mapped[str | None] = mapped_column(String(50), nullable=True)
    archive_type: Mapped[str | None] = mapped_column(String(20), nullable=True)
    extraction_note: Mapped[str | None] = mapped_column(String(100), nullable=True)

    # Linkage
    job_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("jobs.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    root_job_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("jobs.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )

    # Denormalized result
    verdict: Mapped[str | None] = mapped_column(String(20), nullable=True)
    score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    risk_level: Mapped[str | None] = mapped_column(String(20), nullable=True)
    policy_version: Mapped[str | None] = mapped_column(String(20), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    parent: Mapped["Artifact | None"] = relationship(
        "Artifact",
        back_populates="children",
        remote_side="Artifact.id",
        foreign_keys=[parent_id],
    )
    children: Mapped[list["Artifact"]] = relationship(
        "Artifact",
        back_populates="parent",
        cascade="all, delete-orphan",
        foreign_keys=[parent_id],
    )
    job: Mapped["Job | None"] = relationship(  # noqa: F821
        "Job", foreign_keys=[job_id]
    )
