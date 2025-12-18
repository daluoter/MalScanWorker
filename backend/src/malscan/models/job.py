"""Job model for tracking analysis jobs."""

import uuid
from datetime import datetime, timezone
from enum import Enum

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from malscan.models.base import Base


class JobStatus(str, Enum):
    """Status of an analysis job."""

    QUEUED = "queued"
    SCANNING = "scanning"
    DONE = "done"
    FAILED = "failed"


class Job(Base):
    """Represents a malware analysis job."""

    __tablename__ = "jobs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    file_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("files.id"), nullable=False, index=True
    )
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default=JobStatus.QUEUED.value, index=True
    )
    current_stage: Mapped[str | None] = mapped_column(String(50), nullable=True)
    stages_done: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    stages_total: Mapped[int] = mapped_column(Integer, nullable=False, default=5)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    result: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationship to file
    file: Mapped["File"] = relationship("File", back_populates="jobs")  # noqa: F821
