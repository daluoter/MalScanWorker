"""Database operations for job status updates."""

from datetime import datetime, timezone
from typing import Any
from uuid import UUID

import structlog
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

from malscan_worker.config import get_settings

log = structlog.get_logger()
settings = get_settings()

# Create async engine
_engine = create_async_engine(
    settings.database_url,
    echo=False,
    pool_size=5,
    max_overflow=10,
)


async def update_job_status(
    job_id: str,
    status: str,
    error_message: str | None = None,
    **kwargs: Any,
) -> None:
    """Update job status in the database.

    Args:
        job_id: Job UUID as string.
        status: New status (queued, processing, completed, failed).
        error_message: Optional error message for failed status.
        **kwargs: Additional fields to update.
    """
    async with AsyncSession(_engine) as session:
        try:
            values: dict[str, Any] = {
                "status": status,
                "updated_at": datetime.now(timezone.utc),
            }
            if error_message is not None:
                values["error_message"] = error_message
            values.update(kwargs)

            # Use raw SQL update for efficiency
            from sqlalchemy import text

            stmt = text(
                """
                UPDATE jobs
                SET status = :status, updated_at = :updated_at,
                    error_message = :error_message,
                    current_stage = :current_stage,
                    stages_done = :stages_done
                WHERE id = :job_id
                """
            )

            await session.execute(
                stmt,
                {
                    "job_id": UUID(job_id),
                    "status": status,
                    "updated_at": values["updated_at"],
                    "error_message": error_message,
                    "current_stage": kwargs.get("current_stage"),
                    "stages_done": kwargs.get("stages_done", 0),
                },
            )
            await session.commit()

            log.info(
                "job_status_updated",
                job_id=job_id,
                status=status,
                error_message=error_message,
            )

        except Exception as e:
            log.error("job_status_update_failed", job_id=job_id, error=str(e))
            # Don't raise - status update failure should not block analysis
            await session.rollback()


async def update_job_stage(job_id: str, stage: str, stages_done: int) -> None:
    """Update job stage progress in the database.

    Args:
        job_id: Job UUID as string.
        stage: Current stage name.
        stages_done: Number of completed stages.
    """
    async with AsyncSession(_engine) as session:
        try:
            from sqlalchemy import text

            stmt = text(
                """
                UPDATE jobs
                SET current_stage = :stage, stages_done = :stages_done, updated_at = :updated_at
                WHERE id = :job_id
                """
            )

            await session.execute(
                stmt,
                {
                    "job_id": UUID(job_id),
                    "stage": stage,
                    "stages_done": stages_done,
                    "updated_at": datetime.now(timezone.utc),
                },
            )
            await session.commit()

            log.info(
                "job_stage_updated",
                job_id=job_id,
                stage=stage,
                stages_done=stages_done,
            )

        except Exception as e:
            log.error("job_stage_update_failed", job_id=job_id, error=str(e))
            # Don't raise - stage update failure should not block analysis
            await session.rollback()
