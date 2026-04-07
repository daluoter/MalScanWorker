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


async def get_job_for_context(job_id: str, session: AsyncSession | None = None) -> Any | None:
    """Fetch Job record instance for pipeline context.

    If session is provided, use it; otherwise create a temporary one.
    """
    from malscan.models.job import Job
    from sqlalchemy import select

    if session:
        stmt = select(Job).where(Job.id == UUID(job_id))
        result = await session.execute(stmt)
        return result.scalar_one_or_none()

    async with AsyncSession(_engine) as session:
        stmt = select(Job).where(Job.id == UUID(job_id))
        result = await session.execute(stmt)
        return result.scalar_one_or_none()


async def update_job_status(
    job_id: str,
    status: str,
    error_message: str | None = None,
    **kwargs: Any,
) -> None:
    """Update job status in the database.

    Args:
        job_id: Job UUID as string.
        status: New status (queued, scanning, done, failed).
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


async def update_job_result(job_id: str, result: dict[str, Any]) -> None:
    """Store analysis result in job record.

    Args:
        job_id: Job UUID as string.
        result: Analysis result as JSON-serializable dict.
    """
    async with AsyncSession(_engine) as session:
        try:
            import json

            from sqlalchemy import text

            stmt = text(
                """
                UPDATE jobs
                SET result = :result, updated_at = :updated_at
                WHERE id = :job_id
                """
            )

            await session.execute(
                stmt,
                {
                    "job_id": UUID(job_id),
                    "result": json.dumps(result),
                    "updated_at": datetime.now(timezone.utc),
                },
            )
            await session.commit()

            log.info(
                "job_result_stored",
                job_id=job_id,
            )

        except Exception as e:
            log.error("job_result_store_failed", job_id=job_id, error=str(e))
            # Don't raise - result store failure should not block status update
            await session.rollback()


async def update_job_result_strict(job_id: str, result: dict[str, Any]) -> None:
    """Store analysis result and raise on failure."""
    async with AsyncSession(_engine) as session:
        import json

        from sqlalchemy import text

        stmt = text(
            """
            UPDATE jobs
            SET result = :result, updated_at = :updated_at
            WHERE id = :job_id
            """
        )

        await session.execute(
            stmt,
            {
                "job_id": UUID(job_id),
                "result": json.dumps(result),
                "updated_at": datetime.now(timezone.utc),
            },
        )
        await session.commit()


async def increment_password_attempts(job_id: str) -> int:
    """Atomically increment password attempts and return current count."""
    async with AsyncSession(_engine) as session:
        from sqlalchemy import text

        stmt = text(
            """
            UPDATE jobs
            SET password_attempts = password_attempts + 1,
                updated_at = :updated_at
            WHERE id = :job_id
            RETURNING password_attempts
            """
        )

        result = await session.execute(
            stmt,
            {
                "job_id": UUID(job_id),
                "updated_at": datetime.now(timezone.utc),
            },
        )
        await session.commit()
        attempts = result.scalar_one_or_none()
        if attempts is None:
            raise ValueError(f"Job not found: {job_id}")
        return int(attempts)


async def create_artifact(
    *,
    parent_id: str | None,
    root_id: str | None,
    depth: int,
    sha256: str,
    size: int,
    original_filename: str,
    origin_path: str | None = None,
    extraction_source: str | None = None,
    archive_type: str | None = None,
    extraction_note: str | None = None,
    job_id: str | None = None,
    root_job_id: str | None = None,
    md5: str | None = None,
    sha1: str | None = None,
    mime: str | None = None,
    verdict: str | None = None,
    score: int | None = None,
) -> dict[str, Any]:
    """Create an artifact record. Returns dict with 'id' key.

    Uses its own session to avoid polluting the pipeline session.
    """
    from uuid import UUID as _UUID
    from uuid import uuid4

    async with AsyncSession(_engine) as session:
        try:
            artifact_id = uuid4()
            from sqlalchemy import text

            stmt = text(
                """
                INSERT INTO artifacts (
                    id, parent_id, root_id, depth,
                    sha256, md5, sha1, size, mime, original_filename,
                    origin_path, extraction_source, archive_type, extraction_note,
                    job_id, root_job_id, verdict, score, created_at
                ) VALUES (
                    :id, :parent_id, :root_id, :depth,
                    :sha256, :md5, :sha1, :size, :mime, :original_filename,
                    :origin_path, :extraction_source, :archive_type, :extraction_note,
                    :job_id, :root_job_id, :verdict, :score, :created_at
                )
                """
            )
            await session.execute(
                stmt,
                {
                    "id": artifact_id,
                    "parent_id": _UUID(parent_id) if parent_id else None,
                    "root_id": _UUID(root_id) if root_id else None,
                    "depth": depth,
                    "sha256": sha256,
                    "md5": md5,
                    "sha1": sha1,
                    "size": size,
                    "mime": mime,
                    "original_filename": original_filename,
                    "origin_path": origin_path,
                    "extraction_source": extraction_source,
                    "archive_type": archive_type,
                    "extraction_note": extraction_note,
                    "job_id": _UUID(job_id) if job_id else None,
                    "root_job_id": _UUID(root_job_id) if root_job_id else None,
                    "verdict": verdict,
                    "score": score,
                    "created_at": datetime.now(timezone.utc),
                },
            )
            await session.commit()
            return {"id": str(artifact_id)}
        except Exception:
            await session.rollback()
            raise


async def update_artifact_verdict(
    artifact_id: str,
    verdict: str,
    score: int,
) -> None:
    """Update the denormalized verdict/score on an artifact record."""
    from uuid import UUID as _UUID

    from sqlalchemy import text

    async with AsyncSession(_engine) as session:
        try:
            stmt = text("UPDATE artifacts SET verdict = :verdict, score = :score WHERE id = :id")
            await session.execute(
                stmt, {"id": _UUID(artifact_id), "verdict": verdict, "score": score}
            )
            await session.commit()
        except Exception:
            await session.rollback()
            raise
