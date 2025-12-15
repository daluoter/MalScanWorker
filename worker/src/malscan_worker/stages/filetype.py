"""File type detection stage using python-magic."""

from datetime import datetime, timezone

import magic

from malscan_worker.stages.base import Stage, StageContext, StageResult


class FileTypeStage(Stage):
    """Detect file type using magic bytes."""

    @property
    def name(self) -> str:
        return "file-type"

    async def execute(self, ctx: StageContext) -> StageResult:
        started_at = datetime.now(timezone.utc)

        try:
            if ctx.file_path is None or not ctx.file_path.exists():
                raise FileNotFoundError(f"File not found: {ctx.file_path}")

            # Detect MIME type
            mime_type = magic.from_file(str(ctx.file_path), mime=True)
            magic_desc = magic.from_file(str(ctx.file_path))
            file_size = ctx.file_path.stat().st_size

            ended_at = datetime.now(timezone.utc)
            duration_ms = int((ended_at - started_at).total_seconds() * 1000)

            return StageResult(
                stage_name=self.name,
                status="ok",
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=duration_ms,
                findings={
                    "mime_type": mime_type,
                    "magic_desc": magic_desc,
                    "file_size": file_size,
                },
                artifacts=[],
                error=None,
            )

        except Exception as e:
            ended_at = datetime.now(timezone.utc)
            duration_ms = int((ended_at - started_at).total_seconds() * 1000)

            return StageResult(
                stage_name=self.name,
                status="failed",
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=duration_ms,
                findings={},
                artifacts=[],
                error=str(e),
            )
