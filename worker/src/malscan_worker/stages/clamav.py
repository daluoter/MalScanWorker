"""ClamAV scanning stage using clamscan CLI."""

import asyncio
from datetime import datetime, timezone

from malscan_worker.config import get_settings
from malscan_worker.stages.base import Stage, StageContext, StageResult

settings = get_settings()


class ClamAVStage(Stage):
    """Scan file with ClamAV using clamscan CLI."""

    @property
    def name(self) -> str:
        return "clamav"

    async def execute(self, ctx: StageContext) -> StageResult:
        started_at = datetime.now(timezone.utc)

        try:
            if ctx.file_path is None or not ctx.file_path.exists():
                raise FileNotFoundError(f"File not found: {ctx.file_path}")

            # Run clamscan
            proc = await asyncio.create_subprocess_exec(
                settings.clamscan_path,
                "--no-summary",
                str(ctx.file_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await proc.communicate()
            output = stdout.decode().strip()

            # Parse result
            # Exit code: 0 = clean, 1 = infected, 2 = error
            infected = proc.returncode == 1
            threat_name = None

            if infected and ":" in output:
                # Format: "/path/to/file: ThreatName FOUND"
                parts = output.split(":")
                if len(parts) >= 2:
                    threat_part = parts[-1].strip()
                    if threat_part.endswith("FOUND"):
                        threat_name = threat_part.replace("FOUND", "").strip()

            ended_at = datetime.now(timezone.utc)
            duration_ms = int((ended_at - started_at).total_seconds() * 1000)

            # Error case (exit code 2)
            if proc.returncode == 2:
                return StageResult(
                    stage_name=self.name,
                    status="failed",
                    started_at=started_at,
                    ended_at=ended_at,
                    duration_ms=duration_ms,
                    findings={},
                    artifacts=[],
                    error=stderr.decode().strip() or "ClamAV error",
                )

            return StageResult(
                stage_name=self.name,
                status="ok",
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=duration_ms,
                findings={
                    "engine": "ClamAV",
                    "infected": infected,
                    "threat_name": threat_name,
                },
                artifacts=[],
                error=None,
            )

        except FileNotFoundError as e:
            if "clamscan" in str(e):
                # clamscan not installed
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
                    error="clamscan not found. Install ClamAV.",
                )
            raise

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
