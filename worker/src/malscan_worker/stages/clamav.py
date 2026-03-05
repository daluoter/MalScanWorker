"""ClamAV scanning stage using pyclamd network socket."""

import asyncio
from datetime import datetime, timezone

import pyclamd
import structlog

from malscan_worker.config import get_settings
from malscan_worker.stages.base import Stage, StageContext, StageResult

settings = get_settings()
log = structlog.get_logger()


def _get_clamd_client() -> pyclamd.ClamdNetworkSocket:
    """Create and return a ClamdNetworkSocket instance."""
    return pyclamd.ClamdNetworkSocket(
        host=settings.clamav_host, port=settings.clamav_port, timeout=settings.stage_timeout_seconds
    )


def _scan_stream_sync(file_content: bytes) -> dict:
    """Synchronous function to scan a stream using pyclamd."""
    cd = _get_clamd_client()
    # Check if clamd is alive
    if not cd.ping():
        raise ConnectionError(
            f"Could not ping clamd at {settings.clamav_host}:{settings.clamav_port}"
        )

    # Read the file content as stream
    return cd.scan_stream(file_content)


class ClamAVStage(Stage):
    """Scan file with ClamAV using pyclamd network socket."""

    @property
    def name(self) -> str:
        return "clamav"

    async def execute(self, ctx: StageContext) -> StageResult:
        started_at = datetime.now(timezone.utc)

        try:
            if ctx.file_path is None or not ctx.file_path.exists():
                raise FileNotFoundError(f"File not found: {ctx.file_path}")

            # Read file content
            # For stream scanning to a remote clamd container, we send the bytes directly.
            # This avoids volume mounting issues between worker and clamd containers.
            file_content = ctx.file_path.read_bytes()

            # Run pyclamd scan in thread pool
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(None, _scan_stream_sync, file_content)

            # Parse result
            # scan_stream returns None if clean, or {'stream': ('FOUND', 'VirusName')}
            infected = result is not None
            threat_name = None

            if infected and "stream" in result:
                threat_name = result["stream"][1]

            ended_at = datetime.now(timezone.utc)
            duration_ms = int((ended_at - started_at).total_seconds() * 1000)

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

        except ConnectionError as e:
            log.error(
                "clamav_connection_failed",
                error=str(e),
                host=settings.clamav_host,
                port=settings.clamav_port,
            )
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
                error=f"ClamAV connection error: {e}",
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
