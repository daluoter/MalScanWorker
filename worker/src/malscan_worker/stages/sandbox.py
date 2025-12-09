"""Sandbox analysis stage - Mock implementation for MVP."""

import asyncio
from datetime import datetime, timezone

from malscan_worker.config import get_settings
from malscan_worker.stages.base import Stage, StageContext, StageResult

settings = get_settings()


class SandboxStage(Stage):
    """
    Sandbox analysis stage.

    MVP: Mock implementation that returns fake behavior data.
    v2: Replace with real sandbox adapter (Cuckoo, CAPE, etc.)
    """

    @property
    def name(self) -> str:
        return "sandbox"

    async def execute(self, ctx: StageContext) -> StageResult:
        started_at = datetime.now(timezone.utc)

        # Check if sandbox is enabled
        if not settings.sandbox_enabled:
            ended_at = datetime.now(timezone.utc)
            duration_ms = int((ended_at - started_at).total_seconds() * 1000)
            return StageResult(
                stage_name=self.name,
                status="skipped",
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=duration_ms,
                findings={"executed": False, "reason": "Sandbox disabled"},
                artifacts=[],
                error=None,
            )

        # Mock implementation
        if settings.sandbox_mock:
            # Simulate analysis time
            await asyncio.sleep(2)

            ended_at = datetime.now(timezone.utc)
            duration_ms = int((ended_at - started_at).total_seconds() * 1000)

            # Generate mock behavior data
            mock_behaviors = [
                {"type": "file_write", "path": "C:\\Windows\\Temp\\sample.dll"},
                {"type": "registry_read", "key": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion"},
            ]

            mock_network = [
                {"dst_ip": "93.184.216.34", "dst_port": 443, "protocol": "tcp"},
            ]

            return StageResult(
                stage_name=self.name,
                status="ok",
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=duration_ms,
                findings={
                    "executed": True,
                    "behaviors": mock_behaviors,
                    "network_connections": mock_network,
                    "is_mock": True,
                },
                artifacts=[],
                error=None,
            )

        # Real sandbox implementation would go here
        # TODO: Implement real sandbox adapter
        raise NotImplementedError("Real sandbox not implemented yet")
