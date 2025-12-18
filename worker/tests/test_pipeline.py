"""Unit tests for the analysis pipeline."""

from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest
from malscan_worker.stages.base import Stage, StageResult


class MockStage(Stage):
    """Mock stage for testing pipeline flow."""

    def __init__(self, name: str, should_fail: bool = False):
        self._name = name
        self.should_fail = should_fail

    @property
    def name(self) -> str:
        return self._name

    async def execute(self, ctx):
        now = datetime.now(timezone.utc)
        if self.should_fail:
            return StageResult(
                stage_name=self.name,
                status="failed",
                started_at=now,
                ended_at=now,
                duration_ms=10,
                findings={},
                artifacts=[],
                error="Mock failure",
            )
        return StageResult(
            stage_name=self.name,
            status="ok",
            started_at=now,
            ended_at=now,
            duration_ms=10,
            findings={"test": "data"},
            artifacts=[],
            error=None,
        )


@pytest.mark.asyncio
async def test_run_pipeline_success(mocker, tmp_path):
    """Test successful pipeline execution."""
    from malscan_worker.pipeline import run_pipeline

    # Create temp file
    test_file = tmp_path / "test.txt"
    test_file.write_bytes(b"test content")

    # Mock all external dependencies
    mocker.patch(
        "malscan_worker.pipeline.download_file",
        new_callable=AsyncMock,
        return_value=test_file,
    )
    mocker.patch("malscan_worker.pipeline.update_job_status", new_callable=AsyncMock)
    mocker.patch("malscan_worker.pipeline.update_job_stage", new_callable=AsyncMock)
    mocker.patch("malscan_worker.pipeline.update_job_result", new_callable=AsyncMock)
    mocker.patch("malscan_worker.pipeline.stage_latency")

    # Replace STAGES with mock stages
    mock_stages = [MockStage("stage1"), MockStage("stage2")]
    mocker.patch("malscan_worker.pipeline.STAGES", mock_stages)

    job_data = {
        "job_id": "test-job-id",
        "file_id": "test-file-id",
        "storage_key": "test-key",
        "sha256": "test-sha256",
        "original_filename": "test.txt",
    }

    result = await run_pipeline(job_data)

    assert result["job_id"] == "test-job-id"
    assert len(result["stages"]) == 2


@pytest.mark.asyncio
async def test_run_pipeline_stage_failure(mocker, tmp_path):
    """Test pipeline handling of stage failure."""
    from malscan_worker.pipeline import run_pipeline

    # Create temp file
    test_file = tmp_path / "test.txt"
    test_file.write_bytes(b"test content")

    # Mock dependencies
    mocker.patch(
        "malscan_worker.pipeline.download_file",
        new_callable=AsyncMock,
        return_value=test_file,
    )
    mocker.patch("malscan_worker.pipeline.update_job_status", new_callable=AsyncMock)
    mocker.patch("malscan_worker.pipeline.update_job_stage", new_callable=AsyncMock)
    mocker.patch("malscan_worker.pipeline.update_job_result", new_callable=AsyncMock)
    mocker.patch("malscan_worker.pipeline.stage_latency")

    # Mock STAGES (second stage fails)
    mock_stages = [MockStage("stage1"), MockStage("stage2", should_fail=True)]
    mocker.patch("malscan_worker.pipeline.STAGES", mock_stages)

    job_data = {
        "job_id": "test-job-id",
        "file_id": "test-file-id",
        "storage_key": "test-key",
        "sha256": "test-sha256",
        "original_filename": "test.txt",
    }

    # Pipeline should raise RuntimeError on failure
    with pytest.raises(RuntimeError, match="Stage stage2 failed"):
        await run_pipeline(job_data)
