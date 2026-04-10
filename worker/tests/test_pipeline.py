"""Unit tests for the analysis pipeline."""

import uuid
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
    update_job_stage = mocker.patch(
        "malscan_worker.pipeline.update_job_stage", new_callable=AsyncMock
    )
    mocker.patch("malscan_worker.pipeline.update_job_result", new_callable=AsyncMock)
    mocker.patch(
        "malscan_worker.pipeline.get_job_for_context",
        new_callable=AsyncMock,
        return_value=None,
    )
    mocker.patch("malscan_worker.pipeline.stage_latency")

    # Replace STAGES with mock stages
    mock_stages = [MockStage("stage1"), MockStage("stage2")]
    mocker.patch("malscan_worker.pipeline.PARALLEL_STAGES", mock_stages)
    mocker.patch("malscan_worker.pipeline.FORMAT_ANALYSIS_STAGE", MockStage("format-analysis"))
    mocker.patch("malscan_worker.pipeline.SEQUENTIAL_STAGES", [])

    job_id = str(uuid.uuid4())
    file_id = str(uuid.uuid4())
    job_data = {
        "job_id": job_id,
        "file_id": file_id,
        "storage_key": "test-key",
        "sha256": "test-sha256",
        "original_filename": "test.txt",
    }

    result = await run_pipeline(job_data)

    assert result["job_id"] == job_id
    assert len(result["stages"]) == 3
    assert [stage["stage_name"] for stage in result["stages"]] == [
        "stage1",
        "stage2",
        "format-analysis",
    ]

    assert update_job_stage.await_args_list[1].args == (job_id, "recursive_analysis", 3)


@pytest.mark.asyncio
async def test_run_pipeline_stage_failure(mocker, tmp_path):
    """Test pipeline continues and records failed stage."""
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
    mocker.patch(
        "malscan_worker.pipeline.get_job_for_context",
        new_callable=AsyncMock,
        return_value=None,
    )
    mocker.patch("malscan_worker.pipeline.stage_latency")

    # Mock STAGES (second stage fails)
    mock_stages = [MockStage("stage1"), MockStage("stage2", should_fail=True)]
    mocker.patch("malscan_worker.pipeline.PARALLEL_STAGES", mock_stages)
    mocker.patch("malscan_worker.pipeline.FORMAT_ANALYSIS_STAGE", MockStage("format-analysis"))
    mocker.patch("malscan_worker.pipeline.SEQUENTIAL_STAGES", [])

    job_id = str(uuid.uuid4())
    file_id = str(uuid.uuid4())
    job_data = {
        "job_id": job_id,
        "file_id": file_id,
        "storage_key": "test-key",
        "sha256": "test-sha256",
        "original_filename": "test.txt",
    }

    result = await run_pipeline(job_data)

    assert result["job_id"] == job_id
    assert any(
        stage["stage_name"] == "stage2" and stage["status"] == "failed"
        for stage in result["stages"]
    )


def test_build_analysis_result_applies_format_scoring_and_reporting():
    from malscan_worker.pipeline import _build_analysis_result

    now = datetime.now(timezone.utc)
    ctx = type(
        "Ctx",
        (),
        {"sha256": "abc123", "original_filename": "sample.bin", "artifact_id": "artifact-1"},
    )()
    results = [
        StageResult(
            stage_name="file-type",
            status="ok",
            started_at=now,
            ended_at=now,
            duration_ms=1,
            findings={"mime_type": "application/octet-stream", "file_size": 10},
            artifacts=[],
        ),
        StageResult(
            stage_name="clamav",
            status="ok",
            started_at=now,
            ended_at=now,
            duration_ms=1,
            findings={"infected": False, "threat_name": None},
            artifacts=[],
        ),
        StageResult(
            stage_name="yara",
            status="ok",
            started_at=now,
            ended_at=now,
            duration_ms=1,
            findings={"matches": []},
            artifacts=[],
        ),
        StageResult(
            stage_name="format-analysis",
            status="ok",
            started_at=now,
            ended_at=now,
            duration_ms=1,
            findings={
                "analyzer": "pe",
                "format_type": "PE",
                "risk_score": 37,
                "risk_factors": ["packed"],
                "indicators": [{"type": "suspicious_import", "severity": "high"}],
                "heuristics": [
                    {
                        "key": "script.encoded_command_execution",
                        "category": "script_token",
                        "scope": "script",
                        "role": "gate_signal",
                        "severity": "high",
                        "confidence": 0.9,
                        "summary": "Encoded payload and execution primitives appear together",
                        "evidence": {},
                        "tags": (),
                    }
                ],
                "features": {"entrypoint": 4096},
            },
            artifacts=[],
        ),
        StageResult(
            stage_name="archive-extract",
            status="ok",
            started_at=now,
            ended_at=now,
            duration_ms=1,
            findings={
                "archive_type": "zip",
                "heuristics": [
                    {
                        "key": "archive.executable_concentration",
                        "category": "archive",
                        "scope": "archive",
                        "role": "corroborating",
                        "severity": "medium",
                        "confidence": 0.8,
                        "summary": "Archive contains multiple executable-like members",
                        "evidence": {"executable_members": 2},
                        "tags": ("archive", "embedded-executable"),
                    }
                ],
            },
            artifacts=[],
        ),
    ]

    report = _build_analysis_result("job-1", "file-1", ctx, results, 123)

    assert report["verdict"] == "suspicious"
    assert report["risk_level"] == "high"
    assert report["score"] == 84
    assert report["risk"]["policy_version"] == "msrs-v1"
    assert report["risk"]["breakdown"]["local_score"] >= 0

    format_report = report["results"]["format_analysis"]
    assert format_report["analyzer"] == "pe"
    assert format_report["format_type"] == "PE"
    assert format_report["risk_score"] == 37
    assert format_report["risk_factors"] == ["packed"]
    assert format_report["indicators"][0]["severity"] == "high"
    assert format_report["heuristics"][0]["key"] == "script.encoded_command_execution"
    assert format_report["features"] == {"entrypoint": 4096}

    archive_report = report["results"]["archive_extract"]
    assert archive_report["archive_type"] == "zip"
    assert archive_report["heuristics"][0]["key"] == "archive.executable_concentration"
