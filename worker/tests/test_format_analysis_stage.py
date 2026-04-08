"""Tests for format analysis stage dispatch and result shaping."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from malscan_worker.analyzers.base import AnalyzerResult
from malscan_worker.stages.base import StageContext, StageResult
from malscan_worker.stages.format_analysis import FormatAnalysisStage


class _FakeRegistry:
    def __init__(self, analyzer: Any) -> None:
        self._analyzer = analyzer

    def detect(self, file_path: Path, mime: str) -> Any:
        del file_path, mime
        return self._analyzer


class _FakeSubmitter:
    def __init__(self) -> None:
        self.calls = 0

    async def submit_subjob(self, **kwargs: Any) -> str:
        del kwargs
        self.calls += 1
        return f"subjob-{self.calls}"


def _ctx(tmp_path: Path, *, with_file: bool = True, with_job: bool = False) -> StageContext:
    file_path: Path | None = tmp_path / "sample.bin"
    if with_file:
        assert file_path is not None
        file_path.write_bytes(b"MZ test payload")
    else:
        file_path = None

    previous = [
        StageResult(
            stage_name="file-type",
            status="ok",
            started_at=datetime.now(timezone.utc),
            ended_at=datetime.now(timezone.utc),
            duration_ms=1,
            findings={"mime_type": "application/x-dosexec"},
            artifacts=[],
        )
    ]

    ctx = StageContext(
        job_id=str(uuid.uuid4()),
        file_id=str(uuid.uuid4()),
        storage_key="key",
        sha256="a" * 64,
        original_filename="sample.bin",
        file_path=file_path,
        previous_results=previous,
    )

    if with_job:
        ctx.job = SimpleNamespace(id=uuid.uuid4(), depth=0)

    return ctx


@pytest.mark.asyncio
async def test_name_property() -> None:
    stage = FormatAnalysisStage()
    assert stage.name == "format-analysis"


@pytest.mark.asyncio
async def test_skip_when_missing_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "malscan_worker.stages.format_analysis.get_default_analyzer_registry",
        lambda: _FakeRegistry(None),
    )

    stage = FormatAnalysisStage()
    result = await stage.execute(_ctx(tmp_path, with_file=False))

    assert result.status == "skipped"
    assert "reason" in result.findings


@pytest.mark.asyncio
async def test_skip_when_no_analyzer_matched(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "malscan_worker.stages.format_analysis.get_default_analyzer_registry",
        lambda: _FakeRegistry(None),
    )

    stage = FormatAnalysisStage()
    result = await stage.execute(_ctx(tmp_path))

    assert result.status == "skipped"
    assert result.findings["reason"] == "No analyzer matched"


@pytest.mark.asyncio
async def test_dispatch_to_analyzer_and_returns_ok(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact_path = tmp_path / "child.bin"
    artifact_path.write_bytes(b"child payload")

    class _Analyzer:
        name = "pe"

        async def analyze(self, file_path: Path, ctx: StageContext) -> AnalyzerResult:
            del file_path, ctx
            return AnalyzerResult(
                analyzer_name="pe",
                format_type="PE",
                risk_score=42,
                risk_factors=["high_entropy_section"],
                indicators=[{"type": "test", "severity": "low", "detail": "ok"}],
                features={"entrypoint": 4096},
                extracted_strings=[str(i) for i in range(250)],
                extracted_artifacts=[
                    {"path": str(artifact_path), "filename": "child.bin", "size": 13}
                ],
                errors=[],
            )

    fake_submitter = _FakeSubmitter()

    async def _fake_get_submitter() -> _FakeSubmitter:
        return fake_submitter

    async def _fake_create_artifact(**kwargs: Any) -> dict[str, str]:
        del kwargs
        return {"id": str(uuid.uuid4())}

    monkeypatch.setattr(
        "malscan_worker.stages.format_analysis.get_default_analyzer_registry",
        lambda: _FakeRegistry(_Analyzer()),
    )
    monkeypatch.setattr(
        "malscan_worker.stages.format_analysis.InternalJobSubmitter.get_instance",
        _fake_get_submitter,
    )
    monkeypatch.setattr(
        "malscan_worker.stages.format_analysis.create_artifact",
        _fake_create_artifact,
    )

    stage = FormatAnalysisStage()
    result = await stage.execute(_ctx(tmp_path, with_job=True))

    assert result.status == "ok"
    assert result.findings["analyzer"] == "pe"
    assert result.findings["format_type"] == "PE"
    assert result.findings["sub_jobs_created"] == 1
    assert result.findings["extracted_artifacts_count"] == 1
    assert len(result.findings["extracted_strings"]) == 200


@pytest.mark.asyncio
async def test_findings_include_expected_keys(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _Analyzer:
        name = "script"

        async def analyze(self, file_path: Path, ctx: StageContext) -> AnalyzerResult:
            del file_path, ctx
            return AnalyzerResult(
                analyzer_name="script",
                format_type="SCRIPT",
                risk_score=0,
                risk_factors=[],
                indicators=[],
                features={"script_type": "batch"},
                extracted_strings=["one"],
                extracted_artifacts=[],
                errors=[],
            )

    monkeypatch.setattr(
        "malscan_worker.stages.format_analysis.get_default_analyzer_registry",
        lambda: _FakeRegistry(_Analyzer()),
    )

    stage = FormatAnalysisStage()
    result = await stage.execute(_ctx(tmp_path))

    expected = {
        "analyzer",
        "format_type",
        "risk_score",
        "risk_factors",
        "indicators",
        "features",
        "extracted_strings",
        "extracted_artifacts_count",
        "sub_jobs_created",
        "errors",
    }
    assert result.status == "ok"
    assert expected.issubset(result.findings.keys())


@pytest.mark.asyncio
async def test_analyzer_exception_returns_failed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _Analyzer:
        name = "pe"

        async def analyze(self, file_path: Path, ctx: StageContext) -> AnalyzerResult:
            del file_path, ctx
            raise RuntimeError("boom")

    monkeypatch.setattr(
        "malscan_worker.stages.format_analysis.get_default_analyzer_registry",
        lambda: _FakeRegistry(_Analyzer()),
    )

    stage = FormatAnalysisStage()
    result = await stage.execute(_ctx(tmp_path))

    assert result.status == "failed"
    assert result.error is not None
    assert "boom" in result.error
