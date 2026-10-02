"""Regression tests for IOC-derived recursive submissions."""

from __future__ import annotations

import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, create_autospec

import pytest
from malscan_worker.stages.base import StageContext
from malscan_worker.stages.ioc_extract import IocExtractStage
from malscan_worker.utils.submission import InternalJobSubmitter


@pytest.mark.parametrize("caller_db_session", [None, object()], ids=["no-db", "with-db"])
@pytest.mark.asyncio
async def test_ioc_url_subjob_uses_current_submitter_signature(
    caller_db_session: object | None,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    embedded_url = "https://malicious.example/payload.bin"
    file_path = tmp_path / "sample.txt"
    file_path.write_text(f"Embedded content references {embedded_url}")

    parent_job_id = uuid.uuid4()
    root_artifact_id = str(uuid.uuid4())
    root_job_id = str(uuid.uuid4())
    submitter = create_autospec(InternalJobSubmitter, instance=True, spec_set=True)
    submitter.submit_subjob.return_value = str(uuid.uuid4())
    get_instance = AsyncMock(return_value=submitter)
    monkeypatch.setattr(
        "malscan_worker.stages.ioc_extract.InternalJobSubmitter.get_instance",
        get_instance,
    )
    monkeypatch.setattr(
        "malscan_worker.stages.ioc_extract.get_settings",
        lambda: SimpleNamespace(max_job_depth=3),
    )

    context = StageContext(
        job_id=str(parent_job_id),
        file_id=str(uuid.uuid4()),
        storage_key="sample-key",
        sha256="parent-sha256",
        original_filename=file_path.name,
        file_path=file_path,
        job=SimpleNamespace(id=parent_job_id, depth=1),
        db=caller_db_session,
        root_artifact_id=root_artifact_id,
        root_job_id=root_job_id,
        ancestor_hashes={"ancestor-sha256"},
    )

    result = await IocExtractStage().execute(context)

    assert result.status == "ok"
    assert embedded_url in result.findings["urls"]
    assert result.findings["sub_jobs_created"] == 1
    get_instance.assert_awaited_once_with()
    submitter.submit_subjob.assert_awaited_once()

    submitted = submitter.submit_subjob.await_args
    assert submitted is not None
    assert submitted.kwargs["filename"].endswith(".url")
    assert submitted.kwargs["content_type"] == "application/internet-shortcut"
    assert submitted.kwargs["parent_job_id"] == str(parent_job_id)
    assert submitted.kwargs["parent_job_depth"] == 1
    assert submitted.kwargs["root_artifact_id"] == root_artifact_id
    assert submitted.kwargs["root_job_id"] == root_job_id
    assert submitted.kwargs["ancestor_hashes"] == {"ancestor-sha256", "parent-sha256"}
    assert "db" not in submitted.kwargs
    assert "parent_job" not in submitted.kwargs
    assert not Path(submitted.kwargs["file_path"]).exists()
