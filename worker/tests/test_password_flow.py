"""Tests for worker password-control flow across pipeline and consumer."""

from unittest.mock import AsyncMock

import pytest
from malscan_worker.exceptions import ArchivePasswordRequiredError, ArchiveWrongPasswordError
from malscan_worker.stages.base import StageContext


class _StageRaisesPasswordRequired:
    name = "archive-extract"

    async def execute(self, _ctx):
        raise ArchivePasswordRequiredError("zip")


class _FakeMessage:
    def __init__(self, body: dict, headers: dict | None = None):
        import json

        self.body = json.dumps(body).encode()
        self.headers = headers or {}
        self.ack = AsyncMock()
        self.reject = AsyncMock()


@pytest.mark.asyncio
async def test_run_stage_reraises_password_exception(tmp_path):
    from malscan_worker.pipeline import _run_stage

    stage = _StageRaisesPasswordRequired()
    ctx = StageContext(
        job_id="job-1",
        file_id="file-1",
        storage_key="key",
        sha256="sha",
        original_filename="archive.zip",
        file_path=tmp_path / "archive.zip",
    )

    with pytest.raises(ArchivePasswordRequiredError):
        await _run_stage(stage, ctx)


@pytest.mark.asyncio
async def test_consumer_password_required_updates_status_and_ack(mocker):
    from malscan_worker import consumer

    message = _FakeMessage(
        {
            "job_id": "11111111-1111-1111-1111-111111111111",
            "file_id": "22222222-2222-2222-2222-222222222222",
        }
    )

    mocker.patch(
        "malscan_worker.consumer.run_pipeline",
        new_callable=AsyncMock,
        side_effect=ArchivePasswordRequiredError("zip"),
    )
    update_status = mocker.patch(
        "malscan_worker.consumer.update_job_status", new_callable=AsyncMock
    )

    await consumer.process_message(message)

    assert update_status.await_count == 2
    update_status.assert_any_await("11111111-1111-1111-1111-111111111111", "scanning")
    update_status.assert_any_await(
        "11111111-1111-1111-1111-111111111111",
        "password_required",
        error_message="Archive is password-protected. Please provide a password to continue.",
    )
    message.ack.assert_awaited_once()
    message.reject.assert_not_awaited()


@pytest.mark.asyncio
async def test_consumer_wrong_password_exhausted_stores_report_sets_done_and_ack(mocker):
    from malscan_worker import consumer

    message = _FakeMessage(
        {
            "job_id": "33333333-3333-3333-3333-333333333333",
            "file_id": "44444444-4444-4444-4444-444444444444",
            "sha256": "deadbeef",
            "original_filename": "secret.zip",
        }
    )

    mocker.patch(
        "malscan_worker.consumer.run_pipeline",
        new_callable=AsyncMock,
        side_effect=ArchiveWrongPasswordError("zip"),
    )
    mocker.patch(
        "malscan_worker.consumer.increment_password_attempts",
        new_callable=AsyncMock,
        return_value=3,
    )
    update_status = mocker.patch(
        "malscan_worker.consumer.update_job_status", new_callable=AsyncMock
    )
    update_result = mocker.patch(
        "malscan_worker.consumer.update_job_result", new_callable=AsyncMock
    )

    await consumer.process_message(message)

    update_result.assert_awaited_once()
    saved_result = update_result.await_args.args[1]
    assert (
        saved_result["results"]["archive_extract"]["reason"]
        == "Archive extraction failed after 3 incorrect password attempts"
    )
    assert saved_result["results"]["archive_extract"]["extraction_failed"] is True

    update_status.assert_any_await(
        "33333333-3333-3333-3333-333333333333",
        "done",
    )
    message.ack.assert_awaited_once()
    message.reject.assert_not_awaited()
