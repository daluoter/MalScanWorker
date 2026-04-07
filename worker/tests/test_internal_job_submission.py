"""Tests for internal sub-job submission storage behavior."""

import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from malscan_worker.utils.submission import InternalJobSubmitter


class _DummyScalarResult:
    def __init__(self, value):
        self._value = value

    def scalar_one_or_none(self):
        return self._value


@pytest.mark.asyncio
async def test_submit_subjob_reuploads_when_dedup_file_missing_in_storage(monkeypatch):
    """If dedup DB row exists but object is gone, submitter must re-upload."""

    existing_file = SimpleNamespace(id=uuid.uuid4(), sha256="a" * 64)

    class DummySession:
        def __init__(self, *args, **kwargs):
            self._adds = []

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def execute(self, stmt):
            return _DummyScalarResult(existing_file)

        def add(self, obj):
            self._adds.append(obj)

        async def flush(self):
            for obj in self._adds:
                if getattr(obj, "id", None) is None:
                    obj.id = uuid.uuid4()

        async def commit(self):
            return None

    monkeypatch.setattr("malscan_worker.utils.submission.AsyncSession", DummySession)

    upload_mock = AsyncMock()
    monkeypatch.setattr("malscan_worker.utils.submission.upload_to_minio", upload_mock)

    InternalJobSubmitter._instance = None
    submitter = InternalJobSubmitter()
    submitter._ensure_connection = AsyncMock()
    submitter._storage_object_exists = AsyncMock(return_value=False)
    submitter._exchange = SimpleNamespace(publish=AsyncMock())

    sub_job_id = await submitter.submit_subjob(
        file_path="/tmp/sub.bin",
        filename="sub.bin",
        content_type="application/octet-stream",
        sha256_hash="a" * 64,
        file_size=12,
        parent_job_id=str(uuid.uuid4()),
        parent_job_depth=0,
    )

    assert sub_job_id is not None
    upload_mock.assert_awaited_once_with("/tmp/sub.bin", "a" * 64, "application/octet-stream")
