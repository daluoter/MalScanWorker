"""Tests for internal sub-job submission storage behavior."""

import json
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


@pytest.mark.asyncio
async def test_submit_subjob_updates_artifact_job_id_when_artifact_id_provided(
    monkeypatch,
):
    """Successful sub-job submission should attach the new job id to the artifact row."""

    existing_file = SimpleNamespace(id=uuid.uuid4(), sha256="b" * 64)
    artifact_id = str(uuid.uuid4())
    root_artifact_id = str(uuid.uuid4())
    root_job_id = str(uuid.uuid4())
    ancestor_hashes = {"ancestor-a", "ancestor-b"}
    captured_updates = []
    publish_mock = AsyncMock()

    class DummySession:
        def __init__(self, *args, **kwargs):
            self._adds = []

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def execute(self, stmt, *args, **kwargs):
            if kwargs:
                captured_updates.append({"stmt": stmt, "args": args, "kwargs": kwargs})
                return None
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
    submitter._storage_object_exists = AsyncMock(return_value=True)
    submitter._exchange = SimpleNamespace(publish=publish_mock)

    sub_job_id = await submitter.submit_subjob(
        file_path="/tmp/sub.bin",
        filename="sub.bin",
        content_type="application/octet-stream",
        sha256_hash="b" * 64,
        file_size=12,
        parent_job_id=str(uuid.uuid4()),
        parent_job_depth=0,
        artifact_id=artifact_id,
        root_artifact_id=root_artifact_id,
        root_job_id=root_job_id,
        ancestor_hashes=ancestor_hashes,
    )

    assert sub_job_id is not None
    assert captured_updates
    update_call = captured_updates[0]
    update_params = update_call["args"][0]
    assert update_params["artifact_id"] == uuid.UUID(artifact_id)
    assert update_params["job_id"] == uuid.UUID(sub_job_id)

    publish_mock.assert_awaited_once()
    published_message = publish_mock.await_args.args[0]
    published_payload = json.loads(published_message.body.decode())
    assert published_payload["artifact_id"] == artifact_id
    assert published_payload["root_artifact_id"] == root_artifact_id
    assert published_payload["root_job_id"] == root_job_id
    assert set(published_payload["ancestor_hashes"]) == ancestor_hashes


@pytest.mark.asyncio
async def test_submit_subjob_continues_when_artifact_job_link_update_fails(monkeypatch):
    """Artifact linkage failures should be logged and not block MQ publish."""

    existing_file = SimpleNamespace(id=uuid.uuid4(), sha256="c" * 64)
    artifact_id = str(uuid.uuid4())

    class DummySession:
        def __init__(self, *args, **kwargs):
            self._adds = []

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def execute(self, stmt, *args, **kwargs):
            if kwargs:
                raise RuntimeError("artifact link failed")
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

    publish_mock = AsyncMock()
    monkeypatch.setattr("malscan_worker.utils.submission.upload_to_minio", AsyncMock())

    InternalJobSubmitter._instance = None
    submitter = InternalJobSubmitter()
    submitter._ensure_connection = AsyncMock()
    submitter._storage_object_exists = AsyncMock(return_value=True)
    submitter._exchange = SimpleNamespace(publish=publish_mock)

    sub_job_id = await submitter.submit_subjob(
        file_path="/tmp/sub.bin",
        filename="sub.bin",
        content_type="application/octet-stream",
        sha256_hash="c" * 64,
        file_size=12,
        parent_job_id=str(uuid.uuid4()),
        parent_job_depth=0,
        artifact_id=artifact_id,
    )

    assert sub_job_id is not None
    publish_mock.assert_awaited_once()
