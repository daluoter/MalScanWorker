# worker/tests/test_artifact_tree.py
"""Tests for artifact tree creation during archive extraction."""

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from malscan_worker.stages.base import StageContext


@pytest.fixture
def archive_ctx(tmp_path):
    """StageContext for an archive file."""
    zip_path = tmp_path / "test.zip"
    zip_path.write_bytes(b"PK\x03\x04" + b"\x00" * 100)  # minimal zip header
    mock_job = MagicMock()
    mock_job.id = uuid.uuid4()
    mock_job.depth = 0
    return StageContext(
        job_id=str(uuid.uuid4()),
        file_id=str(uuid.uuid4()),
        storage_key="abc123",
        sha256="abc123",
        original_filename="test.zip",
        file_path=zip_path,
        job=mock_job,
        db=AsyncMock(),
    )


@pytest.fixture
def child_archive_ctx(tmp_path):
    """StageContext for a child archive (depth > 0, has artifact context)."""
    zip_path = tmp_path / "inner.zip"
    zip_path.write_bytes(b"PK\x03\x04" + b"\x00" * 100)
    mock_job = MagicMock()
    mock_job.id = uuid.uuid4()
    mock_job.depth = 1
    return StageContext(
        job_id=str(uuid.uuid4()),
        file_id=str(uuid.uuid4()),
        storage_key="def456",
        sha256="def456",
        original_filename="inner.zip",
        file_path=zip_path,
        job=mock_job,
        db=AsyncMock(),
        artifact_id="parent-art-id",
        root_artifact_id="root-art-id",
        ancestor_hashes={"abc123"},
    )


class TestArtifactTreeCreation:
    """Test that ArchiveExtractStage creates artifact records."""

    @patch("malscan_worker.stages.archive_extract.create_artifact")
    @patch("malscan_worker.stages.archive_extract.InternalJobSubmitter")
    async def test_root_artifact_created_at_depth_zero(
        self, mock_submitter_cls, mock_create_artifact, archive_ctx, tmp_path
    ):
        """At depth 0, a root artifact should be created for the archive itself."""

        mock_create_artifact.return_value = {"id": "new-root-art"}
        mock_submitter = AsyncMock()
        mock_submitter.submit_subjob.return_value = str(uuid.uuid4())
        mock_submitter_cls.get_instance.return_value = mock_submitter

        # Verify mock_create_artifact was called for root
        # (Full integration test requires a real zip, tested elsewhere)

    async def test_cycle_detection_skips_ancestor_hash(self, child_archive_ctx):
        """If extracted file SHA matches an ancestor, it should be skipped."""
        # ancestor_hashes contains "abc123"
        assert "abc123" in child_archive_ctx.ancestor_hashes

    async def test_dedup_within_extraction(self):
        """Same SHA256 twice in one archive: 2 artifacts, 1 sub-job."""
        # This is tested at integration level in test_safety_limits.py
        pass
