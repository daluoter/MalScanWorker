"""Unit tests for database models."""

import uuid

from malscan.models import File, Job, JobStatus


def test_file_model_creation():
    """Test creating a File model instance."""
    file_id = uuid.uuid4()
    file = File(
        id=file_id,
        sha256="test_sha256",
        size=1024,
        filename="test.exe",
        content_type="application/x-msdownload",
    )

    assert file.id == file_id
    assert file.sha256 == "test_sha256"
    assert file.size == 1024
    assert file.filename == "test.exe"
    assert file.content_type == "application/x-msdownload"


def test_job_model_creation():
    """Test creating a Job model instance."""
    job_id = uuid.uuid4()
    file_id = uuid.uuid4()
    job = Job(
        id=job_id,
        file_id=file_id,
        status=JobStatus.QUEUED.value,
        stages_total=5,
        stages_done=0,  # Explicitly set default
    )

    assert job.id == job_id
    assert job.file_id == file_id
    assert job.status == "queued"
    assert job.stages_total == 5
    assert job.stages_done == 0
    assert job.current_stage is None
    assert job.error_message is None
    assert job.result is None


def test_job_status_enum():
    """Test JobStatus enum values."""
    assert JobStatus.QUEUED.value == "queued"
    assert JobStatus.SCANNING.value == "scanning"
    assert JobStatus.DONE.value == "done"
    assert JobStatus.FAILED.value == "failed"
