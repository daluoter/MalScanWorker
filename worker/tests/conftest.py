"""Pytest configuration and fixtures for worker tests."""

import uuid
from typing import Generator
from unittest.mock import AsyncMock, MagicMock

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from malscan_worker.stages.base import StageContext


@pytest.fixture
def mock_db_session() -> Generator[AsyncMock, None, None]:
    """Provide a mock database session."""
    session = AsyncMock(spec=AsyncSession)
    yield session


@pytest.fixture
def mock_storage(mocker) -> Generator[MagicMock, None, None]:
    """Mock storage operations."""
    mock_down = mocker.patch("malscan_worker.pipeline.download_file", new_callable=AsyncMock)
    mock_down.return_value = None
    yield mock_down


@pytest.fixture
def temp_test_file(tmp_path):
    """Create a temporary test file with content."""
    file_path = tmp_path / "test_file.txt"
    # URL must be properly formatted for the regex to match
    file_path.write_bytes(b"test file content including https://malicious.com/path and IP 1.2.3.4 here")
    return file_path


@pytest.fixture
def stage_context(temp_test_file) -> StageContext:
    """Create a StageContext with a temporary file."""
    return StageContext(
        job_id=str(uuid.uuid4()),
        file_id=str(uuid.uuid4()),
        storage_key="test_sha256",
        sha256="test_sha256",
        original_filename="test_file.txt",
        file_path=temp_test_file,
    )
