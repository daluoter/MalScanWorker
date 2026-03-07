"""Pytest configuration and fixtures for backend tests."""

import os
import sys
from typing import AsyncGenerator, Generator
from unittest.mock import AsyncMock, MagicMock

# Set required environment variables BEFORE any other imports
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://postgres:test@localhost:5432/malscan")  # noqa: E402
os.environ.setdefault("MINIO_ENDPOINT", "localhost:9000")  # noqa: E402
os.environ.setdefault("MINIO_ACCESS_KEY", "minioadmin")  # noqa: E402
os.environ.setdefault("MINIO_SECRET_KEY", "minioadmin")  # noqa: E402
os.environ.setdefault("RABBITMQ_URL", "amqp://guest:guest@localhost:5672/")  # noqa: E402

# Clear any cached settings to force reload with new env vars
if "malscan" in sys.modules:  # noqa: E402
    for mod in list(sys.modules.keys()):  # noqa: E402
        if mod.startswith("malscan"):  # noqa: E402
            del sys.modules[mod]  # noqa: E402

import pytest  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from httpx import ASGITransport, AsyncClient  # noqa: E402
from malscan.api.routes import router  # noqa: E402
from malscan.db import get_db  # noqa: E402
from sqlalchemy.ext.asyncio import AsyncSession  # noqa: E402


# Create a test app without startup events to avoid DB connection
def create_test_app() -> FastAPI:
    """Create a minimal FastAPI app for testing without startup events."""
    test_app = FastAPI()
    test_app.include_router(router, prefix="/api/v1")
    return test_app


test_app = create_test_app()


@pytest.fixture
def mock_db_session() -> Generator[AsyncMock, None, None]:
    """Provide a mock database session."""
    session = AsyncMock(spec=AsyncSession)
    yield session


@pytest.fixture
def mock_minio(mocker) -> Generator[MagicMock, None, None]:
    """Mock MinIO storage operations."""
    mock_upload = mocker.patch("malscan.api.routes.upload_to_minio", new_callable=AsyncMock)
    mock_upload.return_value = None
    yield mock_upload


@pytest.fixture
def mock_rabbitmq(mocker) -> Generator[MagicMock, None, None]:
    """Mock RabbitMQ publish operations."""
    mock_publish = mocker.patch("malscan.api.routes.publish_job", new_callable=AsyncMock)
    mock_publish.return_value = None
    yield mock_publish


@pytest.fixture
def client(mock_db_session) -> Generator[TestClient, None, None]:
    """Provide a TestClient with overridden dependencies."""
    test_app.dependency_overrides[get_db] = lambda: mock_db_session
    with TestClient(test_app) as c:
        yield c
    test_app.dependency_overrides.clear()


@pytest.fixture
async def async_client(mock_db_session) -> AsyncGenerator[AsyncClient, None]:
    """Provide an asynchronous httpx client with overridden dependencies."""
    test_app.dependency_overrides[get_db] = lambda: mock_db_session
    transport = ASGITransport(app=test_app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    test_app.dependency_overrides.clear()
