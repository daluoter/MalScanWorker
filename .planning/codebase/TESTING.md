# Testing Patterns

**Analysis Date:** 2024-12-19

## Test Framework

### Python Backend & Worker

**Test Runner:**
- **pytest** 7.4.0 with asyncio support
- Config: Default pytest discovery (finds `test_*.py` and `*_test.py` files)
- Async support: **pytest-asyncio** 0.21.0

**Assertion Library:**
- Built-in `assert` statements
- No external assertion library

**Mocking Framework:**
- **pytest-mock** 3.12.0 (provides `mocker` fixture)
- Also uses standard library `unittest.mock` directly

**Coverage:**
- **pytest-cov** 4.1.0
- `.coverage` directory present in both `backend/` and `worker/`

**Run Commands:**
```bash
cd backend/
pytest                          # Run all tests
pytest -v                       # Verbose output
pytest tests/test_api.py        # Run specific test file
pytest tests/test_api.py::test_upload_file_success  # Run specific test
pytest --cov                    # With coverage
pytest --cov=src/malscan --cov-report=term-missing  # Coverage report

cd worker/
pytest                          # Same commands apply
pytest tests/test_stages.py -v
pytest --cov=src/malscan_worker
```

### Frontend

**No test framework configured** - `package.json` has no testing dependencies
- No Jest, Vitest, or other testing runner
- ESLint used for static analysis only

## Test File Organization

### Location

**Python - Backend:**
- Test files: `backend/tests/`
- Organization: Tests are co-located with test utilities but separate from source
- Files: `conftest.py`, `test_models.py`, `test_api.py`

**Python - Worker:**
- Test files: `worker/tests/`
- Organization: Similar to backend
- Files: `conftest.py`, `test_stages.py`, `test_pipeline.py`

### Naming Convention

**Pattern:** `test_*.py` prefix is mandatory
- `test_api.py` - API endpoint tests
- `test_models.py` - Model unit tests
- `test_stages.py` - Pipeline stage tests
- `test_pipeline.py` - Pipeline orchestration tests
- `conftest.py` - Shared fixtures

**Test functions:**
- Prefix: `test_` (required by pytest)
- Pattern: `test_<feature>_<scenario>`
- Examples:
  - `test_upload_file_success`
  - `test_upload_file_max_depth_exceeded`
  - `test_filetype_stage_file_not_found`
  - `test_get_job_status_success`

### File Structure

```
backend/
├── src/
│   └── malscan/
│       ├── models/
│       ├── api/
│       └── ...
└── tests/
    ├── __init__.py           # Empty
    ├── conftest.py           # Shared fixtures
    ├── test_models.py        # Model tests
    └── test_api.py           # API endpoint tests

worker/
├── src/
│   └── malscan_worker/
│       ├── stages/
│       ├── pipeline.py
│       └── ...
└── tests/
    ├── __init__.py           # Empty
    ├── conftest.py           # Shared fixtures
    ├── test_stages.py        # Stage unit tests
    └── test_pipeline.py      # Pipeline tests
```

## Test Structure

### Backend API Tests

**Location:** `backend/tests/test_api.py`

**Pattern:**
```python
def test_upload_file_success(
    client: TestClient,
    mock_db_session: AsyncMock,
    mock_minio,
    mock_rabbitmq
):
    """Test successful file upload."""
    # 1. Setup mocks
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    mock_db_session.execute.return_value = mock_result

    # 2. Configure async mock behavior
    async def mock_flush():
        pass

    mock_db_session.flush = AsyncMock(side_effect=mock_flush)
    mock_db_session.commit = AsyncMock()
    mock_db_session.add = MagicMock()

    # 3. Execute test
    files = {"file": ("test.txt", b"test content", "text/plain")}
    response = client.post("/api/v1/files", files=files)

    # 4. Assert
    assert response.status_code in [201, 500]  # Accept either for now
```

**Key Characteristics:**
- Use dependency injection via `TestClient` and fixture overrides
- Mock external dependencies (database, storage, queue)
- Test client returns synchronous responses even for async routes
- Multiple assertions checking status codes and response content

### Backend Model Tests

**Location:** `backend/tests/test_models.py`

**Pattern:**
```python
def test_job_model_creation():
    """Test creating a Job model instance."""
    job_id = uuid.uuid4()
    file_id = uuid.uuid4()
    job = Job(
        id=job_id,
        file_id=file_id,
        status=JobStatus.QUEUED.value,
        stages_total=5,
        stages_done=0,
    )

    assert job.id == job_id
    assert job.file_id == file_id
    assert job.status == "queued"
    assert job.stages_total == 5
    assert job.stages_done == 0
    assert job.current_stage is None
    assert job.error_message is None
    assert job.result is None
```

**Characteristics:**
- Simple synchronous tests (no async)
- Direct model instantiation
- Verify model fields and defaults
- Test enum values

### Worker Stage Tests

**Location:** `worker/tests/test_stages.py`

**Pattern:**
```python
@pytest.mark.asyncio
async def test_filetype_stage_success(stage_context: StageContext):
    """Test successful file type detection."""
    stage = FileTypeStage()
    result = await stage.execute(stage_context)

    assert result.status == "ok"
    assert result.stage_name == "file-type"
    assert "mime_type" in result.findings
    assert "magic_desc" in result.findings
    assert result.findings["file_size"] > 0
    assert result.error is None
```

**Key Patterns:**
- Use `@pytest.mark.asyncio` decorator for async tests
- Create stage instance and call `await stage.execute(ctx)`
- Verify `StageResult` object fields: `status`, `stage_name`, `findings`, `error`
- Test both success and failure paths

### Worker Pipeline Tests

**Location:** `worker/tests/test_pipeline.py`

**Pattern:**
```python
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
        return StageResult(...)


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
    mocker.patch("malscan_worker.pipeline.update_job_stage", new_callable=AsyncMock)
    mocker.patch("malscan_worker.pipeline.update_job_result", new_callable=AsyncMock)
    mocker.patch("malscan_worker.pipeline.stage_latency")

    # Replace STAGES with mock stages
    mock_stages = [MockStage("stage1"), MockStage("stage2")]
    mocker.patch("malscan_worker.pipeline.PARALLEL_STAGES", mock_stages)
    mocker.patch("malscan_worker.pipeline.SEQUENTIAL_STAGES", [])

    job_data = {
        "job_id": "test-job-id",
        "file_id": "test-file-id",
        "storage_key": "test-key",
        "sha256": "test-sha256",
        "original_filename": "test.txt",
    }

    result = await run_pipeline(job_data)
    ...
```

**Characteristics:**
- Create custom mock implementations (e.g., `MockStage`) for complex dependencies
- Use `mocker.patch()` to mock module-level functions
- Mock intermediate functions to isolate pipeline logic
- Create temporary files with `tmp_path` fixture
- Test with realistic job data structures

## Mocking

### Framework: pytest-mock

**Location:** `backend/tests/conftest.py` and `worker/tests/conftest.py`

**Usage Pattern:**
```python
@pytest.fixture
def mock_minio(mocker) -> Generator[MagicMock, None, None]:
    """Mock MinIO storage operations."""
    mock_upload = mocker.patch("malscan.api.routes.upload_to_minio", new_callable=AsyncMock)
    mock_upload.return_value = None
    yield mock_upload
```

**What to Mock:**
- External services: MinIO (S3 storage), RabbitMQ, database
- I/O operations: file operations, network calls
- External APIs: any third-party service calls

**What NOT to Mock:**
- Core business logic (models, validators)
- Internal application functions
- Stages in isolation (they should use real temp files)

### Mocking Database (AsyncSession)

**Pattern from `backend/tests/conftest.py`:**
```python
@pytest.fixture
def mock_db_session() -> Generator[AsyncMock, None, None]:
    """Provide a mock database session."""
    session = AsyncMock(spec=AsyncSession)
    yield session

@pytest.fixture
def client(mock_db_session) -> Generator[TestClient, None, None]:
    """Provide a TestClient with overridden dependencies."""
    test_app.dependency_overrides[get_db] = lambda: mock_db_session
    with TestClient(test_app) as c:
        yield c
    test_app.dependency_overrides.clear()
```

**Setup Mock Execute Results:**
```python
def test_get_job_status_success(client: TestClient, mock_db_session: AsyncMock):
    job_id = uuid.uuid4()

    # Create a proper mock job object (not AsyncMock)
    mock_job = MagicMock()
    mock_job.id = job_id
    mock_job.status = JobStatus.SCANNING.value
    mock_job.current_stage = "yara"
    mock_job.stages_done = 2
    mock_job.stages_total = 5

    # Configure mock db session
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = mock_job
    mock_db_session.execute.return_value = mock_result

    response = client.get(f"/api/v1/jobs/{job_id}")
    assert response.status_code == 200
```

**Key Pattern:** Mock the `execute().scalar_one_or_none()` chain, not async operations on session itself

### Mocking External Services

**Pattern from `backend/tests/conftest.py`:**
```python
@pytest.fixture
def mock_rabbitmq(mocker) -> Generator[MagicMock, None, None]:
    """Mock RabbitMQ publish operations."""
    mock_publish = mocker.patch("malscan.api.routes.publish_job", new_callable=AsyncMock)
    mock_publish.return_value = None
    yield mock_publish
```

**Key:** Use `new_callable=AsyncMock` for async functions, otherwise `MagicMock()`

## Fixtures

### Backend Fixtures

**Location:** `backend/tests/conftest.py`

**Available Fixtures:**
1. **`mock_db_session`** - Mocked AsyncSession for database operations
2. **`mock_minio`** - Mocked MinIO storage client
3. **`mock_rabbitmq`** - Mocked RabbitMQ publisher
4. **`client`** - FastAPI TestClient with dependency overrides
5. **`async_client`** - AsyncClient for async HTTP testing (less used)

**Environment Setup:**
```python
# conftest.py sets environment variables BEFORE imports
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://postgres:test@localhost:5432/malscan")
os.environ.setdefault("MINIO_ENDPOINT", "localhost:9000")
os.environ.setdefault("MINIO_ACCESS_KEY", "minioadmin")
os.environ.setdefault("MINIO_SECRET_KEY", "minioadmin")
os.environ.setdefault("RABBITMQ_URL", "amqp://guest:guest@localhost:5672/")
```

### Worker Fixtures

**Location:** `worker/tests/conftest.py`

**Available Fixtures:**
1. **`mock_db_session`** - Mocked AsyncSession
2. **`mock_storage`** - Mocked download_file function
3. **`temp_test_file`** - Real temporary file with test content
4. **`stage_context`** - StageContext instance with temp file

**Fixture Implementation:**
```python
@pytest.fixture
def temp_test_file(tmp_path):
    """Create a temporary test file with content."""
    file_path = tmp_path / "test_file.txt"
    file_path.write_bytes(
        b"test file content including https://malicious.com/path and IP 1.2.3.4 here"
    )
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
```

**Key:** Use `tmp_path` fixture (provided by pytest) for real temporary files

## Coverage

### Requirements

**Enforced via:** No CI/CD enforcement visible, but tools are configured
- Target coverage: Not explicitly set, but tooling installed

### View Coverage

```bash
# Backend
cd backend/
pytest --cov=src/malscan --cov-report=html
# Opens coverage in htmlcov/index.html

pytest --cov=src/malscan --cov-report=term-missing
# Shows which lines aren't covered

# Worker
cd worker/
pytest --cov=src/malscan_worker --cov-report=html
pytest --cov=src/malscan_worker --cov-report=term-missing
```

### Coverage Configuration

**File:** `pyproject.toml` (implicit defaults used)
- No explicit `[tool.coverage]` section in visible config
- Uses pytest-cov defaults

## Test Types

### Unit Tests

**Scope:** Individual functions/classes in isolation
**Examples:**
- Model creation and validation (`backend/tests/test_models.py`)
- Individual stage execution (`worker/tests/test_stages.py::test_filetype_stage_success`)
- Helper function behavior

**Approach:**
- Mock all external dependencies
- Test edge cases and error conditions
- Verify return values and state changes

**Example:**
```python
def test_job_status_enum():
    """Test JobStatus enum values."""
    assert JobStatus.QUEUED.value == "queued"
    assert JobStatus.SCANNING.value == "scanning"
    assert JobStatus.DONE.value == "done"
    assert JobStatus.FAILED.value == "failed"
```

### Integration Tests

**Scope:** Multiple components working together
**Examples:**
- API endpoint to database interaction (`backend/tests/test_api.py`)
- Pipeline with multiple stages (`worker/tests/test_pipeline.py`)

**Approach:**
- Mock external services (storage, queue, external APIs)
- Use real application code paths
- Test end-to-end workflows with mocked I/O

**Example:**
```python
@pytest.mark.asyncio
async def test_run_pipeline_success(mocker, tmp_path):
    """Test successful pipeline execution."""
    # Create real temp file
    test_file = tmp_path / "test.txt"
    test_file.write_bytes(b"test content")

    # Mock external calls but not internal pipeline
    mocker.patch("malscan_worker.pipeline.download_file", new_callable=AsyncMock, return_value=test_file)
    mocker.patch("malscan_worker.pipeline.update_job_status", new_callable=AsyncMock)

    # Replace STAGES with test stages
    mock_stages = [MockStage("stage1"), MockStage("stage2")]
    mocker.patch("malscan_worker.pipeline.PARALLEL_STAGES", mock_stages)

    # Execute full pipeline
    result = await run_pipeline(job_data)
    assert result.status == "ok"
```

### E2E Tests

**Status:** Not implemented
- No Selenium, Playwright, or Cypress configuration
- Frontend has no test framework

## Common Patterns

### Async Testing

**Decorator:** `@pytest.mark.asyncio` required for all async tests

```python
@pytest.mark.asyncio
async def test_filetype_stage_success(stage_context: StageContext):
    """Test successful file type detection."""
    stage = FileTypeStage()
    result = await stage.execute(stage_context)

    assert result.status == "ok"
    assert "mime_type" in result.findings
```

**With Mocking:**
```python
@pytest.mark.asyncio
async def test_run_pipeline_success(mocker, tmp_path):
    """Test successful pipeline execution."""
    # Create temp file
    test_file = tmp_path / "test.txt"
    test_file.write_bytes(b"test content")

    # Mock async functions with new_callable=AsyncMock
    mocker.patch(
        "malscan_worker.pipeline.download_file",
        new_callable=AsyncMock,
        return_value=test_file,
    )

    # Mock void async functions
    mocker.patch("malscan_worker.pipeline.update_job_status", new_callable=AsyncMock)

    result = await run_pipeline(job_data)
```

### Error Testing

**Pattern:** Verify error conditions are handled correctly

```python
def test_upload_file_max_depth_exceeded(client: TestClient, mock_db_session: AsyncMock):
    """Test upload fails if parent job exceeds max depth."""
    parent_job_id = uuid.uuid4()

    # Configure mock parent job query
    mock_parent_job = MagicMock()
    mock_parent_job.id = parent_job_id
    mock_parent_job.depth = 3  # Exceeds default limit

    mock_parent_result = MagicMock()
    mock_parent_result.scalar_one_or_none.return_value = mock_parent_job
    mock_db_session.execute.return_value = mock_parent_result

    files = {"file": ("test.txt", b"test content", "text/plain")}
    data = {"parent_job_id": str(parent_job_id)}

    response = client.post("/api/v1/files", files=files, data=data)

    assert response.status_code == 400
    assert "Maximum recursion depth" in response.json()["detail"]
```

**Pattern:**
1. Set up state that triggers error
2. Execute the operation
3. Assert error status code and message

### Missing File Testing

**Pattern:** Test graceful handling of missing resources

```python
@pytest.mark.asyncio
async def test_filetype_stage_file_not_found(stage_context: StageContext):
    """Test file type detection failure due to missing file."""
    # Point to non-existent file
    stage_context.file_path = Path("/non/existent/file")

    stage = FileTypeStage()
    result = await stage.execute(stage_context)

    assert result.status == "failed"
    assert result.error is not None
    assert "File not found" in result.error
```

### Using Temporary Files

**Pattern:** For stage testing requiring real files

```python
@pytest.mark.asyncio
async def test_archive_extract_zip(tmp_path):
    """Test ZIP archive extraction."""
    # Create a ZIP file
    zip_path = tmp_path / "test.zip"
    with zipfile.ZipFile(zip_path, 'w') as zf:
        zf.writestr("file1.txt", "content1")
        zf.writestr("file2.txt", "content2")

    # Create context with ZIP
    stage_context = StageContext(
        job_id=str(uuid.uuid4()),
        file_id=str(uuid.uuid4()),
        storage_key="test",
        sha256="test",
        original_filename="test.zip",
        file_path=zip_path,
    )

    # Test extraction
    stage = ArchiveExtractStage()
    result = await stage.execute(stage_context)

    assert result.status == "ok"
```

## Running Tests

### All Tests
```bash
cd backend/ && pytest
cd worker/ && pytest
```

### Specific Test File
```bash
cd backend/ && pytest tests/test_api.py
cd worker/ && pytest tests/test_stages.py
```

### Specific Test Function
```bash
cd backend/ && pytest tests/test_api.py::test_upload_file_success
cd worker/ && pytest tests/test_stages.py::test_filetype_stage_success
```

### With Verbose Output
```bash
pytest -v
pytest -vv  # Even more verbose
```

### With Coverage
```bash
pytest --cov=src/malscan --cov-report=html
# Then open htmlcov/index.html
```

### Show Print Statements
```bash
pytest -s
# Or with specific test
pytest tests/test_api.py::test_upload_file_success -s
```

## Test Execution Flow

### Backend Test Execution

1. **Conftest Setup:**
   - Set environment variables
   - Create mock database session
   - Create test app
   - Override dependency injection

2. **Test Execution:**
   - Configure mocks based on test needs
   - Execute API endpoint or function
   - Assert response/result

3. **Cleanup:**
   - Clear dependency overrides
   - Clean up temporary files

### Worker Test Execution

1. **Fixture Injection:**
   - `tmp_path` - pytest creates unique temp directory
   - `temp_test_file` - writes test content to temp file
   - `stage_context` - creates StageContext with temp file

2. **Test Execution:**
   - Create stage instance
   - Call `await stage.execute(stage_context)`
   - Assert result object properties

3. **Cleanup:**
   - Temp files automatically cleaned by pytest

## Known Test Patterns and Limitations

### Mock Complexity
- API tests have complex mock setup due to async patterns
- Some tests accept multiple status codes (`assert response.status_code in [201, 500]`)
- Indicates test may be incomplete or overly permissive

### No Frontend Tests
- No Vitest, Jest, or other JavaScript test runner configured
- Frontend uses only ESLint for static analysis

### Limited E2E Coverage
- Worker pipeline tests are integration-level, not E2E
- No actual RabbitMQ/MinIO/Database in tests
- All mocked for unit/integration testing

### Async Learning
- Use `@pytest.mark.asyncio` for async tests
- Use `new_callable=AsyncMock` for async mocks
- Regular `MagicMock()` for sync mocks and data objects

---

*Testing analysis: 2024-12-19*
