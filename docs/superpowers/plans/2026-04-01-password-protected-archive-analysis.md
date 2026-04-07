# Password-Protected Archive Analysis Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let encrypted archives pause analysis for password input, resume analysis after user submission, and produce a final `done` report with explicit extraction failure after 3 wrong passwords.

**Architecture:** Add a new `password_required` job state and `password_attempts` counter in backend persistence, propagate password-specific exceptions from worker archive stage through pipeline to consumer, and add a password submission API that republishes job messages with transient `archive_password`. Frontend `JobStatusPage` will render a password form for `password_required`, and `ReportPage` will explicitly show extraction failure when retries are exhausted.

**Tech Stack:** FastAPI + SQLAlchemy + Alembic (backend), aio-pika + asyncio worker pipeline (worker), React + TypeScript + Vite (frontend), pytest for Python tests.

---

## Scope Check

This is one integrated vertical feature (worker control flow + backend API + frontend interaction) with a single user outcome, so it should stay in one implementation plan.

## File Structure and Responsibilities

- `backend/alembic/versions/003_add_password_attempts_and_status_fields.py` - Adds `password_attempts` schema change.
- `backend/src/malscan/models/job.py` - Adds `PASSWORD_REQUIRED` enum value and `password_attempts` ORM column.
- `backend/src/malscan/schemas/requests.py` - Extends status literals and password request/response schemas.
- `backend/src/malscan/api/routes.py` - Adds `POST /jobs/{job_id}/password` and status payload fields.
- `backend/tests/test_models.py` - Verifies model defaults and enum values.
- `backend/tests/test_password_api.py` - Verifies password endpoint behavior.
- `worker/src/malscan_worker/exceptions.py` - Defines password control-flow exceptions.
- `worker/src/malscan_worker/stages/base.py` - Adds `archive_password` to `StageContext`.
- `worker/src/malscan_worker/stages/archive_extract.py` - Detects password-required/wrong-password and raises domain exceptions.
- `worker/src/malscan_worker/pipeline.py` - Rethrows password exceptions and passes password from queue payload.
- `worker/src/malscan_worker/db.py` - Adds atomic password attempt increment helper.
- `worker/src/malscan_worker/reporting.py` - Builds final extraction-failure report payload for exhausted attempts.
- `worker/src/malscan_worker/consumer.py` - Handles password-specific branches and writes terminal done report on exhaustion.
- `worker/tests/test_archive_password.py` - Stage-level password exception tests.
- `worker/tests/test_password_flow.py` - Pipeline and consumer password-flow tests.
- `frontend/src/api/client.ts` - Adds `submitArchivePassword` and structured error handling.
- `frontend/src/api/types.ts` - Defines request/response/job status fields for password flow.
- `frontend/src/components/PasswordForm.tsx` - User password entry UI with attempts feedback.
- `frontend/src/pages/JobStatusPage.tsx` - Renders password form during `password_required` and handles SSE retry loop.
- `frontend/src/pages/ReportPage.tsx` - Shows explicit archive extraction failure banner.

### Task 1: Backend Persistence Foundation (`password_required` + attempts)

**Files:**
- Create: `backend/alembic/versions/003_add_password_attempts_and_status_fields.py`
- Modify: `backend/src/malscan/models/job.py`
- Modify: `backend/src/malscan/schemas/requests.py`
- Test: `backend/tests/test_models.py`

- [ ] **Step 1: Write the failing test**

```python
# backend/tests/test_models.py
def test_job_model_creation():
    job_id = uuid.uuid4()
    file_id = uuid.uuid4()
    job = Job(
        id=job_id,
        file_id=file_id,
        status=JobStatus.QUEUED.value,
        stages_total=5,
        stages_done=0,
    )

    assert job.password_attempts == 0


def test_job_status_enum():
    assert JobStatus.QUEUED.value == "queued"
    assert JobStatus.SCANNING.value == "scanning"
    assert JobStatus.PASSWORD_REQUIRED.value == "password_required"
    assert JobStatus.DONE.value == "done"
    assert JobStatus.FAILED.value == "failed"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && poetry run pytest tests/test_models.py::test_job_model_creation tests/test_models.py::test_job_status_enum -v`
Expected: FAIL with missing `password_attempts` and `PASSWORD_REQUIRED`.

- [ ] **Step 3: Write minimal implementation**

```python
# backend/src/malscan/models/job.py
class JobStatus(str, Enum):
    QUEUED = "queued"
    SCANNING = "scanning"
    PASSWORD_REQUIRED = "password_required"
    DONE = "done"
    FAILED = "failed"


class Job(Base):
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    file_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("files.id"), nullable=False, index=True
    )
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default=JobStatus.QUEUED.value, index=True
    )
    current_stage: Mapped[str | None] = mapped_column(String(50), nullable=True)
    stages_done: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    stages_total: Mapped[int] = mapped_column(Integer, nullable=False, default=5)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    result: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    password_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
```

```python
# backend/src/malscan/schemas/requests.py
class JobStatusResponse(BaseModel):
    job_id: str
    parent_job_id: str | None = None
    depth: int = 0
    status: Literal["queued", "scanning", "done", "failed", "password_required"]
    progress: JobProgress
    updated_at: datetime
    error_message: str | None
    password_attempts: int = 0
    password_attempts_remaining: int = 3
    total_sub: int = 0
    completed_sub: int = 0
    malicious_sub: int = 0
```

```python
# backend/alembic/versions/003_add_password_attempts_and_status_fields.py
"""Add password attempts counter to jobs

Revision ID: 003_add_password_attempts_and_status_fields
Revises: 002_add_hierarchical_job_fields
Create Date: 2026-04-01
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "003_add_password_attempts_and_status_fields"
down_revision: Union[str, None] = "002_add_hierarchical_job_fields"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "jobs",
        sa.Column("password_attempts", sa.Integer(), nullable=False, server_default="0"),
    )


def downgrade() -> None:
    op.drop_column("jobs", "password_attempts")
```

- [ ] **Step 4: Run tests to verify it passes**

Run: `cd backend && poetry run pytest tests/test_models.py::test_job_model_creation tests/test_models.py::test_job_status_enum -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/alembic/versions/003_add_password_attempts_and_status_fields.py backend/src/malscan/models/job.py backend/src/malscan/schemas/requests.py backend/tests/test_models.py
git commit -m "feat(backend): add password_required status and password attempts field"
```

### Task 2: Worker Password Domain Exceptions and Stage Propagation

**Files:**
- Create: `worker/src/malscan_worker/exceptions.py`
- Modify: `worker/src/malscan_worker/stages/base.py`
- Modify: `worker/src/malscan_worker/stages/archive_extract.py`
- Test: `worker/tests/test_archive_password.py`

- [ ] **Step 1: Write the failing test**

```python
# worker/tests/test_archive_password.py
import pytest
from malscan_worker.exceptions import ArchivePasswordRequiredError, ArchiveWrongPasswordError
from malscan_worker.stages.archive_extract import ArchiveExtractStage
from malscan_worker.stages.base import StageContext


@pytest.mark.asyncio
async def test_archive_stage_reraises_password_required(tmp_path, mocker):
    archive = tmp_path / "enc.zip"
    archive.write_bytes(b"PK\x03\x04")

    stage = ArchiveExtractStage()
    ctx = StageContext(
        job_id="job-1",
        file_id="file-1",
        storage_key="sha",
        sha256="sha",
        original_filename="enc.zip",
        file_path=archive,
    )

    mocker.patch.object(stage, "_detect_format", return_value="zip")
    mocker.patch.object(
        stage,
        "_extract",
        side_effect=ArchivePasswordRequiredError(archive_type="zip"),
    )

    with pytest.raises(ArchivePasswordRequiredError):
        await stage.execute(ctx)


@pytest.mark.asyncio
async def test_archive_stage_reraises_wrong_password(tmp_path, mocker):
    archive = tmp_path / "enc.zip"
    archive.write_bytes(b"PK\x03\x04")

    stage = ArchiveExtractStage()
    ctx = StageContext(
        job_id="job-2",
        file_id="file-2",
        storage_key="sha",
        sha256="sha",
        original_filename="enc.zip",
        file_path=archive,
        archive_password="bad-pass",
    )

    mocker.patch.object(stage, "_detect_format", return_value="zip")
    mocker.patch.object(
        stage,
        "_extract",
        side_effect=ArchiveWrongPasswordError(archive_type="zip"),
    )

    with pytest.raises(ArchiveWrongPasswordError):
        await stage.execute(ctx)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd worker && poetry run pytest tests/test_archive_password.py -v`
Expected: FAIL because exception classes or stage rethrow behavior are not implemented.

- [ ] **Step 3: Write minimal implementation**

```python
# worker/src/malscan_worker/exceptions.py
class ArchivePasswordRequiredError(Exception):
    def __init__(self, archive_type: str):
        super().__init__(f"Password required for {archive_type} archive")
        self.archive_type = archive_type


class ArchiveWrongPasswordError(Exception):
    def __init__(self, archive_type: str):
        super().__init__(f"Wrong password for {archive_type} archive")
        self.archive_type = archive_type
```

```python
# worker/src/malscan_worker/stages/base.py
@dataclass
class StageContext:
    job_id: str
    file_id: str
    storage_key: str
    sha256: str
    original_filename: str
    file_path: Path | None
    archive_password: str | None = None
    previous_results: list["StageResult"] = field(default_factory=list)
    job: Job | None = field(default=None)
    db: AsyncSession | None = field(default=None)
```

```python
# worker/src/malscan_worker/stages/archive_extract.py (key parts)
from malscan_worker.exceptions import ArchivePasswordRequiredError, ArchiveWrongPasswordError


async def execute(self, ctx: StageContext) -> StageResult:
    started_at = datetime.now(timezone.utc)
    settings = get_settings()
    max_files = 15
    max_total_size = 200 * 1024 * 1024
    max_single_size = getattr(settings, "max_file_size", 100 * 1024 * 1024)
    max_expansion_ratio = 100
    archive_size = ctx.file_path.stat().st_size
    extract_dir = Path(f"/tmp/{ctx.job_id}/extracted")
    extract_dir.mkdir(parents=True, exist_ok=True)

    try:
        result = self._extract(
            archive_type=archive_type,
            file_path=ctx.file_path,
            extract_dir=extract_dir,
            archive_size=archive_size,
            max_files=max_files,
            max_total_size=max_total_size,
            max_single_size=max_single_size,
            max_expansion_ratio=max_expansion_ratio,
            archive_password=ctx.archive_password,
        )
    except (ArchivePasswordRequiredError, ArchiveWrongPasswordError):
        raise
    except Exception as e:
        log.error("archive_extraction_failed", job_id=ctx.job_id, error=str(e), exc_info=True)
        return self._build_result(started_at, "failed", {"error": f"Extraction failed: {e!s}"})
```

```python
# worker/src/malscan_worker/stages/archive_extract.py (ZIP password handling)
def _extract_zip(self, file_path: Path, extract_dir: Path, **limits: Any) -> dict[str, Any]:
    extracted_files: list[tuple[str, str, int]] = []
    total_extracted_size = 0
    base_dir_abs = os.path.abspath(str(extract_dir))
    archive_password = limits.get("archive_password")
    pwd = archive_password.encode("utf-8") if archive_password else None

    with zipfile.ZipFile(file_path, "r") as zf:
        encrypted = any((info.flag_bits & 0x1) != 0 for info in zf.infolist() if not info.is_dir())
        if encrypted and pwd is None:
            raise ArchivePasswordRequiredError("zip")

        for i, info in enumerate(zf.infolist()):
            if i >= limits["max_files"]:
                break
            if info.is_dir():
                continue

            target_path = os.path.join(base_dir_abs, info.filename)
            if not os.path.abspath(target_path).startswith(base_dir_abs):
                continue

            res = self._check_size_limits(info.file_size, total_extracted_size, limits, info.filename)
            if res:
                return res

            total_extracted_size += info.file_size
            try:
                extracted_path = zf.extract(info, path=base_dir_abs, pwd=pwd)
            except RuntimeError as exc:
                msg = str(exc).lower()
                if "password required" in msg:
                    raise ArchivePasswordRequiredError("zip") from exc
                if "bad password" in msg:
                    raise ArchiveWrongPasswordError("zip") from exc
                raise
            extracted_files.append((extracted_path, info.filename, info.file_size))

    return {"files": extracted_files}
```

- [ ] **Step 4: Run tests to verify it passes**

Run: `cd worker && poetry run pytest tests/test_archive_password.py tests/test_stages.py::test_archive_extract_zip -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add worker/src/malscan_worker/exceptions.py worker/src/malscan_worker/stages/base.py worker/src/malscan_worker/stages/archive_extract.py worker/tests/test_archive_password.py
git commit -m "feat(worker): add archive password exceptions and stage propagation"
```

### Task 3: Worker Pipeline + Consumer Password Control Flow

**Files:**
- Modify: `worker/src/malscan_worker/pipeline.py`
- Modify: `worker/src/malscan_worker/db.py`
- Modify: `worker/src/malscan_worker/consumer.py`
- Create: `worker/src/malscan_worker/reporting.py`
- Test: `worker/tests/test_password_flow.py`

- [ ] **Step 1: Write the failing test**

```python
# worker/tests/test_password_flow.py
import json
from unittest.mock import AsyncMock

import pytest
from malscan_worker.consumer import process_message
from malscan_worker.exceptions import ArchivePasswordRequiredError, ArchiveWrongPasswordError
from malscan_worker.pipeline import _run_stage
from malscan_worker.stages.base import Stage, StageContext


class DummyMessage:
    def __init__(self, body: dict):
        self.body = json.dumps(body).encode()
        self.headers = {}
        self.ack = AsyncMock()
        self.reject = AsyncMock()


class PasswordStage(Stage):
    @property
    def name(self) -> str:
        return "archive-extract"

    async def execute(self, ctx: StageContext):
        raise ArchivePasswordRequiredError("zip")


@pytest.mark.asyncio
async def test_run_stage_reraises_password_required(tmp_path):
    file_path = tmp_path / "f.bin"
    file_path.write_bytes(b"x")
    ctx = StageContext(
        job_id="job-1",
        file_id="file-1",
        storage_key="key",
        sha256="sha",
        original_filename="x.bin",
        file_path=file_path,
    )

    with pytest.raises(ArchivePasswordRequiredError):
        await _run_stage(PasswordStage(), ctx)


@pytest.mark.asyncio
async def test_consumer_password_required_sets_status(mocker):
    body = {
        "job_id": "job-1",
        "file_id": "file-1",
        "storage_key": "sha",
        "sha256": "sha",
        "original_filename": "enc.zip",
    }
    message = DummyMessage(body)

    mocker.patch(
        "malscan_worker.consumer.run_pipeline",
        new_callable=AsyncMock,
        side_effect=ArchivePasswordRequiredError("zip"),
    )
    update_status = mocker.patch("malscan_worker.consumer.update_job_status", new_callable=AsyncMock)

    await process_message(message)

    update_status.assert_any_call(
        "job-1",
        "password_required",
        error_message="此壓縮檔需要密碼才能解壓縮",
        current_stage="archive-extract",
    )
    message.ack.assert_awaited_once()


@pytest.mark.asyncio
async def test_consumer_wrong_password_exhausted_marks_done(mocker):
    body = {
        "job_id": "job-2",
        "file_id": "file-2",
        "storage_key": "sha2",
        "sha256": "sha2",
        "original_filename": "enc.zip",
    }
    message = DummyMessage(body)

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
    store_result = mocker.patch("malscan_worker.consumer.update_job_result", new_callable=AsyncMock)
    update_status = mocker.patch("malscan_worker.consumer.update_job_status", new_callable=AsyncMock)

    await process_message(message)

    assert store_result.await_count == 1
    update_status.assert_any_call("job-2", "done", current_stage=None, stages_done=5)
    message.ack.assert_awaited_once()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd worker && poetry run pytest tests/test_password_flow.py -v`
Expected: FAIL because `_run_stage` currently swallows password exceptions and consumer lacks password-specific branches.

- [ ] **Step 3: Write minimal implementation**

```python
# worker/src/malscan_worker/pipeline.py (key changes)
from malscan_worker.exceptions import ArchivePasswordRequiredError, ArchiveWrongPasswordError


async def _run_stage(stage, ctx: StageContext) -> StageResult:
    stage_name = stage.name
    job_id = ctx.job_id
    start_time = datetime.now(timezone.utc)
    timeout = getattr(settings, "stage_timeout_seconds", 300)

    try:
        result = await asyncio.wait_for(stage.execute(ctx), timeout=timeout)
        stage_latency.labels(stage=stage_name, status=result.status).observe(result.duration_ms / 1000)
        return result
    except (ArchivePasswordRequiredError, ArchiveWrongPasswordError):
        raise
    except asyncio.TimeoutError:
        now = datetime.now(timezone.utc)
        return StageResult(
            stage_name=stage_name,
            status="failed",
            started_at=start_time,
            ended_at=now,
            duration_ms=int((now - start_time).total_seconds() * 1000),
            findings={},
            artifacts=[],
            error=f"Stage timeout after {timeout}s",
        )
    except Exception as e:
        now = datetime.now(timezone.utc)
        log.error("stage_error", job_id=job_id, stage=stage_name, error=str(e), exc_info=True)
        return StageResult(
            stage_name=stage_name,
            status="failed",
            started_at=start_time,
            ended_at=now,
            duration_ms=int((now - start_time).total_seconds() * 1000),
            findings={},
            artifacts=[],
            error=str(e),
        )


async def run_pipeline(job_data: dict[str, Any]) -> dict[str, Any]:
    ctx = StageContext(
        job_id=job_id,
        file_id=file_id,
        storage_key=storage_key,
        sha256=job_data.get("sha256", ""),
        original_filename=job_data.get("original_filename", "unknown"),
        file_path=file_path,
        archive_password=job_data.get("archive_password"),
        previous_results=[],
        job=job_instance,
        db=session,
    )
```

```python
# worker/src/malscan_worker/db.py
async def increment_password_attempts(job_id: str) -> int:
    async with AsyncSession(_engine) as session:
        from sqlalchemy import text

        stmt = text(
            """
            UPDATE jobs
            SET password_attempts = password_attempts + 1,
                updated_at = :updated_at
            WHERE id = :job_id
            RETURNING password_attempts
            """
        )
        result = await session.execute(
            stmt,
            {
                "job_id": UUID(job_id),
                "updated_at": datetime.now(timezone.utc),
            },
        )
        await session.commit()
        return int(result.scalar_one())
```

```python
# worker/src/malscan_worker/reporting.py
from typing import Any


def build_password_exhausted_report(job_data: dict[str, Any], archive_type: str, attempts: int) -> dict[str, Any]:
    job_id = job_data["job_id"]
    file_id = job_data["file_id"]
    sha256 = job_data.get("sha256", "")
    original_filename = job_data.get("original_filename", "unknown")

    return {
        "job_id": job_id,
        "file": {
            "file_id": file_id,
            "sha256": sha256,
            "mime": "application/octet-stream",
            "size": 0,
            "original_filename": original_filename,
        },
        "verdict": "clean",
        "score": 0,
        "results": {
            "av_result": {
                "engine": "ClamAV",
                "infected": False,
                "threat_name": None,
            },
            "yara_hits": [],
            "iocs": {
                "urls": [],
                "domains": [],
                "ips": [],
                "hashes": {
                    "md5": "",
                    "sha1": "",
                    "sha256": sha256,
                },
            },
            "sandbox": {
                "executed": False,
                "behaviors": [],
                "network_connections": [],
                "is_mock": True,
            },
            "archive_extract": {
                "archive_type": archive_type,
                "extracted_count": 0,
                "sub_jobs_created": 0,
                "total_extracted_bytes": 0,
                "malicious": False,
                "reason": f"Archive extraction failed after {attempts} incorrect password attempts",
                "extraction_failed": True,
            },
        },
        "timings": {
            "total_ms": 0,
            "stages": [],
        },
    }
```

```python
# worker/src/malscan_worker/consumer.py (key branches)
from malscan_worker.db import increment_password_attempts, update_job_result, update_job_status
from malscan_worker.exceptions import ArchivePasswordRequiredError, ArchiveWrongPasswordError
from malscan_worker.reporting import build_password_exhausted_report


MAX_PASSWORD_ATTEMPTS = 3


async def process_message(message: aio_pika.abc.AbstractIncomingMessage) -> None:
    body = json.loads(message.body.decode())
    job_id = body.get("job_id")
    file_id = body.get("file_id")
    retry_count = _get_retry_count(message)
    worker_active_jobs.inc()
    job_total.labels(status="scanning").inc()
    if job_id:
        await update_job_status(job_id, "scanning")

    try:
        await run_pipeline(body)
        job_total.labels(status="done").inc()
        await message.ack()
    except ArchivePasswordRequiredError:
        await update_job_status(
            job_id,
            "password_required",
            error_message="此壓縮檔需要密碼才能解壓縮",
            current_stage="archive-extract",
        )
        await message.ack()
    except ArchiveWrongPasswordError as exc:
        attempts = await increment_password_attempts(job_id)
        remaining = max(0, MAX_PASSWORD_ATTEMPTS - attempts)
        if remaining > 0:
            await update_job_status(
                job_id,
                "password_required",
                error_message=f"密碼錯誤，請重試（剩餘 {remaining} 次）",
                current_stage="archive-extract",
            )
        else:
            report = build_password_exhausted_report(body, exc.archive_type, attempts)
            await update_job_result(job_id, report)
            await update_job_status(job_id, "done", current_stage=None, stages_done=settings.stages_total)
        await message.ack()
    except Exception as e:
        log.error(
            "job_failed",
            job_id=job_id,
            file_id=file_id,
            error=str(e),
            retry_count=retry_count,
        )
        job_total.labels(status="failed").inc()
        if retry_count < MAX_MESSAGE_RETRIES:
            await message.reject(requeue=True)
        else:
            if job_id:
                await update_job_status(job_id, "failed", error_message=f"Max retries exceeded: {e}")
            await message.reject(requeue=False)
    finally:
        worker_active_jobs.dec()
```

- [ ] **Step 4: Run tests to verify it passes**

Run: `cd worker && poetry run pytest tests/test_password_flow.py tests/test_pipeline.py tests/test_stages.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add worker/src/malscan_worker/pipeline.py worker/src/malscan_worker/db.py worker/src/malscan_worker/consumer.py worker/src/malscan_worker/reporting.py worker/tests/test_password_flow.py
git commit -m "feat(worker): implement password-required and retry-exhausted archive flow"
```

### Task 4: Backend Password Submission API and Job Status Payload

**Files:**
- Modify: `backend/src/malscan/schemas/requests.py`
- Modify: `backend/src/malscan/api/routes.py`
- Create: `backend/tests/test_password_api.py`

- [ ] **Step 1: Write the failing test**

```python
# backend/tests/test_password_api.py
import uuid
from unittest.mock import AsyncMock, MagicMock


def test_submit_password_success(client, mock_db_session, mocker):
    job_id = uuid.uuid4()
    file_id = uuid.uuid4()

    mock_job = MagicMock()
    mock_job.id = job_id
    mock_job.status = "password_required"
    mock_job.password_attempts = 1
    mock_job.file = MagicMock(id=file_id, sha256="abc123")

    mock_result = MagicMock()
    mock_result.unique.return_value.scalar_one_or_none.return_value = mock_job
    mock_db_session.execute.return_value = mock_result
    mock_db_session.commit = AsyncMock()

    publish = mocker.patch("malscan.api.routes.publish_job", new_callable=AsyncMock)
    publish.return_value = None

    response = client.post(f"/api/v1/jobs/{job_id}/password", json={"password": "correct-pass"})
    assert response.status_code == 200
    payload = response.json()
    assert payload["job_id"] == str(job_id)
    assert payload["status"] == "queued"
    assert payload["attempts_used"] == 1
    assert payload["attempts_remaining"] == 2


def test_submit_password_invalid_status(client, mock_db_session):
    job_id = uuid.uuid4()

    mock_job = MagicMock()
    mock_job.id = job_id
    mock_job.status = "scanning"
    mock_job.password_attempts = 0

    mock_result = MagicMock()
    mock_result.unique.return_value.scalar_one_or_none.return_value = mock_job
    mock_db_session.execute.return_value = mock_result

    response = client.post(f"/api/v1/jobs/{job_id}/password", json={"password": "abc"})
    assert response.status_code == 409


def test_get_job_status_includes_password_attempt_fields(client, mock_db_session):
    job_id = uuid.uuid4()
    mock_job = MagicMock()
    mock_job.id = job_id
    mock_job.parent_job_id = None
    mock_job.depth = 0
    mock_job.status = "password_required"
    mock_job.current_stage = "archive-extract"
    mock_job.stages_done = 4
    mock_job.stages_total = 5
    mock_job.error_message = "此壓縮檔需要密碼才能解壓縮"
    mock_job.password_attempts = 2
    mock_job.total_sub = 0
    mock_job.completed_sub = 0
    mock_job.malicious_sub = 0
    mock_job.updated_at = MagicMock()

    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = mock_job
    mock_db_session.execute.return_value = mock_result

    response = client.get(f"/api/v1/jobs/{job_id}")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "password_required"
    assert data["password_attempts"] == 2
    assert data["password_attempts_remaining"] == 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && poetry run pytest tests/test_password_api.py -v`
Expected: FAIL because endpoint and status fields are not implemented.

- [ ] **Step 3: Write minimal implementation**

```python
# backend/src/malscan/schemas/requests.py
class PasswordSubmitRequest(BaseModel):
    password: str


class PasswordSubmitResponse(BaseModel):
    job_id: str
    status: str
    message: str
    attempts_used: int
    attempts_remaining: int
```

```python
# backend/src/malscan/api/routes.py (imports)
from malscan.schemas.requests import (
    JobStatusResponse,
    PasswordSubmitRequest,
    PasswordSubmitResponse,
    ReportResponse,
    UploadResponse,
)


MAX_PASSWORD_ATTEMPTS = 3
```

```python
# backend/src/malscan/api/routes.py (new endpoint)
@router.post("/jobs/{job_id}/password", response_model=PasswordSubmitResponse)
async def submit_archive_password(
    job_id: str,
    payload: PasswordSubmitRequest,
    db: AsyncSession = Depends(get_db),
) -> PasswordSubmitResponse:
    if not payload.password.strip():
        raise HTTPException(status_code=422, detail="Password cannot be empty")
    if len(payload.password) > 256:
        raise HTTPException(status_code=422, detail="Password too long")

    try:
        job_uuid = uuid.UUID(job_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid job_id format") from None

    stmt = (
        select(Job)
        .where(Job.id == job_uuid)
        .options(joinedload(Job.file))
        .with_for_update()
    )
    result = await db.execute(stmt)
    job = result.unique().scalar_one_or_none()

    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    if job.status != JobStatus.PASSWORD_REQUIRED.value:
        raise HTTPException(status_code=409, detail="Job is not in password_required status")
    if job.password_attempts >= MAX_PASSWORD_ATTEMPTS:
        raise HTTPException(status_code=409, detail="Password attempts exhausted")
    if not job.file:
        raise HTTPException(status_code=500, detail="Job file metadata missing")

    await publish_job(
        {
            "job_id": str(job.id),
            "file_id": str(job.file.id),
            "storage_key": job.file.sha256,
            "sha256": job.file.sha256,
            "original_filename": job.file.filename,
            "archive_password": payload.password,
        }
    )

    job.status = JobStatus.QUEUED.value
    job.current_stage = None
    job.error_message = None
    await db.commit()

    attempts_used = int(job.password_attempts)
    attempts_remaining = max(0, MAX_PASSWORD_ATTEMPTS - attempts_used)

    return PasswordSubmitResponse(
        job_id=str(job.id),
        status=job.status,
        message="Password submitted. Retrying archive extraction.",
        attempts_used=attempts_used,
        attempts_remaining=attempts_remaining,
    )
```

```python
# backend/src/malscan/api/routes.py (status response additions)
password_attempts = int(getattr(job, "password_attempts", 0))
password_attempts_remaining = max(0, MAX_PASSWORD_ATTEMPTS - password_attempts)

return JobStatusResponse(
    job_id=str(job.id),
    parent_job_id=str(job.parent_job_id) if job.parent_job_id else None,
    depth=job.depth,
    status=job.status,
    progress={
        "current_stage": job.current_stage,
        "stages_done": job.stages_done,
        "stages_total": job.stages_total,
        "percent": percent,
    },
    updated_at=job.updated_at,
    error_message=job.error_message,
    password_attempts=password_attempts,
    password_attempts_remaining=password_attempts_remaining,
    total_sub=job.total_sub,
    completed_sub=job.completed_sub,
    malicious_sub=job.malicious_sub,
)
```

- [ ] **Step 4: Run tests to verify it passes**

Run: `cd backend && poetry run pytest tests/test_password_api.py tests/test_api.py::test_get_job_status_success -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/src/malscan/schemas/requests.py backend/src/malscan/api/routes.py backend/tests/test_password_api.py
git commit -m "feat(api): add archive password submission endpoint and status metadata"
```

### Task 5: Frontend API Client and Type Contract

**Files:**
- Modify: `frontend/src/api/types.ts`
- Modify: `frontend/src/api/client.ts`

- [ ] **Step 1: Write the failing contract check**

```typescript
// frontend/src/api/types.ts
export interface JobStatus {
    job_id: string
    status: JobStatusValue
    progress: JobProgress
    updated_at: string
    error_message: string | null
    password_attempts: number
    password_attempts_remaining: number
}

export interface PasswordSubmitRequest {
    password: string
}

export interface PasswordSubmitResponse {
    job_id: string
    status: string
    message: string
    attempts_used: number
    attempts_remaining: number
}
```

```typescript
// frontend/src/api/client.ts (compile contract before implementation)
import type {
    JobStatus,
    PasswordSubmitRequest,
    PasswordSubmitResponse,
} from './types'

const __passwordSubmitMethod: (jobId: string, req: PasswordSubmitRequest) => Promise<PasswordSubmitResponse> =
    apiClient.submitArchivePassword
void __passwordSubmitMethod
```

- [ ] **Step 2: Run typecheck to verify it fails**

Run: `cd frontend && npm run typecheck`
Expected: FAIL because `submitArchivePassword` method does not exist on `ApiClient`.

- [ ] **Step 3: Write minimal implementation**

```typescript
// frontend/src/api/client.ts
import type {
    ApiError,
    JobStatus,
    PasswordSubmitRequest,
    PasswordSubmitResponse,
    Report,
    UploadResponse,
} from './types'

class ApiClient {
    public baseUrl: string

    constructor(baseUrl: string = API_BASE_URL) {
        this.baseUrl = baseUrl
    }

    getJobStreamUrl(jobId: string): string {
        return `${this.baseUrl}/api/v1/jobs/${jobId}/stream`
    }

    async submitArchivePassword(jobId: string, req: PasswordSubmitRequest): Promise<PasswordSubmitResponse> {
        const response = await fetch(`${this.baseUrl}/api/v1/jobs/${jobId}/password`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(req),
        })

        if (!response.ok) {
            let message = '提交密碼失敗'
            try {
                const errorData = (await response.json()) as { detail?: string | ApiError['error'] }
                if (typeof errorData.detail === 'string') {
                    message = errorData.detail
                }
            } catch {
                message = response.statusText || message
            }
            throw new Error(message)
        }

        return (await response.json()) as PasswordSubmitResponse
    }
}
```

- [ ] **Step 4: Run typecheck to verify it passes**

Run: `cd frontend && npm run typecheck`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add frontend/src/api/types.ts frontend/src/api/client.ts
git commit -m "feat(frontend): add typed archive password submit api client"
```

### Task 6: Job Status Password UI Flow

**Files:**
- Create: `frontend/src/components/PasswordForm.tsx`
- Modify: `frontend/src/pages/JobStatusPage.tsx`
- Modify: `frontend/src/constants/status.ts`

- [ ] **Step 1: Write the failing compile assertion**

```typescript
// frontend/src/pages/JobStatusPage.tsx (add usage first)
import PasswordForm from '../components/PasswordForm'

// inside component render path
{job.status === 'password_required' && (
    <PasswordForm
        attemptsUsed={job.password_attempts}
        attemptsRemaining={job.password_attempts_remaining}
        onSubmit={async (password: string) => {
            await apiClient.submitArchivePassword(job.job_id, { password })
        }}
    />
)}
```

- [ ] **Step 2: Run typecheck to verify it fails**

Run: `cd frontend && npm run typecheck`
Expected: FAIL because `PasswordForm` component file does not exist yet.

- [ ] **Step 3: Write minimal implementation**

```tsx
// frontend/src/components/PasswordForm.tsx
import { useState } from 'react'

interface PasswordFormProps {
    attemptsUsed: number
    attemptsRemaining: number
    onSubmit: (password: string) => Promise<void>
}

export default function PasswordForm({ attemptsUsed, attemptsRemaining, onSubmit }: PasswordFormProps) {
    const [password, setPassword] = useState('')
    const [submitting, setSubmitting] = useState(false)
    const [error, setError] = useState<string | null>(null)

    const handleSubmit = async (event: React.FormEvent) => {
        event.preventDefault()
        if (!password.trim()) {
            setError('請輸入壓縮檔密碼')
            return
        }

        setSubmitting(true)
        setError(null)
        try {
            await onSubmit(password)
            setPassword('')
        } catch (err) {
            setError(err instanceof Error ? err.message : '密碼提交失敗')
        } finally {
            setSubmitting(false)
        }
    }

    return (
        <form onSubmit={handleSubmit} className="mt-6 p-4 rounded-lg bg-caution-yellow/10 border border-caution-yellow/40">
            <p className="text-caution-yellow font-mono text-sm">此壓縮檔需要密碼才能解壓縮</p>
            <p className="text-slate-300 text-xs mt-1">已嘗試 {attemptsUsed}/3 次，剩餘 {attemptsRemaining} 次</p>
            <div className="mt-3 flex gap-2">
                <input
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="輸入壓縮檔密碼"
                    className="flex-1 px-3 py-2 rounded bg-deep-space border border-white/20 text-white"
                />
                <button type="submit" disabled={submitting} className="btn-neon px-4 py-2">
                    {submitting ? '提交中...' : '提交密碼'}
                </button>
            </div>
            {error && <p className="mt-2 text-alert-red text-xs">{error}</p>}
        </form>
    )
}
```

```tsx
// frontend/src/pages/JobStatusPage.tsx (SSE handling key update)
if (data.status === 'done') {
    es.close()
    navigate(`/reports/${jobId}`)
} else if (data.status === 'failed') {
    es.close()
}

// password_required stays connected; render PasswordForm and let user submit
```

- [ ] **Step 4: Run typecheck to verify it passes**

Run: `cd frontend && npm run typecheck`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add frontend/src/components/PasswordForm.tsx frontend/src/pages/JobStatusPage.tsx frontend/src/constants/status.ts
git commit -m "feat(frontend): add password-required form on job status page"
```

### Task 7: Report Failure Visibility and End-to-End Verification

**Files:**
- Modify: `frontend/src/api/types.ts`
- Modify: `frontend/src/pages/ReportPage.tsx`
- Modify: `backend/src/malscan/schemas/requests.py`

- [ ] **Step 1: Write the failing type/UI check**

```typescript
// frontend/src/api/types.ts
archive_extract?: {
    archive_type: string | null
    extracted_count: number
    sub_jobs_created: number
    total_extracted_bytes: number
    malicious: boolean
    reason: string | null
    extraction_failed?: boolean
}
```

```tsx
// frontend/src/pages/ReportPage.tsx (add assertion render path)
{report.results.archive_extract?.extraction_failed && (
    <p className="mt-4 text-alert-red text-sm font-mono">解壓縮失敗：密碼嘗試次數已達上限</p>
)}
```

- [ ] **Step 2: Run typecheck to verify it fails**

Run: `cd frontend && npm run typecheck`
Expected: FAIL until backend/frontend schemas both include `extraction_failed` consistently.

- [ ] **Step 3: Write minimal implementation**

```python
# backend/src/malscan/schemas/requests.py
class ArchiveExtractResult(BaseModel):
    archive_type: str | None = None
    extracted_count: int = 0
    sub_jobs_created: int = 0
    total_extracted_bytes: int = 0
    malicious: bool = False
    reason: str | None = None
    extraction_failed: bool = False
```

```tsx
// frontend/src/pages/ReportPage.tsx (full failure block)
{report.results.archive_extract?.extraction_failed && (
    <div className="mt-4 p-3 rounded bg-alert-red/10 border border-alert-red/50">
        <p className="text-alert-red text-sm font-mono">解壓縮失敗：密碼嘗試次數已達上限</p>
        {report.results.archive_extract.reason && (
            <p className="text-slate-300 text-xs mt-1">{report.results.archive_extract.reason}</p>
        )}
    </div>
)}
```

- [ ] **Step 4: Run full verification suite**

Run:

1. `cd backend && poetry run pytest tests/test_models.py tests/test_api.py tests/test_password_api.py -v`
2. `cd worker && poetry run pytest tests/test_archive_password.py tests/test_password_flow.py tests/test_pipeline.py tests/test_stages.py -v`
3. `cd frontend && npm run typecheck && npm run build`

Expected:

1. Backend tests PASS.
2. Worker tests PASS.
3. Frontend typecheck/build PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/src/malscan/schemas/requests.py frontend/src/api/types.ts frontend/src/pages/ReportPage.tsx
git commit -m "feat(report): show explicit archive extraction failure after password retries"
```

## Manual QA Script (Required Before Merge)

1. Upload encrypted ZIP without password.
2. Confirm `/jobs/:jobId` SSE status becomes `password_required` and password form appears.
3. Submit wrong password twice; each time confirm status returns to `password_required` and remaining attempts decrement.
4. Submit correct password on third try; confirm job reaches `done` and report includes extracted child jobs.
5. Repeat with three wrong passwords; confirm job reaches `done` and report shows extraction failure message.
6. Upload non-encrypted file; confirm no password UI appears and legacy flow remains unchanged.

## Plan Self-Review

### 1) Spec coverage check

- `password_required` state and flow: covered by Tasks 1, 3, 4, 6.
- 3-attempt limit and final `done` report: covered by Tasks 3 and 7.
- Password input on job status page: covered by Task 6.
- Final report extraction failure visibility: covered by Task 7.
- Security requirement (no password persistence): covered by Tasks 3 and 4 implementation snippets.

### 2) Placeholder scan

- No `TODO`, `TBD`, or "implement later" markers remain.
- Each implementation step includes concrete code snippets and commands.

### 3) Type consistency check

- `password_required`, `password_attempts`, and `password_attempts_remaining` naming is consistent across backend schemas, API client, and UI usage.
- Worker uses `archive_password` key consistently in queue payload and context.
