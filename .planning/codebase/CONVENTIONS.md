# Coding Conventions

**Analysis Date:** 2024-12-19

## Overview

The MalScanWorker codebase spans three main components with distinct tech stacks:
- **Backend/Worker**: Python 3.11+ with strict type checking
- **Frontend**: TypeScript 5.2+ with React 18
- Code style is consistently enforced with automated tooling

## Naming Patterns

### Files

**Python:**
- `snake_case.py` for module files
- Examples: `models/job.py`, `stages/base.py`, `tests/test_api.py`
- Test files: `test_*.py` (always prefix with `test_`)

**TypeScript/React:**
- `PascalCase.tsx` for React components
- `camelCase.ts` for utility modules and hooks
- Examples: `pages/UploadPage.tsx`, `api/client.ts`, `App.tsx`

**Directories:**
- `snake_case` for all directories in Python projects
- Example structure: `backend/src/malscan/api/routes.py`
- Feature directories: `stages/`, `models/`, `schemas/`, `db/`

### Functions and Variables

**Python:**
- `snake_case()` for all functions, methods, and variables
- Private/internal: prefix with `_` (single underscore for internal, double for name mangling if needed)
- Examples: `_sanitize_filename()`, `_get_retry_count()`, `get_minio_client()`
- Constants: `UPPER_SNAKE_CASE` (e.g., `MAX_REQUEST_BODY_SIZE`, `DLQ_QUEUE`, `CHUNK_SIZE`)

**TypeScript:**
- `camelCase()` for all functions, methods, and variables
- Private/internal: prefix with `_` in React components
- Examples: `checkHealth()`, `uploadFile()`, `getJobStatus()`
- Constants: `UPPER_SNAKE_CASE` (e.g., `MAX_SIZE`, `API_BASE_URL`)
- Unused parameters: prefix with `_` (enforced via ESLint `@typescript-eslint/no-unused-vars`)

### Types and Classes

**Python:**
- `PascalCase` for all classes and enum names
- Examples: `Job`, `File`, `JobStatus`, `Stage`, `StageContext`, `StageResult`
- Dataclasses use `@dataclass` decorator with PascalCase names
- SQLAlchemy models: `PascalCase` with `__tablename__` in `snake_case`

**TypeScript:**
- `PascalCase` for all interfaces, types, and classes
- Examples: `JobStatus`, `UploadResponse`, `Report`, `ApiClient`
- Generic interfaces with descriptive names: `ApiError`, `JobProgress`, `FileMetadata`
- Enum-like objects: `PascalCase` keys (e.g., `status: 'queued' | 'scanning' | 'done' | 'failed'`)

### Database Models

**Pattern from `backend/src/malscan/models/job.py`:**
- Table name: `__tablename__ = "jobs"` (lowercase, plural)
- Column names: `snake_case`
- Model class: `PascalCase` (e.g., `Job`, `File`)
- IDs: UUID v4 for all primary keys
- Timestamps: Always include `created_at` and `updated_at` with timezone awareness
- Relationships: Use SQLAlchemy relationships with proper forward references in quotes

## Code Style

### Formatting

**Python:**
- Line length: 100 characters (enforced by Black and Ruff)
- Indentation: 4 spaces
- Tool: **Black** for code formatting
- Tool: **isort** for import sorting (profile: "black")
- Tool: **Ruff** for linting with strict rules

**TypeScript:**
- Line length: Not explicitly set in config but follows eslint conventions
- Indentation: 2 spaces (standard for Node.js/React)
- Type annotations: Required on function parameters and returns
- Trailing commas: Allowed in multi-line constructs
- Semicolons: Required
- Tool: **ESLint** for linting with TypeScript support

### Linting

**Python (Ruff configuration from `pyproject.toml`):**
```
[tool.ruff]
line-length = 100
select = ["E", "F", "W", "I", "N", "UP", "B", "C4"]
ignore = ["B008"]
```
- **E**: PEP 8 errors
- **F**: PyFlakes (undefined names, unused imports)
- **W**: PEP 8 warnings
- **I**: isort (import sorting)
- **N**: pep8-naming (naming conventions)
- **UP**: pyupgrade (modern Python syntax)
- **B**: flake8-bugbear (bug detection)
- **C4**: flake8-comprehensions

**MyPy (strict mode enabled):**
```
[tool.mypy]
python_version = "3.11"
strict = true
ignore_missing_imports = true
```
- All functions must have type hints
- No implicit `Any` types
- Missing imports can be ignored for external packages

**TypeScript/ESLint from `frontend/.eslintrc.cjs`:**
- Extends: `eslint:recommended`, `plugin:@typescript-eslint/recommended`, `plugin:react-hooks/recommended`
- Key rules:
  - `react-refresh/only-export-components`: Components must be default exports or constants
  - `@typescript-eslint/no-unused-vars`: Error on unused variables, except those starting with `_`
  - No explicit `any` types without suppression

### Code Comments

**When to Comment:**
- Complex algorithms or non-obvious logic
- Important assumptions or constraints
- Security considerations and validation logic
- TODO/FIXME items with context

**Pattern from code:**
- Docstring on every function/class (Python)
- JSDoc style rarely used (mostly plain comments)
- Inline comments explain `why`, not `what`

**Examples:**
```python
"""Upload a file for malware analysis.

- Uses streaming to handle large files efficiently
- Calculates SHA256 hash incrementally
- Stores file in MinIO
- Creates file and job records in database
- Publishes job to RabbitMQ
- Returns job_id immediately (async processing)
"""

# Replace Windows path separators with Unix ones, then get basename
filename = filename.replace(chr(92), "/")
filename = os.path.basename(filename)

# CORS middleware (added last = runs first in middleware chain)
app.add_middleware(
    CORSMiddleware,
    ...
)
```

**TypeScript Comments:**
```typescript
// Health check polling
useEffect(() => {
    const checkBackend = async () => {
        ...
    }
}, [])

// Handle both {"detail": {"error": {"message": "..."}}} and {"error": {"message": "..."}}
const errorMessage =
    errorData?.detail?.error?.message ||
    errorData?.detail?.message ||
    ...
```

## Import Organization

### Python Import Order

**Pattern from `backend/src/malscan/api/routes.py`:**

1. Standard library imports (asyncio, hashlib, os, tempfile, uuid, etc.)
2. Third-party imports (fastapi, sqlalchemy, structlog, etc.)
3. Local application imports (malscan.*)
4. Blank line between each group

**Example:**
```python
import asyncio
import hashlib
import os
import tempfile
import uuid
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from malscan.config import get_settings
from malscan.db import get_db
from malscan.models import File, Job, JobStatus
```

Enforced by: **isort** with Black profile

### TypeScript Import Order

**Pattern from `frontend/src/pages/UploadPage.tsx`:**

1. React and library imports
2. Project-local imports (using relative paths)
3. Organized by type: hooks/utilities, then components

**Example:**
```typescript
import { useState, useCallback, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { apiClient } from '../api/client'
```

**No explicit import aliases** in `frontend/tsconfig.json` - all imports use relative paths

## Error Handling

### Python Error Handling Pattern

**Strategy:** Try-catch with structured logging, propagate errors via HTTPException or raise

**Pattern from `backend/src/malscan/api/routes.py`:**

```python
# 1. Validate input early
try:
    parent_job_uuid = uuid.UUID(parent_job_id_str)
except ValueError:
    raise HTTPException(
        status_code=400, detail="Invalid parent_job_id format"
    ) from None

# 2. Use structured logging for errors
try:
    await upload_to_minio(temp_path, sha256_hash, content_type)
except Exception as e:
    log.error("minio_upload_failed", sha256=sha256_hash, error=str(e))
    raise HTTPException(
        status_code=500,
        detail={
            "error": {
                "code": "STORAGE_ERROR",
                "message": f"Failed to store file: {e}",
            }
        },
    ) from e

# 3. Distinguish recoverable vs fatal errors
try:
    await init_rabbitmq()
    log.info("rabbitmq_initialized")
except Exception as e:
    log.error("rabbitmq_initialization_failed", error=str(e))
    raise  # Fatal: re-raise to stop startup

# 4. Finally blocks for cleanup
try:
    with os.fdopen(fd, "wb") as temp_file:
        ...
finally:
    if os.path.exists(temp_path):
        os.remove(temp_path)
```

**Error Response Format:**
```json
{
  "error": {
    "code": "FILE_TOO_LARGE",
    "message": "File size exceeds limit",
    "details": {
      "max_size_bytes": 104857600,
      "actual_size_bytes": 150000000
    }
  }
}
```

### TypeScript Error Handling Pattern

**Pattern from `frontend/src/api/client.ts`:**

```typescript
// 1. Check response status before parsing
async uploadFile(file: File): Promise<UploadResponse> {
    const formData = new FormData()
    formData.append('file', file)

    const response = await fetch(`${this.baseUrl}/api/v1/files`, {
        method: 'POST',
        body: formData,
    })

    if (!response.ok) {
        const errorData = await response.json()
        // Handle nested error structures
        const errorMessage =
            errorData?.detail?.error?.message ||
            errorData?.detail?.message ||
            errorData?.error?.message ||
            errorData?.detail ||
            '上傳失敗'
        throw new Error(String(errorMessage))
    }

    return response.json()
}

// 2. Try-catch with fallback messages
async getJobStatus(jobId: string): Promise<JobStatus> {
    const response = await fetch(`${this.baseUrl}/api/v1/jobs/${jobId}`)

    if (!response.ok) {
        let errorMessage = '取得工作狀態失敗'
        try {
            const errorData = await response.json()
            errorMessage = errorData?.detail?.error?.message ||
                           errorData?.error?.message ||
                           errorData?.detail ||
                           errorMessage
        } catch {
            errorMessage = response.statusText
        }
        throw new Error(errorMessage)
    }

    return response.json()
}
```

## Logging

### Python Logging

**Framework:** **structlog** - structured JSON logging
**Pattern from `backend/src/malscan/main.py`:**

```python
import structlog

structlog.configure(
    processors=[
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ]
)

log = structlog.get_logger()

# Log with context fields (becomes JSON)
log.info("application_startup", cors_origins=cors_origins)
log.error("rabbitmq_initialization_failed", error=str(e))
log.info("file_upload_started", filename=filename, content_type=content_type)
```

**Key Context Fields (from actual code):**
- Job operations: `job_id`, `file_id`, `sha256`
- File operations: `filename`, `content_type`, `size`
- Stage execution: `stage_name`, `status`, `duration_ms`
- Errors: `error` (string representation), specific error codes

**Log Levels:**
- `log.info()` - Normal operations: startup, file created, job status changes
- `log.error()` - Failures: initialization failed, upload failed, processing errors
- `log.warning()` - Potential issues (if used)
- `log.debug()` - Detailed traces (if used)

### Worker Logging (RabbitMQ Consumer)

**Pattern from `worker/src/malscan_worker/consumer.py`:**
```python
import logging
import structlog

log = structlog.get_logger()
_logger = logging.getLogger(__name__)  # For tenacity retry logging

# structlog for main flow
log.info("job_status_updated", job_id=job_id, status=new_status)
log.error("job_processing_failed", job_id=job_id, error=str(e))

# Standard logging for library integration
_logger.info("Retrying after 10 seconds")  # Used by tenacity
```

## Function Design

### Python Functions

**Size:** Keep functions focused, typically under 50 lines for complex operations
**Parameters:** Use explicit parameters, avoid **kwargs for required args
**Type Hints:** Required on all parameters and return values
**Return Values:** None if side-effect only, tuple for multiple values

**Example patterns:**

```python
# 1. Async operations with typing
async def upload_file(request: Request, db: AsyncSession = Depends(get_db)) -> UploadResponse:
    """Upload a file for malware analysis."""
    ...

# 2. Database queries with type hints
async def get_job_status(job_id: str, db: AsyncSession = Depends(get_db)) -> JobStatusResponse:
    """Get the status of a job."""
    job_uuid = uuid.UUID(job_id)
    stmt = select(Job).where(Job.id == job_uuid)
    result = await db.execute(stmt)
    job = result.scalar_one_or_none()
    ...

# 3. Helper functions with default parameters
def _sanitize_filename(filename: str) -> str:
    """Sanitize uploaded filename."""
    ...

# 4. Configuration getters
def get_minio_client() -> Minio:
    """Get or create the MinIO client instance (Singleton)."""
    global _minio_client
    if _minio_client is None:
        _minio_client = Minio(...)
    return _minio_client
```

### TypeScript Functions

**Async by default:** Most functions are `async` for API operations
**Type annotations:** All parameters and returns must be typed
**Return types:** Always explicit (no implicit `Promise<any>`)

**Example patterns:**

```typescript
// 1. Async API methods
async uploadFile(file: File): Promise<UploadResponse> {
    const formData = new FormData()
    formData.append('file', file)
    const response = await fetch(...)
    return response.json()
}

// 2. React hooks with typed state
const [file, setFile] = useState<File | null>(null)
const [isUploading, setIsUploading] = useState(false)
const [error, setError] = useState<string | null>(null)

// 3. Callback handlers
const handleFile = useCallback((selectedFile: File) => {
    if (selectedFile.size > MAX_SIZE) {
        setError(`Size exceeds limit`)
        return
    }
    setFile(selectedFile)
}, [])

// 4. Event handlers
const handleDragOver = (e: React.DragEvent<HTMLDivElement>): void => {
    e.preventDefault()
    setIsDragging(true)
}
```

## Module Design

### Python Modules

**Pattern: Feature-based organization with clear layer separation**

```
backend/src/malscan/
├── models/          # SQLAlchemy models
│   ├── base.py     # Base class
│   ├── file.py
│   └── job.py
├── schemas/        # Pydantic validation models
│   └── requests.py
├── api/            # FastAPI routes
│   └── routes.py
├── db/             # Database connectivity
│   ├── engine.py
│   └── session.py
├── config.py       # Settings/configuration
├── main.py         # Application entry point
└── __init__.py     # Package exports
```

**Exports Pattern:**
```python
# In models/__init__.py
from malscan.models.file import File
from malscan.models.job import Job, JobStatus
from malscan.models.base import Base

__all__ = ["File", "Job", "JobStatus", "Base"]

# In routes.py, use: from malscan.models import File, Job
```

### TypeScript React Modules

**Pattern: Page-based organization with shared API layer**

```
frontend/src/
├── pages/
│   ├── UploadPage.tsx
│   ├── JobStatusPage.tsx
│   └── ReportPage.tsx
├── api/
│   └── client.ts          # Single API client class
├── App.tsx                # Router setup
└── main.tsx               # Entry point
```

**No barrel files** - imports use relative paths directly

**API Client pattern (`frontend/src/api/client.ts`):**
```typescript
export interface UploadResponse { ... }
export interface JobStatus { ... }

export class ApiClient {
    baseUrl: string

    constructor(baseUrl: string = API_BASE_URL) { ... }

    async uploadFile(file: File): Promise<UploadResponse> { ... }
    async getJobStatus(jobId: string): Promise<JobStatus> { ... }
}

export const apiClient = new ApiClient()
```

## Async/Await Patterns

### Python Async Pattern

**Pattern from `backend/src/malscan/api/routes.py`:**

```python
# 1. Async route handlers
@router.post("/files", response_model=UploadResponse, status_code=201)
async def upload_file(request: Request, db: AsyncSession = Depends(get_db)) -> UploadResponse:
    # Process file
    ...
    # All DB operations are async
    result = await db.execute(stmt)
    await db.commit()
    # External calls are async
    await upload_to_minio(temp_path, sha256_hash, content_type)
    await publish_job(job_message)
    return response

# 2. AsyncSession for database operations
async with factory() as session:
    stmt = select(Job).where(Job.id == job_uuid)
    result = await session.execute(stmt)
    job = result.scalar_one_or_none()

# 3. Event generator for Server-Sent Events
async def event_generator():
    try:
        while True:
            if await request.is_disconnected():
                break
            # Query inside loop
            async with session_factory() as session:
                result = await session.execute(stmt)
                job = result.scalar_one_or_none()
            await asyncio.sleep(1.0)
    except asyncio.CancelledError:
        log.info("cancelled")

return EventSourceResponse(event_generator())
```

### TypeScript Async Pattern

**Pattern from `frontend/src/api/client.ts`:**

```typescript
// 1. All API methods are async
async checkHealth(): Promise<boolean> {
    try {
        const response = await fetch(`${this.baseUrl}/health`)
        return response.ok
    } catch {
        return false
    }
}

// 2. In React components with useEffect
useEffect(() => {
    const checkBackend = async () => {
        const online = await apiClient.checkHealth()
        setIsBackendOnline(online)
    }
    checkBackend()
    const interval = setInterval(checkBackend, 10000)
    return () => clearInterval(interval)
}, [])

// 3. In event handlers
const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setIsUploading(true)
    try {
        const response = await apiClient.uploadFile(file)
        navigate(`/jobs/${response.job_id}`)
    } catch (err) {
        setError(err instanceof Error ? err.message : 'Unknown error')
    } finally {
        setIsUploading(false)
    }
}
```

## Special Patterns

### Retry and Resilience (Python)

**Library:** **tenacity** for retry logic
**Pattern from `worker/src/malscan_worker/consumer.py`:**

```python
from tenacity import (
    before_sleep_log,
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_fixed,
)

@retry(
    retry=retry_if_exception_type(aio_pika.exceptions.AMQPConnectionError),
    stop=stop_after_attempt(MAX_CONNECTION_RETRIES),
    wait=wait_fixed(RETRY_DELAY),
    before_sleep=before_sleep_log(_logger, logging.INFO),
)
async def connect_rabbitmq() -> aio_pika.Connection:
    """Connect to RabbitMQ with retries."""
    ...
```

### Validation (Python)

**Library:** **Pydantic** for runtime validation
**Pattern from `backend/src/malscan/schemas/requests.py`:**

```python
from pydantic import BaseModel

class JobStatusResponse(BaseModel):
    """Response for GET /jobs/{job_id}."""

    job_id: str
    status: Literal["queued", "scanning", "done", "failed"]
    progress: JobProgress
    updated_at: datetime
    error_message: str | None

# Automatic validation:
# - Fields with None must accept None (str | None)
# - Type checking at runtime
# - .model_dump_json() for serialization
```

### TypeScript Interface Patterns

**Pattern from `frontend/src/api/client.ts`:**

```typescript
// 1. API contract interfaces
export interface UploadResponse {
    job_id: string
    file_id: string
    sha256: string
    status: string
    created_at: string
}

// 2. Literal types for enums
export interface JobStatus {
    status: 'queued' | 'scanning' | 'done' | 'failed'
    progress: JobProgress
}

// 3. Optional fields with undefined
export interface Report {
    child_jobs: Array<{
        job_id: string
        filename: string
        verdict: string | null  // Nullable if not computed yet
    }>
}
```

---

*Convention analysis: 2024-12-19*
