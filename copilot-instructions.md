<!-- GSD:project-start source:PROJECT.md -->
## Project

**MalScanWorker — Go Ingestion Layer**

A high-performance Go microservice that replaces the Python/FastAPI file upload endpoint in the MalScanWorker malware analysis pipeline. The service handles multipart file streaming, SHA256 hashing, MinIO object upload, PostgreSQL record creation, and RabbitMQ job publishing — all with native Go concurrency to support 10–50 simultaneous uploads with lower latency and higher throughput than the current Python implementation.

**Core Value:** Fast, reliable file ingestion that never drops uploads under concurrent load — the gateway through which every malware sample enters the analysis pipeline.

### Constraints

- **Schema compatibility**: Must write to existing `files` and `jobs` tables with exact column types and defaults — Python worker and FastAPI backend read from these same tables
- **API contract**: `POST /api/v1/files` request/response format must be identical to current Python endpoint — frontend must work without changes
- **Infrastructure**: Must connect to the same PostgreSQL, MinIO, and RabbitMQ instances used by existing services
- **Deployment**: Must coexist with existing Python backend (not replace it entirely) — routing splits at proxy layer
- **Message format**: RabbitMQ messages must match the JSON format the Python worker consumer expects (`job_id`, `file_id`, etc.)
<!-- GSD:project-end -->

<!-- GSD:stack-start source:codebase/STACK.md -->
## Technology Stack

## Languages
- Python 3.11 - Backend API server and worker pipeline
- TypeScript 5.2 - Frontend application
- JavaScript (Node.js) - Build tooling and frontend dev
- YAML - Kubernetes manifests, Docker Compose, configuration
- SQL - PostgreSQL database schemas (managed via SQLAlchemy ORM)
## Runtime
- Python 3.11-slim (Docker image base)
- Node.js via npm (frontend build)
- Poetry 1.8+ (Python dependency management)
- npm (JavaScript)
## Frameworks
- FastAPI 0.104.0 - REST API framework for backend (`backend/src/malscan/main.py`)
- uvicorn 0.24.0 - ASGI server for FastAPI
- SQLAlchemy 2.0.0 (asyncio) - ORM for database operations (`backend/src/malscan/db/engine.py`)
- React 18.2.0 - Frontend UI framework
- Vite 5.0.0 - Frontend build tool and dev server
- pytest 7.4.0 - Python test runner
- pytest-asyncio 0.21.0 - Async test support
- pytest-cov 4.1.0 - Coverage reporting
- pytest-mock 3.12.0 - Mocking utilities
- TypeScript 5.2.2 - Type checking for frontend
- Tailwind CSS 3.4.0 - Utility-first CSS framework
- PostCSS 8.4.32 - CSS transformation
- ESLint 8.53.0 - JavaScript/TypeScript linting
- Vite TypeScript plugin (@vitejs/plugin-react 4.2.0) - JSX support
- black 23.11.0 - Python code formatter
- ruff 0.1.0 - Python linter
- mypy 1.7.0 - Python type checker
- isort 5.12.0 - Python import sorter
- structlog 23.2.0 - Structured logging for Python (JSON output)
- prometheus-fastapi-instrumentator 6.1.0 - Metrics collection for FastAPI
- prometheus-client 0.19.0 - Prometheus metrics for worker
## Key Dependencies
- aio-pika 9.3.0 - RabbitMQ async client for message queuing
- minio 7.2.0 - S3-compatible object storage client
- asyncpg 0.29.0 - PostgreSQL async driver
- pydantic 2.5.0 + pydantic-settings 2.1.0 - Data validation and settings management
- tenacity 8.2.0 - Retry library with exponential backoff
- python-magic 0.4.27 - File type detection
- yara-python 4.5.4 - YARA malware rule engine binding
- pyclamd 0.4.0 - ClamAV network socket client
- py7zr 0.22.0 - 7z archive extraction
- rarfile 4.2 - RAR archive handling
- aiohttp 3.9.0 - HTTP client for async operations
- sse-starlette 1.1.5 - Server-Sent Events for Starlette/FastAPI
- alembic 1.13.0 - Database migration tool
- python-multipart 0.0.7 - Multipart form parsing for file uploads
## Configuration
- Configuration loaded from `.env` files using Pydantic Settings
- Backend config: `backend/src/malscan/config.py`
- Worker config: `worker/src/malscan_worker/config.py`
- Example: `.env.example` at repository root
- `DATABASE_URL` - PostgreSQL connection string (asyncpg driver)
- `MINIO_ENDPOINT` - MinIO server address
- `MINIO_ACCESS_KEY` - MinIO authentication
- `MINIO_SECRET_KEY` - MinIO authentication
- `RABBITMQ_URL` - RabbitMQ broker URL (AMQP protocol)
- `CORS_ORIGINS` - CORS-allowed origins (default: "*")
- `LOG_LEVEL` - Logging level (default: "INFO")
- `LOG_FORMAT` - Log format, "json" for structured logging (default: "json")
- `MAX_FILE_SIZE` - Max upload size in bytes (default: 104857600 = 100MB)
- `STAGES_TOTAL` - Number of pipeline stages (default: 5)
- `CLAMAV_HOST` - ClamAV daemon host (default: "clamav")
- `CLAMAV_PORT` - ClamAV daemon port (default: 3310)
- `SANDBOX_ENABLED` - Enable sandbox analysis (default: true)
- `SANDBOX_MOCK` - Use mock sandbox (default: true)
- `METRICS_PORT` - Prometheus metrics port (default: 9090)
- `YARA_RULES_PATH` - Directory containing YARA rule files (default: "/etc/yara/rules")
- Frontend: `frontend/vite.config.ts` - Vite configuration
- Frontend: `frontend/tsconfig.json` - TypeScript configuration
- Frontend: `frontend/.eslintrc.cjs` - ESLint configuration
- Backend: `backend/pyproject.toml` - Poetry configuration with tool settings
- Backend: `backend/poetry.lock` - Dependency lock file
- Frontend dist: `frontend/dist/` (static HTML/JS/CSS)
- Backend container: Dockerfile in `backend/`
- Worker container: Dockerfile in `worker/`
## Platform Requirements
- Python 3.11+
- Node.js 16+
- Docker & Docker Compose (for local infrastructure)
- Poetry (Python dependency manager)
- npm (Node package manager)
- Docker container runtime
- Kubernetes 1.25+ (via k3s)
- PostgreSQL 13+ database
- RabbitMQ 3.x message broker
- MinIO S3-compatible object storage
- ClamAV virus scanner daemon
- YARA malware detection engine
- Linux kernel (tested on Ubuntu 22.04)
- postgres:15
- minio/minio:latest
- rabbitmq:3-management
- clamav/clamav:latest
- Python 3.11-slim container images
## Container Images
- Backend: `ghcr.io/{OWNER}/malscan-api:latest`
- Worker: `ghcr.io/{OWNER}/malscan-worker:latest`
- Frontend: Deployed to GitHub Pages (static)
- GitHub Container Registry (GHCR) for Python services
- GitHub Pages for static frontend
<!-- GSD:stack-end -->

<!-- GSD:conventions-start source:CONVENTIONS.md -->
## Conventions

## Overview
- **Backend/Worker**: Python 3.11+ with strict type checking
- **Frontend**: TypeScript 5.2+ with React 18
- Code style is consistently enforced with automated tooling
## Naming Patterns
### Files
- `snake_case.py` for module files
- Examples: `models/job.py`, `stages/base.py`, `tests/test_api.py`
- Test files: `test_*.py` (always prefix with `test_`)
- `PascalCase.tsx` for React components
- `camelCase.ts` for utility modules and hooks
- Examples: `pages/UploadPage.tsx`, `api/client.ts`, `App.tsx`
- `snake_case` for all directories in Python projects
- Example structure: `backend/src/malscan/api/routes.py`
- Feature directories: `stages/`, `models/`, `schemas/`, `db/`
### Functions and Variables
- `snake_case()` for all functions, methods, and variables
- Private/internal: prefix with `_` (single underscore for internal, double for name mangling if needed)
- Examples: `_sanitize_filename()`, `_get_retry_count()`, `get_minio_client()`
- Constants: `UPPER_SNAKE_CASE` (e.g., `MAX_REQUEST_BODY_SIZE`, `DLQ_QUEUE`, `CHUNK_SIZE`)
- `camelCase()` for all functions, methods, and variables
- Private/internal: prefix with `_` in React components
- Examples: `checkHealth()`, `uploadFile()`, `getJobStatus()`
- Constants: `UPPER_SNAKE_CASE` (e.g., `MAX_SIZE`, `API_BASE_URL`)
- Unused parameters: prefix with `_` (enforced via ESLint `@typescript-eslint/no-unused-vars`)
### Types and Classes
- `PascalCase` for all classes and enum names
- Examples: `Job`, `File`, `JobStatus`, `Stage`, `StageContext`, `StageResult`
- Dataclasses use `@dataclass` decorator with PascalCase names
- SQLAlchemy models: `PascalCase` with `__tablename__` in `snake_case`
- `PascalCase` for all interfaces, types, and classes
- Examples: `JobStatus`, `UploadResponse`, `Report`, `ApiClient`
- Generic interfaces with descriptive names: `ApiError`, `JobProgress`, `FileMetadata`
- Enum-like objects: `PascalCase` keys (e.g., `status: 'queued' | 'scanning' | 'done' | 'failed'`)
### Database Models
- Table name: `__tablename__ = "jobs"` (lowercase, plural)
- Column names: `snake_case`
- Model class: `PascalCase` (e.g., `Job`, `File`)
- IDs: UUID v4 for all primary keys
- Timestamps: Always include `created_at` and `updated_at` with timezone awareness
- Relationships: Use SQLAlchemy relationships with proper forward references in quotes
## Code Style
### Formatting
- Line length: 100 characters (enforced by Black and Ruff)
- Indentation: 4 spaces
- Tool: **Black** for code formatting
- Tool: **isort** for import sorting (profile: "black")
- Tool: **Ruff** for linting with strict rules
- Line length: Not explicitly set in config but follows eslint conventions
- Indentation: 2 spaces (standard for Node.js/React)
- Type annotations: Required on function parameters and returns
- Trailing commas: Allowed in multi-line constructs
- Semicolons: Required
- Tool: **ESLint** for linting with TypeScript support
### Linting
- **E**: PEP 8 errors
- **F**: PyFlakes (undefined names, unused imports)
- **W**: PEP 8 warnings
- **I**: isort (import sorting)
- **N**: pep8-naming (naming conventions)
- **UP**: pyupgrade (modern Python syntax)
- **B**: flake8-bugbear (bug detection)
- **C4**: flake8-comprehensions
- All functions must have type hints
- No implicit `Any` types
- Missing imports can be ignored for external packages
- Extends: `eslint:recommended`, `plugin:@typescript-eslint/recommended`, `plugin:react-hooks/recommended`
- Key rules:
### Code Comments
- Complex algorithms or non-obvious logic
- Important assumptions or constraints
- Security considerations and validation logic
- TODO/FIXME items with context
- Docstring on every function/class (Python)
- JSDoc style rarely used (mostly plain comments)
- Inline comments explain `why`, not `what`
- Uses streaming to handle large files efficiently
- Calculates SHA256 hash incrementally
- Stores file in MinIO
- Creates file and job records in database
- Publishes job to RabbitMQ
- Returns job_id immediately (async processing)
## Import Organization
### Python Import Order
### TypeScript Import Order
## Error Handling
### Python Error Handling Pattern
### TypeScript Error Handling Pattern
## Logging
### Python Logging
- Job operations: `job_id`, `file_id`, `sha256`
- File operations: `filename`, `content_type`, `size`
- Stage execution: `stage_name`, `status`, `duration_ms`
- Errors: `error` (string representation), specific error codes
- `log.info()` - Normal operations: startup, file created, job status changes
- `log.error()` - Failures: initialization failed, upload failed, processing errors
- `log.warning()` - Potential issues (if used)
- `log.debug()` - Detailed traces (if used)
### Worker Logging (RabbitMQ Consumer)
## Function Design
### Python Functions
### TypeScript Functions
## Module Design
### Python Modules
### TypeScript React Modules
## Async/Await Patterns
### Python Async Pattern
### TypeScript Async Pattern
## Special Patterns
### Retry and Resilience (Python)
### Validation (Python)
### TypeScript Interface Patterns
<!-- GSD:conventions-end -->

<!-- GSD:architecture-start source:ARCHITECTURE.md -->
## Architecture

## Pattern Overview
- **Async-first design** - All components use async/await for I/O operations
- **Pipeline-based processing** - Multi-stage analysis orchestration with parallel + sequential stages
- **Message-driven** - RabbitMQ decouples frontend from worker processing
- **Cloud-native** - Kubernetes-ready with distributed storage (MinIO) and database (Supabase PostgreSQL)
- **Hierarchical analysis** - Recursive archive extraction creates sub-jobs for nested file analysis
## Layers
- Purpose: User interface for file upload, job tracking, and report viewing
- Location: `frontend/src/`
- Contains: React components for three main pages (Upload, Job Status, Report), API client
- Depends on: Backend API via HTTP/SSE
- Used by: End users in GitHub Pages (static deployment)
- Purpose: HTTP request handler, job orchestration, database management, file storage coordination
- Location: `backend/src/malscan/`
- Contains: Routes, models, schemas, configuration, database session management
- Depends on: PostgreSQL (Supabase), RabbitMQ, MinIO
- Used by: Frontend, Worker (indirectly via database)
- Purpose: Process queued jobs, execute analysis stages, generate reports
- Location: `worker/src/malscan_worker/`
- Contains: RabbitMQ consumer, pipeline orchestrator, analysis stages, job submission for sub-jobs
- Depends on: PostgreSQL, MinIO, RabbitMQ, ClamAV CLI, YARA CLI
- Used by: Triggered by RabbitMQ messages from backend
- PostgreSQL (Supabase): Persistent job state, file metadata, analysis results
- RabbitMQ: Job queue with dead-letter queue (DLQ) for failed messages
- MinIO: File storage with 1-day lifecycle expiration
- ClamAV: Antivirus scanning via CLI
- YARA: Pattern matching against rule files
## Data Flow
- **Job State Machine**: QUEUED → SCANNING → DONE (or FAILED at any point)
- **Database as source of truth**: All state persisted in PostgreSQL
- **Async updates**: Worker updates Job.current_stage, Job.stages_done during pipeline
- **Result storage**: Analysis findings stored as JSONB in Job.result for complex nested data
- **Parent-child relationships**: Jobs reference parent_job_id for hierarchical tracking
## Key Abstractions
- Purpose: Encapsulate analysis logic into pluggable units
- Examples: `ClamAVStage`, `YaraStage`, `ArchiveExtractStage` in `worker/src/malscan_worker/stages/`
- Pattern: Each stage implements `async execute(ctx: StageContext) → StageResult`
- Stages are either read-only (FileType, ClamAV, YARA, IOC) or mutating (ArchiveExtract, Sandbox)
- Purpose: Pass job data and dependencies through pipeline without mutation
- Contains: job_id, file_id, storage_key, sha256, original_filename, file_path, previous_results, db session
- Pattern: Created once per pipeline run, enriched as stages execute, never modified by individual stages
- Purpose: Capture outcomes from individual stages uniformly
- Contains: stage_name, status (ok/failed/skipped), timings, findings dict, artifacts list, error message
- Pattern: Immutable dataclass, collects results from all stages for final report building
- Purpose: Centralized API communication with error handling and type safety
- Location: `frontend/src/api/client.ts`
- Pattern: Singleton instance wraps all backend HTTP calls, provides typed interfaces
- Purpose: Submit recursive sub-jobs from ArchiveExtractStage safely with dedicated MQ connection
- Location: `worker/src/malscan_worker/utils/submission.py`
- Pattern: Singleton with lazy-initialized RabbitMQ connection, avoids async context pollution
## Entry Points
- Location: `frontend/src/main.tsx`
- Triggers: User opens GitHub Pages URL
- Responsibilities: Mounts React app, initializes router (BrowserRouter with GitHub Pages basename)
- Location: `backend/src/malscan/main.py`
- Triggers: Container startup or `poetry run uvicorn malscan.main:app`
- Responsibilities: Initializes FastAPI app, sets up CORS, initializes RabbitMQ and MinIO, auto-creates database tables
- Location: `worker/src/malscan_worker/main.py`
- Triggers: Container startup or `poetry run python -m malscan_worker.main`
- Responsibilities: Initializes InternalJobSubmitter, starts RabbitMQ consumer, metrics server, handles SIGTERM/SIGINT
- `POST /api/v1/files`: Upload file for analysis
- `GET /api/v1/jobs/{job_id}`: Get job status JSON
- `GET /api/v1/jobs/{job_id}/stream`: Stream job updates via SSE
- `GET /api/v1/reports/{job_id}`: Get completed analysis report
- `GET /health`: Health check endpoint
- `GET /ready`: Readiness check endpoint (TODO: checks all backends)
## Error Handling
- File too large → 400 with FILE_TOO_LARGE error code
- MinIO upload fails → 500 with STORAGE_ERROR, job marked as FAILED
- RabbitMQ publish fails → 503 with QUEUE_PUBLISH_FAILED, job marked as FAILED
- Sanitization failures caught → defaults to "unnamed" filename
- Stage timeout (300s default) → Stage marked "failed", error captured, pipeline continues
- File download fails → Job marked FAILED with error message, cleanup triggered
- Archive extract fails → Stage marked "failed", parent job continues, sub-jobs not created
- Database failures → AsyncSession context ensures rollback on exception
- Max retries exceeded (3 attempts) → Message routed to DLQ (malscan-dlq)
- Processing crashes → Message requeued with exponential backoff via x-death header
- Connection loss → Automatic reconnect via aio_pika.connect_robust()
- RabbitMQ DLQ with x-death tracking: Message gets 3 attempts before DLQ
- Backend publish uses tenacity with exponential backoff (max 5 attempts)
- Worker consumer retries max 3 times before DLQ routing
- Sub-job submission uses separate MQ connection with robust reconnection
## Cross-Cutting Concerns
- Framework: structlog with JSON renderer
- Pattern: All logs emitted as JSON via `structlog.get_logger()`
- Fields: job_id, file_id, stage_name, status, error, duration_ms, timings
- Locations: `backend/src/malscan/main.py`, `worker/src/malscan_worker/main.py`
- Frontend: OpenAPI schema validation in FastAPI (Pydantic models)
- Backend: Request validation with custom sanitization (`_sanitize_filename`)
- Database: SQLAlchemy constraints (unique indexes, foreign keys, not null)
- Worker: Stage-level validation (file exists, format supported, depth limits)
- Current: None (public API)
- CORS: Configurable via `cors_origins` setting (default "*" in dev, should restrict in production)
- Deployment: GitHub Pages static frontend, no auth needed
- Backend: FastAPI handles async requests with uvicorn workers
- Worker: asyncio.gather() for parallel stages, sequential lock via single AsyncSession
- Database: asyncpg async driver with connection pooling
- RabbitMQ: aio_pika with connection robustness and automatic heartbeat
- Worker: Prometheus metrics (stage_latency, job_total, worker_active_jobs)
- Metrics server: Runs on separate port (default 8001)
- Pattern: `prometheus_fastapi_instrumentator` for backend (optional)
<!-- GSD:architecture-end -->

<!-- GSD:workflow-start source:GSD defaults -->
## GSD Workflow Enforcement

Before using Edit, Write, or other file-changing tools, start work through a GSD command so planning artifacts and execution context stay in sync.

Use these entry points:
- `/gsd-quick` for small fixes, doc updates, and ad-hoc tasks
- `/gsd-debug` for investigation and bug fixing
- `/gsd-execute-phase` for planned phase work

Do not make direct repo edits outside a GSD workflow unless the user explicitly asks to bypass it.
<!-- GSD:workflow-end -->



<!-- GSD:profile-start -->
## Developer Profile

> Profile not yet configured. Run `/gsd-profile-user` to generate your developer profile.
> This section is managed by `generate-claude-profile` -- do not edit manually.
<!-- GSD:profile-end -->
