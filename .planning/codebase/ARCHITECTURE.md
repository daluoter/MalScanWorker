# Architecture

**Analysis Date:** 2025-03-27

## Pattern Overview

**Overall:** Distributed asynchronous malware analysis pipeline with microservices architecture.

**Key Characteristics:**
- **Async-first design** - All components use async/await for I/O operations
- **Pipeline-based processing** - Multi-stage analysis orchestration with parallel + sequential stages
- **Message-driven** - RabbitMQ decouples frontend from worker processing
- **Cloud-native** - Kubernetes-ready with distributed storage (MinIO) and database (Supabase PostgreSQL)
- **Hierarchical analysis** - Recursive archive extraction creates sub-jobs for nested file analysis

## Layers

**Frontend (React/TypeScript):**
- Purpose: User interface for file upload, job tracking, and report viewing
- Location: `frontend/src/`
- Contains: React components for three main pages (Upload, Job Status, Report), API client
- Depends on: Backend API via HTTP/SSE
- Used by: End users in GitHub Pages (static deployment)

**Backend API (FastAPI/Python):**
- Purpose: HTTP request handler, job orchestration, database management, file storage coordination
- Location: `backend/src/malscan/`
- Contains: Routes, models, schemas, configuration, database session management
- Depends on: PostgreSQL (Supabase), RabbitMQ, MinIO
- Used by: Frontend, Worker (indirectly via database)

**Worker/Consumer (Python):**
- Purpose: Process queued jobs, execute analysis stages, generate reports
- Location: `worker/src/malscan_worker/`
- Contains: RabbitMQ consumer, pipeline orchestrator, analysis stages, job submission for sub-jobs
- Depends on: PostgreSQL, MinIO, RabbitMQ, ClamAV CLI, YARA CLI
- Used by: Triggered by RabbitMQ messages from backend

**Infrastructure Services:**
- PostgreSQL (Supabase): Persistent job state, file metadata, analysis results
- RabbitMQ: Job queue with dead-letter queue (DLQ) for failed messages
- MinIO: File storage with 1-day lifecycle expiration
- ClamAV: Antivirus scanning via CLI
- YARA: Pattern matching against rule files

## Data Flow

**File Upload Analysis Request:**

1. User uploads file via `/api/v1/files` (streaming multipart)
2. Backend sanitizes filename, streams to temp file, calculates SHA256 hash
3. Backend uploads file to MinIO with hash as key
4. Backend creates `File` record (SHA256 deduplicated) in PostgreSQL
5. Backend creates `Job` record with status=QUEUED in PostgreSQL
6. Backend publishes job message to RabbitMQ queue
7. Returns `job_id` to frontend immediately

**Job Processing Pipeline:**

1. Worker consumes message from RabbitMQ queue
2. Worker downloads file from MinIO to `/tmp/{job_id}/`
3. Worker creates `StageContext` with job metadata and DB session
4. **Parallel Stage Execution** (static analysis):
   - `FileTypeStage`: Identifies MIME type, file size
   - `ClamAVStage`: Runs clamscan CLI, detects viruses
   - `YaraStage`: Applies YARA rules, captures rule matches
   - `IocExtractStage`: Extracts IOCs (URLs, domains, IPs, hashes)
5. **Sequential Stage Execution** (dynamic analysis):
   - `ArchiveExtractStage`: Detects archive format, extracts contents, creates sub-jobs recursively
   - `SandboxStage`: Executes file (or mock sandbox), captures behaviors/network
6. Worker builds complete analysis result from all stage findings
7. Worker determines verdict (clean/suspicious/malicious) based on findings
8. Worker stores result as JSONB in Job.result in PostgreSQL
9. Worker sets Job.status=DONE, cleans up `/tmp/{job_id}`

**Report Retrieval:**

1. Frontend polls or SSE-streams `/api/v1/jobs/{job_id}` for status updates
2. When status=DONE, frontend fetches `/api/v1/reports/{job_id}`
3. Backend queries Job with eager-loaded file and sub_jobs relationships
4. Backend returns analysis result with child job summaries

**Recursive Analysis (Sub-jobs):**

1. ArchiveExtractStage detects supported archive format
2. Stage extracts files, calculates SHA256 for each
3. For each extracted file (if not at max recursion depth):
   - Stage uploads extracted file to MinIO
   - Stage creates new File record if not exists
   - Stage creates new Job record with parent_job_id and depth+1
   - Stage publishes new job message to RabbitMQ via InternalJobSubmitter
4. Parent job tracks total_sub, completed_sub, malicious_sub counts
5. Final report includes child_jobs summary

**State Management:**

- **Job State Machine**: QUEUED → SCANNING → DONE (or FAILED at any point)
- **Database as source of truth**: All state persisted in PostgreSQL
- **Async updates**: Worker updates Job.current_stage, Job.stages_done during pipeline
- **Result storage**: Analysis findings stored as JSONB in Job.result for complex nested data
- **Parent-child relationships**: Jobs reference parent_job_id for hierarchical tracking

## Key Abstractions

**Stage (Abstract Base):**
- Purpose: Encapsulate analysis logic into pluggable units
- Examples: `ClamAVStage`, `YaraStage`, `ArchiveExtractStage` in `worker/src/malscan_worker/stages/`
- Pattern: Each stage implements `async execute(ctx: StageContext) → StageResult`
- Stages are either read-only (FileType, ClamAV, YARA, IOC) or mutating (ArchiveExtract, Sandbox)

**StageContext:**
- Purpose: Pass job data and dependencies through pipeline without mutation
- Contains: job_id, file_id, storage_key, sha256, original_filename, file_path, previous_results, db session
- Pattern: Created once per pipeline run, enriched as stages execute, never modified by individual stages

**StageResult:**
- Purpose: Capture outcomes from individual stages uniformly
- Contains: stage_name, status (ok/failed/skipped), timings, findings dict, artifacts list, error message
- Pattern: Immutable dataclass, collects results from all stages for final report building

**ApiClient (Frontend TypeScript):**
- Purpose: Centralized API communication with error handling and type safety
- Location: `frontend/src/api/client.ts`
- Pattern: Singleton instance wraps all backend HTTP calls, provides typed interfaces

**InternalJobSubmitter (Worker):**
- Purpose: Submit recursive sub-jobs from ArchiveExtractStage safely with dedicated MQ connection
- Location: `worker/src/malscan_worker/utils/submission.py`
- Pattern: Singleton with lazy-initialized RabbitMQ connection, avoids async context pollution

## Entry Points

**Frontend:**
- Location: `frontend/src/main.tsx`
- Triggers: User opens GitHub Pages URL
- Responsibilities: Mounts React app, initializes router (BrowserRouter with GitHub Pages basename)

**Backend:**
- Location: `backend/src/malscan/main.py`
- Triggers: Container startup or `poetry run uvicorn malscan.main:app`
- Responsibilities: Initializes FastAPI app, sets up CORS, initializes RabbitMQ and MinIO, auto-creates database tables

**Worker:**
- Location: `worker/src/malscan_worker/main.py`
- Triggers: Container startup or `poetry run python -m malscan_worker.main`
- Responsibilities: Initializes InternalJobSubmitter, starts RabbitMQ consumer, metrics server, handles SIGTERM/SIGINT

**Routes (Backend HTTP):**
- `POST /api/v1/files`: Upload file for analysis
- `GET /api/v1/jobs/{job_id}`: Get job status JSON
- `GET /api/v1/jobs/{job_id}/stream`: Stream job updates via SSE
- `GET /api/v1/reports/{job_id}`: Get completed analysis report
- `GET /health`: Health check endpoint
- `GET /ready`: Readiness check endpoint (TODO: checks all backends)

## Error Handling

**Strategy:** Resilience with graceful degradation

**Patterns:**

**Upload Endpoint Errors:**
- File too large → 400 with FILE_TOO_LARGE error code
- MinIO upload fails → 500 with STORAGE_ERROR, job marked as FAILED
- RabbitMQ publish fails → 503 with QUEUE_PUBLISH_FAILED, job marked as FAILED
- Sanitization failures caught → defaults to "unnamed" filename

**Pipeline Errors:**
- Stage timeout (300s default) → Stage marked "failed", error captured, pipeline continues
- File download fails → Job marked FAILED with error message, cleanup triggered
- Archive extract fails → Stage marked "failed", parent job continues, sub-jobs not created
- Database failures → AsyncSession context ensures rollback on exception

**Consumer Errors:**
- Max retries exceeded (3 attempts) → Message routed to DLQ (malscan-dlq)
- Processing crashes → Message requeued with exponential backoff via x-death header
- Connection loss → Automatic reconnect via aio_pika.connect_robust()

**Retry Mechanism:**
- RabbitMQ DLQ with x-death tracking: Message gets 3 attempts before DLQ
- Backend publish uses tenacity with exponential backoff (max 5 attempts)
- Worker consumer retries max 3 times before DLQ routing
- Sub-job submission uses separate MQ connection with robust reconnection

## Cross-Cutting Concerns

**Logging:**
- Framework: structlog with JSON renderer
- Pattern: All logs emitted as JSON via `structlog.get_logger()`
- Fields: job_id, file_id, stage_name, status, error, duration_ms, timings
- Locations: `backend/src/malscan/main.py`, `worker/src/malscan_worker/main.py`

**Validation:**
- Frontend: OpenAPI schema validation in FastAPI (Pydantic models)
- Backend: Request validation with custom sanitization (`_sanitize_filename`)
- Database: SQLAlchemy constraints (unique indexes, foreign keys, not null)
- Worker: Stage-level validation (file exists, format supported, depth limits)

**Authentication:**
- Current: None (public API)
- CORS: Configurable via `cors_origins` setting (default "*" in dev, should restrict in production)
- Deployment: GitHub Pages static frontend, no auth needed

**Concurrency:**
- Backend: FastAPI handles async requests with uvicorn workers
- Worker: asyncio.gather() for parallel stages, sequential lock via single AsyncSession
- Database: asyncpg async driver with connection pooling
- RabbitMQ: aio_pika with connection robustness and automatic heartbeat

**Metrics:**
- Worker: Prometheus metrics (stage_latency, job_total, worker_active_jobs)
- Metrics server: Runs on separate port (default 8001)
- Pattern: `prometheus_fastapi_instrumentator` for backend (optional)

---

*Architecture analysis: 2025-03-27*
