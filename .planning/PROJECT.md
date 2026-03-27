# MalScanWorker — Go Ingestion Layer

## What This Is

A high-performance Go microservice that replaces the Python/FastAPI file upload endpoint in the MalScanWorker malware analysis pipeline. The service handles multipart file streaming, SHA256 hashing, MinIO object upload, PostgreSQL record creation, and RabbitMQ job publishing — all with native Go concurrency to support 10–50 simultaneous uploads with lower latency and higher throughput than the current Python implementation.

## Core Value

Fast, reliable file ingestion that never drops uploads under concurrent load — the gateway through which every malware sample enters the analysis pipeline.

## Requirements

### Validated

<!-- Existing capabilities inferred from codebase — these must be preserved. -->

- ✓ Multipart file upload streaming with 1MB chunked reads — existing (`backend/src/malscan/api/routes.py`)
- ✓ Filename sanitization (path traversal defense, null-byte removal, 255-char limit) — existing
- ✓ Streaming SHA256 hash computation during upload — existing
- ✓ File size enforcement with per-chunk validation (configurable max, default 100MB) — existing
- ✓ MinIO object upload keyed by SHA256 hash — existing (`backend/src/malscan/storage.py`)
- ✓ SHA256-based file deduplication in PostgreSQL (skip MinIO re-upload for known files) — existing
- ✓ File record creation (UUID PK, sha256, size, filename, content_type, created_at) — existing
- ✓ Job record creation (UUID PK, file_id FK, status=QUEUED, stages_total, depth, parent_job_id) — existing
- ✓ Atomic DB transaction (File + Job committed together) — existing
- ✓ RabbitMQ persistent message publishing to `malscan.jobs` queue — existing (`backend/src/malscan/queue.py`)
- ✓ Retry with exponential backoff on RabbitMQ publish failure (5 attempts, 1–16s) — existing
- ✓ Job marked FAILED in DB if RabbitMQ publish fails after retries — existing
- ✓ Hierarchical job support (parent_job_id + depth for recursive archive analysis) — existing
- ✓ JSON structured logging (structlog-compatible format) — existing
- ✓ Temp file cleanup on failure/completion — existing
- ✓ CORS support for frontend origins — existing
- ✓ Request body limit enforcement (150MB) — existing

### Active

<!-- New capabilities for the Go ingestion service. -->

- [ ] Go microservice implementing `POST /api/v1/files` with identical API contract (request/response schema)
- [ ] Native Go concurrency (goroutines) for 10–50 simultaneous uploads
- [x] Direct PostgreSQL writes using the exact existing `files` and `jobs` table schema — Validated in Phase 3
- [x] Direct RabbitMQ AMQP publishing (no Python intermediary) — Validated in Phase 3
- [x] Direct MinIO S3 upload via Go SDK — Validated in Phase 2
- [x] Streaming multipart processing without full file buffering in memory — Validated in Phase 2
- [x] Configuration via environment variables (same vars as current backend: `DATABASE_URL`, `MINIO_*`, `RABBITMQ_URL`, etc.) — Validated in Phase 1
- [x] Health check endpoint (`GET /healthz`) for Kubernetes liveness/readiness probes — Validated in Phase 1
- [x] Dockerfile for containerized deployment (multi-stage build, minimal image) — Validated in Phase 1
- [x] Docker Compose service entry alongside existing backend/worker/infra services — Validated in Phase 1
- [ ] Kubernetes manifests (Deployment, Service) in `k8s/` directory
- [ ] Nginx/proxy routing so frontend hits Go service for uploads, FastAPI for everything else
- [ ] Graceful shutdown with in-flight upload draining
- [ ] Prometheus metrics endpoint for upload throughput, latency, error rates

### Out of Scope

- Worker/consumer rewrite — stays Python, not part of this milestone
- Job status endpoints (`GET /api/v1/jobs/*`) — stays in FastAPI
- Report endpoints (`GET /api/v1/reports/*`) — stays in FastAPI
- SSE streaming for job progress — stays in FastAPI
- Frontend changes — same API contract, no UI work needed
- Database schema migration — using exact existing tables
- Archive extraction / sub-job submission — stays in Python worker
- Authentication/authorization — none currently exists, not adding now
- Rate limiting — not in scope for v1
- Go-based worker consumer — only the upload path moves to Go

## Context

**Existing Architecture:**
The current system is a distributed malware analysis pipeline: React frontend → FastAPI backend → RabbitMQ → Python worker (ClamAV + YARA + archive extraction). The upload endpoint in `backend/src/malscan/api/routes.py` handles the full ingestion pipeline in a single ~200-line async function.

**Why Go:**
The Python upload path uses `asyncio` with a 4-worker `ThreadPoolExecutor` for MinIO uploads. Under concurrent load (>4 simultaneous uploads), MinIO operations queue up. SHA256 hashing runs in the async event loop (CPU-bound work blocking the event loop). Go's goroutines provide true parallelism for I/O-heavy workloads without thread pool limits.

**Integration Pattern:**
The Go service runs as a standalone microservice. An Nginx reverse proxy (or similar) routes `POST /api/v1/files` to the Go service and all other paths to the existing FastAPI backend. The frontend sees the same API — no changes required.

**Database Schema (must match exactly):**
- `files` table: `id` (UUID4 PK), `sha256` (VARCHAR 64, unique index), `size` (INTEGER), `filename` (VARCHAR 255), `content_type` (VARCHAR 100), `created_at` (TIMESTAMPTZ)
- `jobs` table: `id` (UUID4 PK), `file_id` (UUID FK→files.id), `status` (VARCHAR 20, default "queued"), `current_stage` (VARCHAR 50, nullable), `stages_done` (INTEGER, default 0), `stages_total` (INTEGER, default 5), `error_message` (TEXT, nullable), `result` (JSONB, nullable), `created_at` (TIMESTAMPTZ), `updated_at` (TIMESTAMPTZ), `parent_job_id` (UUID FK→jobs.id, nullable), `depth` (INTEGER, default 0), `total_sub` (INTEGER, default 0), `completed_sub` (INTEGER, default 0), `malicious_sub` (INTEGER, default 0)

**Infrastructure:**
- PostgreSQL 13+ (Supabase, connection via `DATABASE_URL` with `asyncpg` format — Go will use `pgx` driver)
- MinIO (S3-compatible, `MINIO_ENDPOINT` / `MINIO_ACCESS_KEY` / `MINIO_SECRET_KEY`)
- RabbitMQ 3.x (`RABBITMQ_URL` as `amqp://` URI)
- Docker Compose for local dev, k3s Kubernetes for production

## Constraints

- **Schema compatibility**: Must write to existing `files` and `jobs` tables with exact column types and defaults — Python worker and FastAPI backend read from these same tables
- **API contract**: `POST /api/v1/files` request/response format must be identical to current Python endpoint — frontend must work without changes
- **Infrastructure**: Must connect to the same PostgreSQL, MinIO, and RabbitMQ instances used by existing services
- **Deployment**: Must coexist with existing Python backend (not replace it entirely) — routing splits at proxy layer
- **Message format**: RabbitMQ messages must match the JSON format the Python worker consumer expects (`job_id`, `file_id`, etc.)

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Go over Rust | Simpler concurrency model (goroutines), richer ecosystem for network services (MinIO SDK, pgx, amqp091-go), faster development cycle | — Pending |
| Standalone microservice over direct replacement | FastAPI still needed for job status, reports, SSE — splitting at proxy layer is cleanest | — Pending |
| Same DB schema, no migrations | Worker and existing backend must read the same data — schema changes would require coordinated multi-service migration | — Pending |
| Proxy routing (Nginx) | Frontend unchanged, routing is transparent — Go service only handles the upload path | — Pending |

## Evolution

This document evolves at phase transitions and milestone boundaries.

**After each phase transition** (via `/gsd-transition`):
1. Requirements invalidated? → Move to Out of Scope with reason
2. Requirements validated? → Move to Validated with phase reference
3. New requirements emerged? → Add to Active
4. Decisions to log? → Add to Key Decisions
5. "What This Is" still accurate? → Update if drifted

**After each milestone** (via `/gsd-complete-milestone`):
1. Full review of all sections
2. Core Value check — still the right priority?
3. Audit Out of Scope — reasons still valid?
4. Update Context with current state

---
*Last updated: 2026-03-27 after Phase 3 completion*
