# Roadmap: MalScanWorker Go Ingestion Layer

## Overview

This roadmap delivers a high-performance Go microservice that replaces the Python/FastAPI file upload endpoint. The journey follows the data flow: first wire up infrastructure and configuration (Phase 1), then build file streaming and MinIO storage (Phase 2), then add database persistence and message queue publishing (Phase 3), then verify API contract compatibility and add production resilience (Phase 4), and finally deploy alongside the existing Python backend with proxy routing and Kubernetes manifests (Phase 5). At completion, `POST /api/v1/files` is handled by Go while the frontend sees zero changes.

## Phases

**Phase Numbering:**
- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order.

- [ ] **Phase 1: Foundation & Infrastructure Wiring** - Go module, config, logging, health check, Docker, backend connectivity
- [ ] **Phase 2: File Streaming & Storage** - Multipart streaming, SHA256 hashing, size validation, MinIO upload
- [ ] **Phase 3: Database, Dedup & Message Queue** - Atomic record creation, deduplication, RabbitMQ publish with retry
- [ ] **Phase 4: API Contract & Production Readiness** - Response format compliance, CORS, graceful shutdown
- [ ] **Phase 5: Integration & Deployment** - Nginx proxy routing, Kubernetes manifests

## Phase Details

### Phase 1: Foundation & Infrastructure Wiring
**Goal**: Go service builds, runs in Docker Compose alongside existing services, connects to all backends, and serves health checks with structured JSON logging
**Depends on**: Nothing (first phase)
**Requirements**: OPS-03, DB-07, DB-06, OPS-02, OPS-01, OPS-05, OPS-06, STORE-02
**Success Criteria** (what must be TRUE):
  1. `go build` produces a static binary and `docker compose up ingest` starts the Go service successfully alongside existing api, worker, and infrastructure services
  2. `GET /healthz` returns HTTP 200, confirming the service is alive and reachable on its configured port
  3. Service logs are JSON-formatted with `level`, `msg`, `time` fields visible in `docker compose logs ingest`
  4. Service reads all configuration from environment variables (`DATABASE_URL`, `MINIO_*`, `RABBITMQ_URL`, `CORS_ORIGINS`, `MAX_FILE_SIZE`, `PORT`, etc.) and successfully connects to PostgreSQL (pooled via pgxpool), MinIO, and RabbitMQ on startup — no hardcoded values
  5. MinIO `uploads` bucket exists after service startup (auto-created with 1-day lifecycle expiration policy if missing)
**Plans:** 3 plans

Plans:
- [x] 01-01-PLAN.md — Go module init, config parsing, structured logging, main.go skeleton
- [x] 01-02-PLAN.md — Backend connections (pgxpool, MinIO, RabbitMQ), health endpoint, tests
- [x] 01-03-PLAN.md — Multi-stage Dockerfile, Docker Compose service entry

### Phase 2: File Streaming & Storage
**Goal**: Files can be streamed into the service, incrementally hashed, validated for size and filename, and stored in MinIO — all without buffering entire files in memory
**Depends on**: Phase 1
**Requirements**: UPLOAD-01, UPLOAD-02, UPLOAD-03, UPLOAD-04, UPLOAD-05, UPLOAD-06, STORE-01
**Success Criteria** (what must be TRUE):
  1. A multipart file upload is streamed in chunks via `MultipartReader` — SHA256 hash is computed incrementally during streaming and the correct hash appears in MinIO as the object key
  2. Uploads exceeding the configurable size limit (default 100MB) are rejected mid-stream with HTTP 400 and descriptive error — the full file is never stored
  3. Request bodies exceeding 150MB are aborted at the HTTP layer before multipart parsing begins
  4. Filenames containing path separators, null bytes, or exceeding 255 characters are sanitized; empty filenames default to "unnamed"
  5. The uploaded file exists in MinIO keyed by SHA256 hash with correct content-type metadata; temp files are cleaned up on all code paths (success, error, panic)
**Plans:** 2 plans

Plans:
- [x] 02-01-PLAN.md — Filename sanitization + error response helpers (TDD)
- [x] 02-02-PLAN.md — Streaming upload handler, MinIO upload, router wiring

### Phase 3: Database, Dedup & Message Queue
**Goal**: Complete upload pipeline — file and job records created atomically in PostgreSQL, duplicate files handled safely under concurrency, and job messages published to RabbitMQ with retry and failure handling
**Depends on**: Phase 2
**Requirements**: STORE-03, DB-01, DB-02, DB-03, DB-04, DB-05, MQ-01, MQ-02, MQ-03, MQ-04
**Success Criteria** (what must be TRUE):
  1. Each upload creates a `File` record and a `Job` record (status "queued") in a single PostgreSQL transaction — if Job creation fails, the File insert rolls back
  2. Uploading a file with an already-known SHA256 skips MinIO re-upload, reuses the existing File record, and creates only a new Job; two simultaneous uploads of the same file both succeed without constraint violations
  3. If `parent_job_id` is provided, the parent job is validated and recursion depth is checked against max (default 3) — HTTP 400 returned for invalid parent or exceeded depth
  4. A persistent JSON message is published to `malscan.jobs` queue with exact fields the Python worker expects (`job_id`, `file_id`, `storage_key`, `sha256`, `original_filename`)
  5. If RabbitMQ publish fails after 5 retries with exponential backoff (1s→2s→4s→8s→16s), the job status is updated to "failed" in DB and the request returns HTTP 503
**Plans:** 3 plans

Plans:
- [x] 03-01-PLAN.md — Database store package: File/Job CRUD, SHA256 dedup, parent validation (TDD)
- [x] 03-02-PLAN.md — RabbitMQ publisher: queue declaration, persistent publish, exponential backoff retry (TDD)
- [x] 03-03-PLAN.md — Integration: wire Store + Publisher into upload handler and main.go

### Phase 4: API Contract & Production Readiness
**Goal**: API responses are format-compatible with the Python endpoint so the frontend works without changes, CORS allows frontend access, and the service shuts down gracefully without dropping in-flight uploads
**Depends on**: Phase 3
**Requirements**: API-01, API-02, API-03, API-04, OPS-04
**Success Criteria** (what must be TRUE):
  1. Successful upload returns HTTP 201 with JSON body `{"job_id", "file_id", "sha256", "status": "queued", "created_at"}` matching the Python `UploadResponse` schema exactly (field names, types, timestamp format)
  2. All error paths return the envelope format `{"error": {"code": "ERROR_CODE", "message": "...", "details": {...}}}` with correct HTTP status codes: 400 (validation/size/depth), 422 (missing file field), 500 (storage/DB), 503 (queue unavailable)
  3. CORS middleware allows requests from configured frontend origins (via `CORS_ORIGINS` env var) with appropriate headers for multipart uploads
  4. On SIGTERM/SIGINT, the service stops accepting new connections, drains in-flight uploads to completion (within configurable timeout), then closes DB pool and RabbitMQ connection cleanly
**Plans:** 3 plans

Plans:
- [x] 04-01-PLAN.md — Typed UploadResponse struct, error code audit & MaxBytesError handling
- [x] 04-02-PLAN.md — CORS middleware (go-chi/cors) matching Python FastAPI config
- [x] 04-03-PLAN.md — Configurable graceful shutdown timeout

### Phase 5: Integration & Deployment
**Goal**: Go ingest service runs alongside the existing FastAPI backend in production with transparent proxy routing and Kubernetes deployment manifests
**Depends on**: Phase 4
**Requirements**: DEPLOY-01, DEPLOY-02
**Success Criteria** (what must be TRUE):
  1. Nginx reverse proxy routes `POST /api/v1/files` to the Go ingest service and all other API paths to the FastAPI backend — the frontend uploads files through the Go service without any code or configuration changes
  2. Kubernetes manifests in `k8s/ingest/` define a Deployment and Service with liveness probe on `/healthz`, resource requests/limits, and security context (runAsNonRoot, readOnlyRootFilesystem)
**Plans**: TBD

## Progress

**Execution Order:**
Phases execute in numeric order: 1 → 2 → 3 → 4 → 5

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Foundation & Infrastructure Wiring | 3/3 | Complete | 2026-03-27 |
| 2. File Streaming & Storage | 2/2 | Complete | 2026-03-27 |
| 3. Database, Dedup & Message Queue | 3/3 | Complete | 2026-03-27 |
| 4. API Contract & Production Readiness | 1/3 | In progress | - |
| 5. Integration & Deployment | 0/TBD | Not started | - |
