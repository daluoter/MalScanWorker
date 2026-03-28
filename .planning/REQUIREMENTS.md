# Requirements: MalScanWorker Go Ingestion Layer

**Version:** v1.0
**Created:** 2026-03-27
**Status:** Active

## v1 Requirements

### Core Upload Pipeline

- [ ] **UPLOAD-01**: Go service accepts `POST /api/v1/files` multipart uploads, streaming file data in chunks without buffering the entire file in memory
- [ ] **UPLOAD-02**: SHA256 hash is computed incrementally during file streaming (via `io.TeeReader`) and returned in the response
- [ ] **UPLOAD-03**: File size is enforced per-chunk during streaming, rejecting with HTTP 400 and `FILE_TOO_LARGE` error code when configurable max (default 100MB) is exceeded
- [ ] **UPLOAD-04**: Request body limit enforced at HTTP level (150MB via `http.MaxBytesReader`) to abort oversized requests early
- [ ] **UPLOAD-05**: Filename sanitization strips path separators (`/`, `\`), null bytes, truncates to 255 chars, and falls back to "unnamed" — matching `_sanitize_filename()` behavior in `backend/src/malscan/api/routes.py`
- [ ] **UPLOAD-06**: Uploaded file is streamed to a temp file on disk, with `defer os.Remove()` cleanup on all code paths (success, error, panic)

### Storage Integration

- [ ] **STORE-01**: File is uploaded to MinIO using SHA256 hash as the object key in the `uploads` bucket, preserving the content-type metadata
- [x] **STORE-02**: On startup, Go service creates the MinIO `uploads` bucket if it doesn't exist and sets a 1-day lifecycle expiration policy
- [ ] **STORE-03**: Before uploading to MinIO, Go service checks PostgreSQL `files` table for existing SHA256 — skips MinIO upload and reuses existing `File` record for duplicates, creates new `Job` against existing file

### Database Operations

- [ ] **DB-01**: `File` record created in `files` table with exact schema: `id` (UUID4 PK), `sha256` (VARCHAR 64, unique), `size` (INTEGER), `filename` (VARCHAR 255), `content_type` (VARCHAR 100), `created_at` (TIMESTAMPTZ, UTC)
- [ ] **DB-02**: `Job` record created in `jobs` table with exact schema: `id` (UUID4 PK), `file_id` (FK→files.id), `status` ("queued"), `stages_total` (configurable, default 5), `depth` (0 or parent+1), `parent_job_id` (nullable UUID FK), plus counter fields defaulting to 0
- [ ] **DB-03**: File and Job records are inserted in a single PostgreSQL transaction — if Job creation fails, File insert rolls back
- [ ] **DB-04**: File deduplication uses `INSERT ... ON CONFLICT (sha256) DO NOTHING` + `SELECT` to handle concurrent uploads of identical files safely (race condition prevention)
- [ ] **DB-05**: If `parent_job_id` is provided, Go service validates the parent job exists and checks recursion depth against max (default 3), returning HTTP 400 if invalid or exceeded
- [x] **DB-06**: PostgreSQL connection pool via `pgxpool` configured for 10–50 concurrent uploads (`MaxConns`, `MinConns`, `MaxConnLifetime` tunable via env vars)
- [x] **DB-07**: `DATABASE_URL` parsing strips the `+asyncpg` dialect prefix from the shared env var (converting `postgresql+asyncpg://` to `postgresql://` for pgx compatibility)

### Message Queue

- [ ] **MQ-01**: Job message published to `malscan.jobs` RabbitMQ queue with `DeliveryMode=Persistent`, JSON body containing `job_id`, `file_id`, `storage_key` (SHA256), `sha256`, and `original_filename`
- [ ] **MQ-02**: Queue declared at startup with `durable=true` and dead-letter exchange arguments matching existing Python configuration (`x-dead-letter-exchange: ""`, `x-dead-letter-routing-key: "malscan-dlq"`)
- [ ] **MQ-03**: RabbitMQ publish retries up to 5 times with exponential backoff (1s→2s→4s→8s→16s), logging each retry attempt
- [ ] **MQ-04**: If all RabbitMQ retries fail, job status is updated to "failed" with error message in DB, and HTTP 503 with `QUEUE_PUBLISH_FAILED` error code is returned

### API Contract

- [x] **API-01**: Success response is HTTP 201 with JSON body `{"job_id": "uuid", "file_id": "uuid", "sha256": "hex", "status": "queued", "created_at": "ISO8601"}` — matching `UploadResponse` schema in `backend/src/malscan/schemas/requests.py`
- [x] **API-02**: Error responses use envelope format `{"error": {"code": "ERROR_CODE", "message": "...", "details": {...}}}` — matching `ApiErrorResponse` schema
- [x] **API-03**: HTTP status codes match existing endpoint: 201 (success), 400 (validation/size/depth), 422 (missing file field), 500 (storage/DB error), 503 (queue unavailable)
- [x] **API-04**: CORS middleware supports configurable allowed origins via `CORS_ORIGINS` env var, matching current FastAPI CORS configuration

### Operations & Deployment

- [x] **OPS-01**: `GET /healthz` endpoint returns HTTP 200 when service is alive, for Kubernetes liveness probes
- [x] **OPS-02**: JSON structured logging via `log/slog` with fields: `job_id`, `file_id`, `sha256`, `duration_ms`, `error`, `level`, `msg`, `time` — parseable by existing log aggregation
- [x] **OPS-03**: All configuration via environment variables: `DATABASE_URL`, `MINIO_ENDPOINT`, `MINIO_ACCESS_KEY`, `MINIO_SECRET_KEY`, `MINIO_SECURE`, `RABBITMQ_URL`, `CORS_ORIGINS`, `MAX_FILE_SIZE`, `STAGES_TOTAL`, `LOG_LEVEL`, `PORT`
- [x] **OPS-04**: Graceful shutdown on SIGTERM/SIGINT — drains in-flight uploads, closes DB pool and RabbitMQ connection, respects configurable shutdown timeout
- [x] **OPS-05**: Multi-stage Dockerfile (`golang:alpine` → `alpine`) producing minimal static binary image (~15MB)
- [x] **OPS-06**: Docker Compose service entry for `ingest` alongside existing `api`, `worker`, and infrastructure services

### Integration & Deployment

- [x] **DEPLOY-01**: Nginx (or equivalent) reverse proxy config routing `POST /api/v1/files` to Go ingest service and all other paths to FastAPI backend
- [x] **DEPLOY-02**: Kubernetes manifests in `k8s/ingest/` — Deployment, Service, with liveness probe on `/healthz`, resource limits, and security context

## v2 Requirements (Deferred)

- [ ] **V2-METRICS-01**: Prometheus metrics endpoint (`/metrics`) with upload count, latency histogram, error rate, in-flight gauge, bytes uploaded counter
- [ ] **V2-READY-01**: Readiness probe (`/readyz`) that checks PostgreSQL, MinIO, and RabbitMQ connectivity with 5s result caching
- [ ] **V2-STREAM-01**: Streaming MinIO upload via `io.Pipe` — pipe multipart directly to MinIO without temp file (eliminates disk I/O, halves latency for large files)
- [ ] **V2-HEALTH-01**: Connection health monitoring with proactive reconnection for PostgreSQL and RabbitMQ
- [ ] **V2-TIMEOUT-01**: Per-upload timeout enforcement to abort stalled uploads (slow clients)
- [ ] **V2-CONTEXT-01**: Request-scoped structured logging context with `X-Request-Id` header propagation
- [ ] **V2-RECONNECT-01**: RabbitMQ auto-reconnection wrapper (amqp091-go lacks built-in reconnect unlike Python's `aio_pika.connect_robust`)

## Out of Scope

- **Worker/consumer rewrite** — stays Python, not part of this milestone
- **Job status endpoints** (`GET /api/v1/jobs/*`) — stays in FastAPI
- **Report endpoints** (`GET /api/v1/reports/*`) — stays in FastAPI
- **SSE streaming** — stays in FastAPI
- **Frontend changes** — same API contract, no UI work
- **Database schema migration** — Go is a schema consumer, not creator
- **Authentication/authorization** — none exists today, add uniformly later
- **Rate limiting** — defer to proxy layer or future milestone
- **File content pre-scanning** — analysis stays in worker pipeline
- **Auto-create DB tables** — Python backend owns schema creation
- **WebSocket support** — no requirement exists

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| UPLOAD-01 | Phase 2 | Pending |
| UPLOAD-02 | Phase 2 | Pending |
| UPLOAD-03 | Phase 2 | Pending |
| UPLOAD-04 | Phase 2 | Pending |
| UPLOAD-05 | Phase 2 | Pending |
| UPLOAD-06 | Phase 2 | Pending |
| STORE-01 | Phase 2 | Pending |
| STORE-02 | Phase 1 | Complete |
| STORE-03 | Phase 3 | Pending |
| DB-01 | Phase 3 | Pending |
| DB-02 | Phase 3 | Pending |
| DB-03 | Phase 3 | Pending |
| DB-04 | Phase 3 | Pending |
| DB-05 | Phase 3 | Pending |
| DB-06 | Phase 1 | Complete |
| DB-07 | Phase 1 | Complete |
| MQ-01 | Phase 3 | Pending |
| MQ-02 | Phase 3 | Pending |
| MQ-03 | Phase 3 | Pending |
| MQ-04 | Phase 3 | Pending |
| API-01 | Phase 4 | Complete |
| API-02 | Phase 4 | Complete |
| API-03 | Phase 4 | Complete |
| API-04 | Phase 4 | Complete |
| OPS-01 | Phase 1 | Complete |
| OPS-02 | Phase 1 | Complete |
| OPS-03 | Phase 1 | Complete |
| OPS-04 | Phase 4 | Complete |
| OPS-05 | Phase 1 | Complete |
| OPS-06 | Phase 1 | Complete |
| DEPLOY-01 | Phase 5 | Complete |
| DEPLOY-02 | Phase 5 | Complete |

---
*Generated: 2026-03-27*
