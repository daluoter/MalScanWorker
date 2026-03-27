# Feature Landscape

**Domain:** Go high-concurrency file ingestion microservice for malware analysis pipeline
**Researched:** 2025-03-27
**Confidence:** HIGH — features derived directly from existing Python codebase analysis + production file upload service patterns

## Table Stakes

Features that must exist for the Go service to function as a drop-in replacement. Missing any of these breaks the pipeline or the frontend contract.

### Core Upload Pipeline

| Feature | Why Expected | Complexity | Notes |
|---------|--------------|------------|-------|
| **Multipart streaming upload** | Existing Python endpoint streams 1MB chunks. Go must do the same — buffering 100MB files into memory is not viable | Med | Use `mime/multipart.Reader` with chunk-by-chunk reads. Go's stdlib handles this natively, unlike Python's asyncio approach |
| **Streaming SHA256 computation** | Hash computed incrementally during upload. Existing contract returns `sha256` in response. Worker uses it as storage key | Low | `crypto/sha256` + `io.TeeReader` — trivial in Go. Python does `hasher.update(chunk)` per loop iteration; Go wires the same via io plumbing |
| **File size enforcement (per-chunk)** | Existing service rejects at 100MB during stream, not after full receipt. Must abort early, not waste bandwidth | Low | Track cumulative bytes per chunk. Return 400 with `FILE_TOO_LARGE` error code when exceeded. Also enforce 150MB `http.MaxBytesReader` at request level |
| **Filename sanitization** | Path traversal defense, null-byte removal, 255-char truncation, fallback to "unnamed". Existing code in `_sanitize_filename()` | Low | Port logic directly. Strip `\` and `/` path components, remove `\x00`, truncate, fallback. Pure string manipulation |
| **Temp file streaming** | Current Python writes to `tempfile.mkstemp()`, then uploads to MinIO from path. Go must avoid holding entire file in memory | Low | `os.CreateTemp` + chunked writes. Cleanup in `defer`. Critical: ensure cleanup on all error paths |

### Storage Integration

| Feature | Why Expected | Complexity | Notes |
|---------|--------------|------------|-------|
| **MinIO upload keyed by SHA256** | Storage key = SHA256 hash. Worker downloads from MinIO using this key. Changing key format breaks the entire pipeline | Med | Use `minio-go` SDK's `PutObject`. Must match existing bucket name (`uploads`) and content-type metadata |
| **MinIO bucket auto-creation** | Python calls `init_buckets()` at startup — creates bucket if missing, sets 1-day lifecycle expiry | Low | `minio-go` `MakeBucket` + `SetBucketLifecycle`. Run once in startup sequence |
| **SHA256-based file deduplication** | If file hash already exists in `files` table, skip MinIO re-upload, reuse existing `File` record. Creates new `Job` against existing file | Med | `SELECT ... WHERE sha256 = $1` before MinIO upload. Current Python uploads first then deduplicates — Go should check **before** uploading to MinIO for efficiency. But must match behavior: Python uploads even for dupes (MinIO `put_object` is idempotent), then checks DB |

### Database Operations

| Feature | Why Expected | Complexity | Notes |
|---------|--------------|------------|-------|
| **File record creation (exact schema)** | `files` table: `id` UUID4 PK, `sha256` VARCHAR(64) unique, `size` INTEGER, `filename` VARCHAR(255), `content_type` VARCHAR(100), `created_at` TIMESTAMPTZ | Med | Use `pgx` driver. Must generate UUIDv4 in Go (`google/uuid`). Timestamps must be UTC with timezone |
| **Job record creation (exact schema)** | `jobs` table: `id` UUID4 PK, `file_id` FK→files.id, `status` "queued", `stages_total` 5, `depth` 0/N, `parent_job_id` nullable, plus all counter fields defaulting to 0 | Med | All 14 columns must be populated correctly. `current_stage` NULL, `stages_done` 0, `error_message` NULL, `result` NULL |
| **Atomic DB transaction** | File + Job committed in single transaction. If Job creation fails, File insert rolls back. Python uses SQLAlchemy `db.commit()` after both | Med | `pgx` transaction with `Begin()`/`Commit()`/`Rollback()`. `defer tx.Rollback()` pattern |
| **Parent job validation** | If `parent_job_id` provided, validate it exists, check recursion depth against max (default 3). Return 400 if invalid/exceeded | Low | SELECT parent job, check `depth >= max_depth`. Exact error messages must match current API |
| **Connection pooling** | Python uses `asyncpg` with pooling. Go must pool connections to handle concurrent uploads without exhausting PostgreSQL | Med | `pgxpool` built-in pool. Configure `MaxConns`, `MinConns`, `MaxConnLifetime`. Critical for 10–50 concurrent uploads |

### Message Queue

| Feature | Why Expected | Complexity | Notes |
|---------|--------------|------------|-------|
| **RabbitMQ persistent message publish** | Job message published to `malscan.jobs` queue with `DeliveryMode=Persistent`. DLQ configured with `x-dead-letter-exchange` and `x-dead-letter-routing-key` | Med | Use `amqp091-go`. Must declare queue with exact same arguments as Python (`durable=True`, DLQ headers). Message format: `{"job_id","file_id","storage_key","sha256","original_filename"}` |
| **Retry with exponential backoff** | 5 attempts, waits 1s→2s→4s→8s→16s. Python uses `tenacity`. Go must implement equivalent | Med | Custom retry loop or use `cenkalti/backoff`. Must log each retry attempt. Total max wait ~31s |
| **Job marked FAILED on publish failure** | If all RabbitMQ retries exhausted, update job status to "failed" with error message in DB. Return 503 with `QUEUE_PUBLISH_FAILED` | Low | `UPDATE jobs SET status='failed', error_message=$1 WHERE id=$2` after retry exhaustion. Transaction already committed at this point (Python commits before publish), so this is a separate UPDATE |
| **Queue declaration at startup** | Python declares queue on startup (idempotent). Go must do the same to ensure queue exists | Low | `channel.QueueDeclare` with matching parameters |

### API Contract Compliance

| Feature | Why Expected | Complexity | Notes |
|---------|--------------|------------|-------|
| **POST /api/v1/files identical response** | Response: `{"job_id","file_id","sha256","status":"queued","created_at":"ISO8601"}`. Frontend parses this exactly | Low | JSON struct with exact field names. `created_at` must be ISO 8601 with timezone (Go's `time.RFC3339`) |
| **Error response format matching** | Error bodies: `{"error":{"code":"FILE_TOO_LARGE","message":"...","details":{...}}}`. Frontend error handling depends on this structure | Low | Define error response struct matching `ApiErrorResponse` schema |
| **HTTP status codes matching** | 201 (success), 400 (validation), 422 (missing file), 500 (storage), 503 (queue). Frontend handles these specifically | Low | Map each error condition to exact status code from Python implementation |
| **CORS headers** | Frontend at different origin needs preflight. Current Python allows configurable origins | Low | Use Go CORS middleware (e.g., `rs/cors`). Match config: configurable origins, methods, headers |

### Operational Basics

| Feature | Why Expected | Complexity | Notes |
|---------|--------------|------------|-------|
| **Health check endpoint** | `GET /healthz` for k8s liveness probe. Returns 200 if process alive | Low | Trivial handler. Existing k8s manifests use `/health` — new service should use `/healthz` (Go convention) but also consider `/health` for consistency |
| **JSON structured logging** | Existing pipeline uses structlog JSON format. Logs must be parseable by same log aggregation | Low | Use `slog` (stdlib, Go 1.21+) with JSON handler. Fields: `job_id`, `file_id`, `sha256`, `stage`, `duration_ms`, `error` |
| **Environment variable configuration** | Same env vars: `DATABASE_URL`, `MINIO_ENDPOINT`, `MINIO_ACCESS_KEY`, `MINIO_SECRET_KEY`, `RABBITMQ_URL`, `CORS_ORIGINS`, `MAX_FILE_SIZE` | Low | Parse env vars at startup. Note: `DATABASE_URL` currently has `postgresql+asyncpg://` prefix — Go must strip/convert to `postgres://` format for `pgx` |
| **Temp file cleanup on all paths** | Python cleans up in `finally` block. Go must clean up on success, error, and panic | Low | `defer os.Remove(tmpPath)` immediately after creation. Go's defer is more reliable than Python's try/finally for this |
| **Graceful shutdown** | Drain in-flight uploads on SIGTERM. k8s sends SIGTERM before killing pod | Med | `signal.NotifyContext` + `http.Server.Shutdown()`. Must wait for active upload goroutines to complete before closing DB/MQ connections |
| **Containerized deployment** | Dockerfile for multi-stage build. Must produce minimal image for k8s | Low | `golang:1.22-alpine` → `alpine:3.19` multi-stage. Static binary, no CGO. ~15MB image vs Python's ~200MB+ |

## Differentiators

Features that make the Go service operationally excellent — not required for functional parity, but justify the rewrite.

| Feature | Value Proposition | Complexity | Notes |
|---------|-------------------|------------|-------|
| **True concurrent upload handling** | Python bottlenecks at 4 MinIO uploads (ThreadPoolExecutor). Go goroutines handle 50+ concurrent uploads without pool limits. This is the primary reason for the rewrite | Med | Each upload is a goroutine. No shared state beyond connection pools. Go's scheduler multiplexes goroutines across OS threads automatically |
| **Streaming MinIO upload via io.Pipe** | Instead of write-to-temp-file-then-upload, pipe multipart stream directly to MinIO. Eliminates disk I/O for uploads, halves latency | High | `io.Pipe` + `io.TeeReader` to simultaneously hash and upload. Complex: must handle errors on both sides of pipe. Fallback to temp file for reliability. **Consider deferring to v2** |
| **Prometheus metrics endpoint** | Upload count, latency histogram, error rate, in-flight uploads, bytes uploaded. Enables SRE-grade observability | Med | Use `prometheus/client_golang`. Expose `/metrics`. Histogram for latency, counters for success/failure/dedup, gauge for in-flight |
| **Readiness probe with backend checks** | Current Python `/ready` returns hardcoded "ready" (has a TODO). Go should actually check PostgreSQL, MinIO, RabbitMQ connectivity | Med | Ping each backend on `/readyz`. Cache result for 5s to avoid probe storms. If any backend down, return 503 — k8s stops routing traffic |
| **Request-scoped structured context** | Propagate `request_id`, `job_id`, `file_id` through all log entries for a single upload. Python logs these but manually per call | Low | `context.WithValue` + `slog` with handler that extracts context. Every log line in an upload carries the same correlation IDs |
| **Connection health monitoring** | Detect stale PostgreSQL/RabbitMQ connections before they cause upload failures. Reconnect proactively | Med | `pgxpool` has built-in health checks. For RabbitMQ `amqp091-go`, handle `NotifyClose` channel to detect disconnects and reconnect |
| **Upload timeout enforcement** | Abort uploads that stall (e.g., slow client sending 1 byte/minute). Python has no explicit timeout — relies on uvicorn defaults | Low | `http.Server.ReadTimeout` + `http.Server.WriteTimeout`. Also per-upload context with deadline |
| **Dedup-before-upload optimization** | Check SHA256 in DB before uploading to MinIO. Skip MinIO upload entirely for known files. Python uploads first, then checks — wasteful for repeated samples | Med | Requires a two-pass approach: stream to temp + hash, then check DB, then conditionally upload. Net savings for duplicate-heavy workloads (common in malware pipelines where same sample submitted multiple times) |
| **Request ID / trace propagation** | Generate or accept `X-Request-Id` header. Include in all logs and responses. Enables end-to-end tracing from frontend through proxy | Low | Middleware reads/generates UUID, sets in context. All logs include it. Response header echoes it back |

## Anti-Features

Features to explicitly **NOT build** in this service. These boundaries are critical for keeping scope tight.

| Anti-Feature | Why Avoid | What to Do Instead |
|--------------|-----------|-------------------|
| **Job status / report endpoints** | These stay in FastAPI. Go service only handles the upload path. Duplicating read endpoints creates data consistency risk and doubles the API surface to maintain | Route all non-upload paths to FastAPI via Nginx proxy |
| **SSE streaming** | Job progress streaming uses FastAPI's SSE support and polls the DB. This is a read-only concern, unrelated to file ingestion | Keep in FastAPI. No Go involvement |
| **Authentication / authorization** | No auth exists today. Adding it to Go but not FastAPI creates an inconsistent security posture. Auth should be added uniformly at the proxy/gateway layer | Defer to a future milestone that adds auth across all services simultaneously |
| **Rate limiting** | Per PROJECT.md, not in scope for v1. Adding rate limiting to Go but not FastAPI creates bypass paths (users could hit FastAPI directly) | Add at proxy layer (Nginx `limit_req`) when needed, or defer to API gateway |
| **Database schema migration** | Python backend owns the schema via SQLAlchemy `create_all`. Go service must be a schema consumer, not creator. Dual-ownership of schema = migration conflicts | Go reads/writes to existing tables. If schema changes needed, coordinate through Python backend or a dedicated migration tool |
| **Archive extraction / sub-job submission** | This is worker logic. The upload endpoint only creates the initial Job; archive analysis happens downstream | Keep in Python worker. Go service only receives parent_job_id as input, never creates child jobs during upload |
| **Worker/consumer rewrite** | Worker is complex (ClamAV, YARA, sandbox, archive extraction). Rewriting it provides minimal concurrency benefit — it's I/O-bound on external tools | Keep Python worker. This milestone is laser-focused on the upload bottleneck |
| **File content validation / virus pre-scan** | Tempting to add a quick ClamAV scan during upload, but it would block the upload response and change the API contract (currently returns immediately) | Keep analysis in the worker pipeline. Upload must remain fast and asynchronous |
| **Multipart form field parsing beyond file + parent_job_id** | Don't expand the API contract. No new form fields, no query parameters, no headers that the current endpoint doesn't accept | Strict parity. If new fields needed later, add to both Go and FastAPI simultaneously |
| **Auto-create DB tables** | Python backend does `Base.metadata.create_all` at startup. Go service should NOT also create tables — risks conflicting DDL or race conditions | Depend on Python backend (or a separate migration tool) to ensure tables exist |
| **WebSocket support** | No WebSocket requirements exist. Adding real-time upload progress via WebSocket is scope creep | Frontend doesn't need it — upload completes, then polls for job status via SSE (FastAPI) |

## Feature Dependencies

```
Multipart streaming upload
├── Streaming SHA256 computation (reads from stream)
├── File size enforcement (checked per chunk)
├── Filename sanitization (from multipart headers)
└── Temp file streaming (writes chunked data)
    └── MinIO upload (reads from temp file)
        └── SHA256-based deduplication (decides if MinIO upload needed)
            └── File record creation (dedup check against files table)
                └── Job record creation (needs file_id FK)
                    └── Atomic DB transaction (wraps file + job)
                        └── RabbitMQ publish (after commit)
                            └── Retry with exponential backoff
                                └── Job marked FAILED on failure

Environment variable config (startup prerequisite for everything)
├── Connection pooling (PostgreSQL)
├── MinIO client init + bucket creation
├── RabbitMQ connection + queue declaration
└── HTTP server config (port, timeouts, CORS)

Health check endpoint (independent)
Graceful shutdown (depends on: HTTP server, DB pool, MQ connection)
Prometheus metrics (independent, wraps other features)
```

## Critical Path (Upload Pipeline Sequence)

```
1. Receive multipart request
2. Read Content-Disposition → sanitize filename, extract content_type
3. Stream chunks: hash + size-check + write to temp file (parallel via io.TeeReader)
4. [Optional] Check SHA256 in DB (dedup optimization)
5. Upload temp file to MinIO (key = SHA256)
6. BEGIN transaction
7.   INSERT INTO files (if not exists by SHA256) → get file_id
8.   INSERT INTO jobs (file_id, status=queued, ...) → get job_id
9. COMMIT
10. Publish to RabbitMQ (with retry)
11.   On failure: UPDATE jobs SET status=failed → return 503
12. Return 201 {job_id, file_id, sha256, status, created_at}
13. Cleanup temp file (defer)
```

## MVP Recommendation

### Phase 1: Functional Parity (must ship)

Prioritize in this order (follows the data flow):

1. **Environment variable configuration** — everything depends on this
2. **Multipart streaming + SHA256 + size enforcement + sanitization** — the core upload loop
3. **Temp file streaming + MinIO upload** — gets the file stored
4. **PostgreSQL operations** (file + job creation, dedup, atomic txn) — creates the records
5. **RabbitMQ publish with retry + failure handling** — triggers the pipeline
6. **API contract compliance** (response format, error format, status codes) — frontend works
7. **Health check endpoint** — k8s can manage the pod
8. **CORS support** — frontend can reach the service
9. **Graceful shutdown** — safe deployments
10. **Dockerfile + Docker Compose entry** — can run locally and in CI

### Phase 2: Operational Excellence (ship soon after)

11. **Prometheus metrics** — enables monitoring before production traffic
12. **Readiness probe with real backend checks** — k8s routes traffic correctly
13. **Request-scoped logging context** — debuggable in production
14. **Connection health monitoring** — resilient under infrastructure issues
15. **Upload timeout enforcement** — prevents resource exhaustion
16. **Kubernetes manifests** — production deployment

### Defer to v2

17. **Streaming MinIO upload via io.Pipe** — high complexity, temp file approach works fine for v1. Optimize only if disk I/O proves to be a bottleneck
18. **Dedup-before-upload optimization** — nice-to-have. Current Python behavior (upload then dedup) is acceptable and simpler to reason about

## Sources

- Direct codebase analysis: `backend/src/malscan/api/routes.py` (upload endpoint, 290 lines)
- Direct codebase analysis: `backend/src/malscan/storage.py` (MinIO client with ThreadPoolExecutor bottleneck)
- Direct codebase analysis: `backend/src/malscan/queue.py` (RabbitMQ publisher with tenacity retry)
- Direct codebase analysis: `backend/src/malscan/schemas/requests.py` (exact API response schemas)
- Direct codebase analysis: `backend/src/malscan/models/file.py` + `job.py` (exact DB schema)
- Direct codebase analysis: `backend/src/malscan/config.py` (all environment variables)
- Direct codebase analysis: `backend/src/malscan/main.py` (startup sequence, CORS, body limit)
- Direct codebase analysis: `k8s/api/deployment.yaml` (probe configuration, resource limits, security context)
- Direct codebase analysis: `docker-compose.yml` (infrastructure service versions and config)
- `.planning/PROJECT.md` (validated requirements, out-of-scope, constraints, key decisions)
- `.planning/codebase/ARCHITECTURE.md` (data flow, error handling patterns, concurrency model)
- Production patterns: Go file upload services (stdlib `net/http`, `mime/multipart`, `io.TeeReader` patterns) — HIGH confidence from Go ecosystem knowledge
