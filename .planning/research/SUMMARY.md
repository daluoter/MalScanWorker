# Project Research Summary

**Project:** MalScanWorker — Go Ingestion Layer
**Domain:** High-concurrency file ingestion microservice (Go) replacing Python/FastAPI upload bottleneck in a malware analysis pipeline
**Researched:** 2025-03-27
**Confidence:** HIGH

## Executive Summary

MalScanWorker is a malware analysis pipeline where files are uploaded, stored, queued, and analyzed through multiple stages (ClamAV, YARA, sandbox, archive extraction). The existing Python/FastAPI upload endpoint is the bottleneck: its `ThreadPoolExecutor(max_workers=4)` ceiling on MinIO uploads and CPU-bound SHA256 hashing blocking the asyncio event loop cap throughput at ~4 concurrent uploads. The Go ingestion service replaces exactly one route (`POST /api/v1/files`) with a sidecar microservice that handles 50+ concurrent uploads via goroutines. Everything else—job status, reports, SSE streaming, workers—stays in Python.

The recommended approach is a lean Go binary (~9 direct dependencies, ~15MB Docker image) using chi for HTTP routing, pgx for PostgreSQL, minio-go for MinIO, and amqp091-go for RabbitMQ. The service streams multipart uploads through `io.TeeReader` to simultaneously hash (SHA256) and write to a temp file in 1MB chunks—never buffering the full file in memory. An Nginx reverse proxy splits traffic by path, making the Go/Python split transparent to the frontend. All integration points (DB schema, RabbitMQ message format, API response shape) are known contracts from the existing codebase, making this a well-defined porting exercise rather than greenfield design.

The key risks are integration fidelity, not technology. The `DATABASE_URL` format mismatch (`postgresql+asyncpg://` vs `postgresql://`), RabbitMQ queue declaration argument equality enforcement, file deduplication race conditions under true parallelism, and `net/http` multipart memory buffering are the top pitfalls—all well-understood and preventable with specific patterns documented in this research. The Go ecosystem choices are canonical (every library is the vendor-maintained or de facto standard option), and all versions were verified against the Go module proxy.

## Key Findings

### Recommended Stack

The Go stack is intentionally minimal and unopinionated. Every library is either stdlib, vendor-maintained, or the de facto community standard. Total transitive dependency count (~20) is a fraction of the Python backend's 50+.

**Core technologies:**
- **Go 1.26.x**: Goroutines provide true parallelism for concurrent uploads; stdlib includes `log/slog`, `crypto/sha256`, `mime/multipart`, `io.TeeReader`
- **go-chi/chi v5.2.5**: HTTP router implementing `net/http.Handler`; middleware chaining for CORS, recovery, logging, size limits
- **jackc/pgx v5.9.1**: Native PostgreSQL driver with built-in connection pooling (`pgxpool`); supports UUID, TIMESTAMPTZ, JSONB natively
- **minio/minio-go v7.0.99**: Official MinIO SDK; `PutObject` accepts `io.Reader` for streaming uploads
- **rabbitmq/amqp091-go v1.10.0**: Official RabbitMQ Go client; persistent messages, queue declaration with DLX arguments
- **log/slog (stdlib)**: Zero-dependency structured JSON logging; sufficient for this service's needs
- **prometheus/client_golang v1.23.2**: Standard Prometheus metrics; histograms for upload latency, counters for success/error
- **caarlos0/env v11.4.0**: Struct-tag-based env var parsing (equivalent to Python's pydantic-settings)
- **cenkalti/backoff v5.0.3**: Exponential backoff retry (equivalent to Python's tenacity)

**Key version requirement:** Go 1.21+ minimum for `log/slog` stdlib; Go 1.22+ for method-based routing in `net/http.ServeMux`. Targeting Go 1.26.x (latest stable).

**Alternatives rejected with strong rationale:** Gin/Fiber/Echo (non-stdlib interfaces), GORM/sqlc (overkill for 3 queries), Viper (10x complexity for env-only config), zerolog/zap (stdlib slog is sufficient). See STACK.md for full comparison table.

### Expected Features

**Must have (table stakes — required for drop-in replacement):**
- Multipart streaming upload with 1MB chunked reads (never buffer full file in memory)
- Streaming SHA256 computation via `io.TeeReader`
- Per-chunk file size enforcement (100MB limit, abort early)
- Filename sanitization (exact port of Python's `_sanitize_filename()`)
- MinIO upload keyed by SHA256 hash with bucket auto-creation
- SHA256-based file deduplication against `files` table
- Atomic DB transaction for file + job creation (exact schema match: 6 columns on `files`, 14 columns on `jobs`)
- Parent job validation with recursion depth check
- RabbitMQ persistent message publish with 5-retry exponential backoff (1s→16s)
- Job marked FAILED on publish exhaustion
- Exact API response format: `{"job_id","file_id","sha256","status":"queued","created_at"}`
- Exact error envelope: `{"error":{"code":"...","message":"...","details":{...}}}`
- HTTP status codes: 201/400/422/500/503 matching Python
- Health check endpoint, CORS, graceful shutdown, JSON structured logging, env var config

**Should have (differentiators — justify the rewrite):**
- True concurrent upload handling (50+ goroutines vs Python's 4-thread limit)
- Prometheus metrics (upload count, latency histogram, error rate, in-flight gauge, bytes total)
- Readiness probe with real backend health checks (PostgreSQL, MinIO, RabbitMQ ping)
- Request-scoped structured logging context (request_id, job_id, file_id propagation)
- Connection health monitoring and reconnection
- Upload timeout enforcement (`ReadTimeout`/`WriteTimeout`)
- Request ID / X-Request-Id trace propagation

**Defer to v2+:**
- Streaming MinIO upload via `io.Pipe` (high complexity; temp file approach is fine for v1)
- Dedup-before-upload optimization (current Python behavior of upload-then-dedup is acceptable)

**Anti-features (explicitly out of scope):**
- Job status/report endpoints (stay in FastAPI)
- SSE streaming, authentication, rate limiting, DB migrations, worker rewrite, file content validation, archive extraction, WebSocket support

### Architecture Approach

The Go service operates as a **sidecar upload service** — a standalone microservice owning exactly one route while Nginx splits traffic by path. Both Go and FastAPI are readers/writers to the same PostgreSQL database; coordination happens entirely through the database and RabbitMQ. The Go service is insert-only on `files` and `jobs` tables, never updates or reads status.

**Major components:**
1. **Nginx Proxy** — Path-based routing: `POST /api/v1/files` → Go :8080, everything else → FastAPI :8000. Critical setting: `proxy_request_buffering off` for streaming.
2. **Go Ingestion Service** — Single binary with `cmd/ingest/main.go` entry point. `internal/` packages: config, handler, middleware, model, storage, queue, db, sanitize, server.
3. **Upload Handler** — Orchestrates the pipeline: multipart parse → stream chunks (hash + size-check + temp write) → MinIO upload → DB transaction (dedup + file + job insert) → RabbitMQ publish with retry → JSON response.
4. **Infrastructure Clients** — pgxpool (min:2, max:15 connections), minio-go (Go's `http.Transport` handles connection pooling), amqp091-go (1 connection, channel pool for goroutine safety).

**Key patterns:**
- Dependency injection via constructors (no DI framework, no global singletons)
- `defer tx.Rollback()` for transaction safety
- `defer os.Remove(tmpFile)` immediately after creation
- `context.Context` propagation from `r.Context()` to all downstream calls
- `signal.NotifyContext` + `http.Server.Shutdown` for graceful shutdown with 30s drain

**Project layout:** Standard `cmd/` + `internal/` Go convention. Flat internal packages (one per concern). No `pkg/` (nothing should be importable externally). No hexagonal/DDD (overkill for single-endpoint service).

### Critical Pitfalls

The top pitfalls are integration fidelity issues that arise from replacing one service in a multi-service pipeline:

1. **DATABASE_URL format incompatibility** — Existing `postgresql+asyncpg://` prefix breaks pgx parsing. Fix: `strings.Replace(url, "+asyncpg", "", 1)` at config load. Phase 1.
2. **File deduplication race condition** — True goroutine parallelism means two identical uploads can both pass the SELECT check before either INSERT completes. Fix: `INSERT ... ON CONFLICT (sha256) DO NOTHING RETURNING id`. Phase 2.
3. **RabbitMQ queue declaration argument mismatch** — RabbitMQ enforces exact argument equality on re-declaration. Missing DLX args = `PRECONDITION_FAILED` = channel closed. Fix: Use passive declaration (`QueueDeclarePassive`) — let Python own the queue definition. Phase 2.
4. **RabbitMQ message format divergence** — Worker parses exact JSON fields (`job_id`, `file_id`, `storage_key`, `sha256`, `original_filename`). Missing field = worker crash. Fix: Define Go struct with exact `json` tags; write cross-language integration test. Phase 2.
5. **`net/http` multipart memory buffering (OOM)** — `r.FormFile()` / `ParseMultipartForm()` buffers up to 32MB per upload in RAM. At 50 concurrent uploads = 1.6GB. Fix: Use `r.MultipartReader()` for true streaming; never call `ParseMultipartForm()`. Phase 2.
6. **AMQP Channel is NOT goroutine-safe** — 50 concurrent goroutines publishing through one channel = corrupted frames. Fix: Channel pool (buffered Go channel of `*amqp.Channel`, size 10) or dedicated publisher goroutine. Phase 2.
7. **JSON response schema mismatch** — Go's `time.Time` RFC 3339 vs Python's Pydantic microsecond ISO 8601. Error responses must use nested `{"error":{...}}` envelope, not Go's typical flat format. Fix: Explicit response structs with exact json tags; test against OpenAPI spec. Phase 2.

## Implications for Roadmap

Based on combined research, the project decomposes naturally into 5 phases following the dependency graph and data flow.

### Phase 1: Foundation & Scaffolding
**Rationale:** Everything depends on config, models, and project structure. Must verify Go can connect to all three backends (PostgreSQL, MinIO, RabbitMQ) before writing business logic. This phase has zero business logic risk — it's all infrastructure wiring.
**Delivers:** Buildable Go module, Docker image, env var config with DATABASE_URL transform, model structs, filename sanitizer with tests, health check endpoint, Docker Compose entry for go-ingest service.
**Features addressed:** Environment variable configuration, health check endpoint, containerized deployment, filename sanitization.
**Pitfalls to avoid:** DATABASE_URL format (#1), Go module path naming (#18), Docker multi-stage build caching (#19), structlog JSON format key names (#16).
**Estimated complexity:** LOW — all standard patterns, no integration unknowns.

### Phase 2: Core Upload Pipeline
**Rationale:** This is the bulk of the service — the entire upload flow from multipart parsing through RabbitMQ publish. Built as a single phase because the upload is one atomic operation (stream → hash → store → record → queue). Splitting it would mean building untestable partial flows.
**Delivers:** Working `POST /api/v1/files` endpoint that accepts uploads, stores in MinIO, creates file+job records, publishes to RabbitMQ, returns correct JSON response. Functionally equivalent to the Python endpoint.
**Features addressed:** Multipart streaming, SHA256 computation, file size enforcement, MinIO upload, deduplication, atomic DB transaction, parent job validation, RabbitMQ publish with retry, failure handling, API contract compliance (response format, error format, status codes).
**Pitfalls to avoid:** Multipart memory buffering (#5), dedup race condition (#2), queue argument mismatch (#3), message format divergence (#4), AMQP channel goroutine safety (#6), JSON response schema (#7), timestamp timezone (#8), request body size limit (#10), filename sanitization divergence (#15), MinIO bucket init race (#12).
**Estimated complexity:** MEDIUM-HIGH — most pitfalls concentrate here. Each sub-component is well-understood, but the orchestration across all backends in a single request handler is the integration challenge.

### Phase 3: Production Hardening
**Rationale:** The core flow works but isn't production-ready. This phase adds resilience (graceful shutdown, connection health monitoring, upload timeouts) and observability (Prometheus metrics, request-scoped logging, readiness probes). These features wrap existing functionality — they don't change business logic.
**Delivers:** Graceful shutdown with in-flight upload draining (30s–5min timeout), Prometheus `/metrics` endpoint, real readiness probes (`/readyz` pinging backends), request-scoped structured logging with correlation IDs, connection health monitoring for PostgreSQL and RabbitMQ.
**Features addressed:** Graceful shutdown, Prometheus metrics, readiness probe with backend checks, request-scoped logging context, connection health monitoring, upload timeout enforcement, request ID propagation.
**Pitfalls to avoid:** Graceful shutdown timeout too short (#11), goroutine leak on client disconnect (#9), pgxpool default sizing (#13), temp file leak (#14).
**Estimated complexity:** MEDIUM — well-documented Go patterns, but graceful shutdown with long-running uploads needs careful timeout tuning.

### Phase 4: Integration & Proxy Routing
**Rationale:** The Go service works standalone; now it needs to coexist with the existing FastAPI backend. Nginx proxy routing, CORS unification, and end-to-end testing against the full pipeline (Go publishes → Python worker consumes and processes). This is where integration mismatches surface.
**Delivers:** Nginx reverse proxy config with path-based routing, CORS handled at proxy layer, Docker Compose with full pipeline (Go + FastAPI + Nginx + PostgreSQL + MinIO + RabbitMQ + Worker), end-to-end integration tests verifying the full upload→analysis flow.
**Features addressed:** CORS support (at Nginx level), Nginx proxy routing config.
**Pitfalls to avoid:** CORS configuration mismatch (#20), Nginx buffering uploads (#proxy_request_buffering), API contract verification against frontend.
**Estimated complexity:** MEDIUM — Nginx config is straightforward but end-to-end testing across Go/Python boundary is where subtle issues appear (message format, timestamp precision, error codes).

### Phase 5: Kubernetes & Deployment
**Rationale:** Everything works locally in Docker Compose. This phase creates production deployment manifests, sets resource limits, configures probes, and adds Prometheus scraping annotations. Last because it requires a fully working, hardened service.
**Delivers:** K8s Deployment + Service manifests for go-ingest, resource requests/limits (64Mi–256Mi memory, 50m–500m CPU), startup/liveness/readiness probes, Prometheus annotations, emptyDir volume for `/tmp` with sizeLimit, security context (runAsNonRoot, readOnlyRootFilesystem).
**Features addressed:** Kubernetes manifests, production deployment.
**Pitfalls to avoid:** emptyDir sizeLimit for temp files, pgxpool sizing for shared PostgreSQL connection budget.
**Estimated complexity:** LOW — standard k8s patterns, existing manifests for FastAPI provide a reference.

### Phase Ordering Rationale

- **Phase 1 → 2:** Can't build the upload pipeline without config, models, and a running container. Phase 1 validates that Go can reach all backends.
- **Phase 2 is monolithic by design:** The upload flow is a single transaction spanning 4 systems (HTTP → MinIO → PostgreSQL → RabbitMQ). Building sub-components in isolation produces untestable code. One phase, one integration test.
- **Phase 3 after 2:** Can't add metrics/timeouts/graceful shutdown to code that doesn't exist yet. But ship 3 quickly — production hardening before production traffic.
- **Phase 4 after 3:** Nginx proxy and end-to-end tests require a fully hardened service. Proxy config is the final integration step.
- **Phase 5 last:** K8s manifests are deployment config, not application code. Requires everything else to be working.

### Research Flags

**Phases likely needing deeper research during planning:**
- **Phase 2 (Core Upload Pipeline):** Needs research on `mime/multipart.Reader` streaming behavior with `http.MaxBytesReader`. Verify that `r.MultipartReader()` truly avoids buffering. Also research `INSERT ... ON CONFLICT DO NOTHING RETURNING id` behavior when RETURNING returns no rows. Also research amqp091-go channel pool patterns — limited community documentation on production channel pool implementations.
- **Phase 4 (Integration & Proxy Routing):** Needs research on Nginx `proxy_request_buffering off` behavior with multipart uploads. Also: SSE passthrough configuration for the FastAPI routes (`chunked_transfer_encoding off`, `proxy_buffering off`).

**Phases with standard patterns (skip research-phase):**
- **Phase 1 (Foundation):** Go project scaffolding, env var parsing, Docker multi-stage builds — all extremely well-documented. No research needed.
- **Phase 3 (Production Hardening):** Graceful shutdown (`signal.NotifyContext`), Prometheus client, slog — all canonical Go patterns with extensive documentation.
- **Phase 5 (Kubernetes):** Standard k8s Deployment manifests. Existing FastAPI k8s manifests in `k8s/api/` provide a direct reference.

## Confidence Assessment

| Area | Confidence | Notes |
|------|------------|-------|
| Stack | **HIGH** | All library versions verified against Go module proxy (`proxy.golang.org`). Every library is the canonical or vendor-maintained choice. No experimental or niche dependencies. |
| Features | **HIGH** | API contract fully documented via direct codebase analysis of Python routes, schemas, models, and worker consumer. Schema is known, message format is known, response shape is known. |
| Architecture | **HIGH** | Standard Go patterns: goroutines for concurrency, pgxpool for DB, `io.TeeReader` for streaming, chi for routing. Sidecar + Nginx proxy is a well-established microservice integration pattern. |
| Pitfalls | **HIGH** | 20 pitfalls identified from direct codebase analysis + Go ecosystem knowledge. Top pitfalls (DATABASE_URL, dedup race, queue args, OOM buffering) are well-understood with proven prevention strategies. |

**Overall confidence: HIGH**

This is a well-defined porting exercise with known contracts, canonical libraries, and extensively documented integration points. The existing Python codebase provides a complete specification for every behavior the Go service must replicate.

### Gaps to Address

- **RabbitMQ connection recovery:** amqp091-go does NOT have automatic reconnection (unlike Python's aio-pika `connect_robust`). Need manual reconnection logic using `NotifyClose` channel. Research needed during Phase 2 planning to decide between: (a) wrapper with reconnect loop, (b) external library, (c) restart-on-disconnect with k8s handling recovery.
- **Nginx multipart streaming verification:** `proxy_request_buffering off` is the documented solution, but needs empirical verification with 100MB uploads through Nginx → Go to confirm no intermediate buffering. Test during Phase 4.
- **PostgreSQL connection budget:** Python backend uses 30 connections (10 base + 20 overflow), Python worker uses 15 (5 base + 10 overflow). Go service targets max 15. Total: 60. Verify PostgreSQL `max_connections` setting accommodates this. Check during Phase 1 when configuring pgxpool.
- **`filepath.Base` vs `path.Base` behavior:** Go's `filepath.Base` on Linux treats `\` as a regular character (not a path separator). The sanitizer must use `path.Base` (POSIX semantics) after backslash replacement, or pre-replace `\` → `/` then use `path.Base`. Edge case: `filepath.Base("")` returns `"."` not `""`. Verify with Python-equivalent test cases during Phase 1.
- **MinIO bucket lifecycle ownership:** Python backend sets 1-day expiry lifecycle on `uploads` bucket. Go should only verify bucket existence, not re-set lifecycle rules. If Go must be independently deployable (cold start without Python), it needs to match lifecycle config exactly. Decision needed during Phase 2.
- **Structured log key compatibility:** Python structlog uses `event` as message key; Go slog uses `msg`. If log aggregation parses `event`, Go logs won't be captured. Decide during Phase 1: (a) configure slog with custom key names, (b) accept the difference and update log aggregation, (c) use zerolog for custom key support.

## Sources

### Primary (HIGH confidence)
- **Direct codebase analysis:** `backend/src/malscan/api/routes.py` (upload handler, 290 lines), `storage.py` (MinIO + ThreadPoolExecutor), `queue.py` (RabbitMQ publisher + tenacity retry), `schemas/requests.py` (API response schema), `models/file.py` + `job.py` (DB schema), `config.py` (env vars), `main.py` (startup + CORS)
- **Worker contract:** `worker/src/malscan_worker/consumer.py` (message parsing), `pipeline.py` (field usage)
- **Deployment config:** `docker-compose.yml` (service versions), `k8s/api/deployment.yaml` (probe config, resource limits)
- **Go module proxy (`proxy.golang.org`):** All library versions verified on 2025-03-27 — pgx v5.9.1, minio-go v7.0.99, amqp091-go v1.10.0, chi v5.2.5, prometheus/client_golang v1.23.2, env v11.4.0, backoff v5.0.3, testify v1.11.1, testcontainers-go v0.41.0
- **Go standard library:** `net/http`, `crypto/sha256`, `io.TeeReader`, `mime/multipart`, `log/slog`, `context`, `signal` — all stdlib since Go 1.21+

### Secondary (MEDIUM confidence)
- **amqp091-go goroutine safety:** Channel concurrency warnings from library documentation — well-documented limitation, channel pool pattern inferred from community usage
- **RabbitMQ AMQP 0-9-1 specification:** Queue declaration argument matching behavior — authoritative protocol spec

### Tertiary (LOW confidence)
- **Nginx multipart proxy buffering:** `proxy_request_buffering off` behavior with large uploads needs empirical verification during Phase 4
- **Structured log key compatibility:** Impact on existing log aggregation unclear without knowing the specific aggregation tooling in use

---
*Research completed: 2025-03-27*
*Ready for roadmap: yes*
