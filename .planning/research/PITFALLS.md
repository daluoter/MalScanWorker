# Domain Pitfalls

**Domain:** Go file ingestion microservice replacing Python/FastAPI upload endpoint
**Researched:** 2025-03-27
**Confidence:** HIGH (based on direct codebase analysis + Go ecosystem knowledge)

---

## Critical Pitfalls

Mistakes that cause data corruption, service outages, or require rewrites.

---

### Pitfall 1: DATABASE_URL Format Incompatibility

**What goes wrong:** The existing `DATABASE_URL` environment variable uses SQLAlchemy's asyncpg dialect format: `postgresql+asyncpg://postgres:postgres@postgres:5432/malscan`. Go's `pgx` driver cannot parse the `+asyncpg` dialect prefix — it expects standard `postgres://` or `postgresql://` URIs. The Go service fails to connect to the database on startup.

**Why it happens:** Docker Compose and deployment configs share a single `DATABASE_URL` variable across all services. Developers assume Go can reuse it directly.

**Consequences:** Go service crashes on startup. If "fixed" by changing the shared env var, the Python backend and worker break instead.

**Prevention:**
- In the Go service, strip `+asyncpg` from the URL at startup: `strings.Replace(url, "+asyncpg", "", 1)`
- OR define a separate env var (`DATABASE_URL_GO` / `PGX_DATABASE_URL`) but this adds config surface
- **Recommend the string-replace approach** — it's self-contained, transparent, and lets all services share one variable
- Add a startup log line confirming the parsed connection string (with password masked)

**Detection:** Service fails to start with `pgx` parse error. Easy to miss in CI if Go tests use a hardcoded connection string.

**Phase:** Phase 1 (project scaffolding / configuration)

---

### Pitfall 2: File Deduplication Race Condition Under True Parallelism

**What goes wrong:** Two concurrent uploads of the same file (identical SHA256) both execute `SELECT ... WHERE sha256 = $1`, both find no existing record, and both attempt `INSERT INTO files`. The second INSERT violates the `sha256` UNIQUE constraint and the upload fails with a 500 error.

**Why it happens:** Python's asyncio single-event-loop model makes this window very narrow — the `SELECT` + `INSERT` happens in an uninterrupted async flow. Go's goroutine-based parallelism means two uploads can genuinely execute the SELECT simultaneously on separate connections before either INSERT completes.

**Consequences:** Intermittent 500 errors for legitimate concurrent uploads of the same file. Worse: if the error isn't caught specifically, the job record might not be created even though the file was already uploaded to MinIO.

**Prevention:**
- Use `INSERT INTO files (...) VALUES (...) ON CONFLICT (sha256) DO NOTHING RETURNING id` — atomically handles dedup at the database level
- If `RETURNING id` returns nothing (conflict occurred), follow up with `SELECT id FROM files WHERE sha256 = $1`
- Wrap both file INSERT and job INSERT in a single PostgreSQL transaction
- **Do NOT rely on application-level locking** (sync.Mutex) — it doesn't protect across multiple Go service instances

**Detection:** Load test with 10+ concurrent uploads of the same file. If any return 500, the race condition exists.

**Phase:** Phase 2 (core upload handler / database logic)

---

### Pitfall 3: RabbitMQ Queue Declaration Argument Mismatch

**What goes wrong:** The existing Python backend and worker declare the `malscan.jobs` queue with specific dead-letter arguments: `x-dead-letter-exchange: ""` and `x-dead-letter-routing-key: "malscan-dlq"`. If the Go service declares the same queue with different arguments (e.g., missing DLQ config, different key name, or additional arguments), RabbitMQ returns a `PRECONDITION_FAILED` error and closes the channel.

**Why it happens:** RabbitMQ enforces argument equality on re-declaration. The Go developer writes their own queue declaration without exactly matching the existing Python arguments. Even a missing argument counts as a mismatch.

**Consequences:** Go service cannot publish messages. The channel is closed by RabbitMQ, and unless there's reconnection logic, all subsequent publishes fail silently.

**Prevention:**
- Copy the exact queue arguments from `backend/src/malscan/queue.py:43-49`:
  ```go
  args := amqp.Table{
      "x-dead-letter-exchange":    "",
      "x-dead-letter-routing-key": "malscan-dlq",
  }
  ```
- OR use **passive declaration** (`QueueDeclarePassive`) which checks the queue exists without asserting arguments — safer when another service owns the queue definition
- **Recommend passive declaration for Go** — let the Python backend/worker own the queue definition, and the Go service just confirms it exists
- If the queue doesn't exist yet (cold start), fall back to full declaration with matched args

**Detection:** Channel error immediately after `QueueDeclare`. Logs will show `PRECONDITION_FAILED - inequivalent arg 'x-dead-letter-routing-key'` (or similar).

**Phase:** Phase 2 (RabbitMQ integration)

---

### Pitfall 4: RabbitMQ Message Format Divergence

**What goes wrong:** The Python worker's `consumer.py` parses specific JSON fields from the message body: `job_id`, `file_id`, `storage_key`, `sha256`, `original_filename` (all strings). The Python publisher also sets `delivery_mode=PERSISTENT` and `content_type="application/json"`. If the Go publisher omits any field, uses different field names, uses non-string types (e.g., UUID object instead of string), or forgets the persistence flag, the worker either crashes, silently ignores the job, or processes it incorrectly.

**Why it happens:** No shared schema definition between publisher and consumer. The message format is an implicit contract defined only in code (`routes.py:244-250` and `consumer.py:80-82`).

**Consequences:**
- Missing `storage_key` → worker can't download file from MinIO → job fails
- UUID as binary instead of string → `json.loads` succeeds but `body.get("job_id")` returns wrong type → worker status updates fail
- Missing persistence flag → messages lost on RabbitMQ restart → jobs stuck in QUEUED forever

**Prevention:**
- Define a Go struct that exactly mirrors the Python message:
  ```go
  type JobMessage struct {
      JobID            string `json:"job_id"`
      FileID           string `json:"file_id"`
      StorageKey       string `json:"storage_key"`
      SHA256           string `json:"sha256"`
      OriginalFilename string `json:"original_filename"`
  }
  ```
- Always use `amqp.Publishing{DeliveryMode: amqp.Persistent, ContentType: "application/json"}`
- Write an integration test: Go publishes → Python worker consumes and processes successfully
- **Treat the message schema as a contract** — document it in the repo and test both sides against it

**Detection:** Python worker logs `job_received` but then fails immediately, or fields are `None` in worker logs.

**Phase:** Phase 2 (RabbitMQ publishing)

---

### Pitfall 5: `net/http` Multipart Memory Buffering (OOM)

**What goes wrong:** Go's `http.Request.FormFile()` and `ParseMultipartForm()` buffer up to `maxMemory` bytes in RAM (default 32MB) before spilling to disk. For a 100MB file limit, this means at 50 concurrent uploads, the Go service could consume 50 × 32MB = 1.6GB of RAM just for multipart buffering — plus the remainder stored in temp files. If `ParseMultipartForm` is called with a high `maxMemory`, the entire file stays in RAM.

**Why it happens:** Developers use the convenient `r.FormFile("file")` API without understanding it triggers `ParseMultipartForm` under the hood. The streaming alternative (`r.MultipartReader()`) is less discoverable.

**Consequences:** OOM kills under concurrent load. The Go service is supposed to handle 10-50 simultaneous uploads; with `FormFile()`, even 10 concurrent 100MB uploads could consume 1GB+ RAM.

**Prevention:**
- Use `r.Body` with `multipart.NewReader(r.Body, boundary)` for true streaming OR use `r.MultipartReader()` which returns a `*multipart.Reader` without buffering
- Stream each part through `io.TeeReader` to simultaneously write to temp file and hash:
  ```go
  hasher := sha256.New()
  tmpFile, _ := os.CreateTemp("", "upload-*")
  written, _ := io.Copy(io.MultiWriter(tmpFile, hasher), part)
  ```
- **Never call `r.ParseMultipartForm()`** — it forces buffering
- Also set `http.MaxBytesReader(w, r.Body, maxRequestSize)` to enforce the 150MB body limit at the HTTP layer

**Detection:** Monitor RSS memory under concurrent upload load test. If it grows proportionally to concurrent uploads × file size, you're buffering.

**Phase:** Phase 2 (core upload handler)

---

### Pitfall 6: `amqp091-go` Channel is NOT Goroutine-Safe for Publishing

**What goes wrong:** Go's `amqp091-go` library's `Channel` type is explicitly documented as unsafe for concurrent use by multiple goroutines. If 50 concurrent upload handlers all try to publish through a shared channel simultaneously, you get corrupted AMQP frames, channel closures, or panics.

**Why it happens:** Developers assume a single channel is fine because "RabbitMQ channels are lightweight" and "we only do simple publishes." The Python code uses a single channel safely because asyncio is single-threaded.

**Consequences:** Intermittent publish failures under load. Corrupted AMQP protocol frames. The channel closes unexpectedly and no reconnection logic exists. Jobs are created in DB but never published to RabbitMQ.

**Prevention:**
- **Option A (recommended): Use a channel pool.** Create N channels (e.g., 10) and use a buffered Go channel as a pool:
  ```go
  chanPool := make(chan *amqp.Channel, 10)
  // Initialize pool, acquire/release around each publish
  ```
- **Option B:** Create a dedicated publishing goroutine with a work channel — all handlers send messages to this goroutine via a Go channel, and it publishes sequentially
- **Option C:** Use `Channel.Confirm` mode per-channel for publisher confirms — adds reliability
- **Do NOT use a `sync.Mutex` around a single channel** — it works but serializes all publishes, becoming a bottleneck under load

**Detection:** Run 50 concurrent uploads. Check for `channel/connection is not open` errors in logs. Often manifests only under load.

**Phase:** Phase 2 (RabbitMQ integration)

---

### Pitfall 7: JSON Response Schema Mismatch

**What goes wrong:** The frontend expects the exact JSON response schema from `POST /api/v1/files` as defined in `UploadResponse`: `job_id` (string), `file_id` (string), `sha256` (string), `status` (literal "queued"), `created_at` (ISO 8601 datetime). Go's `time.Time` marshals to RFC 3339 by default (`2024-01-15T10:30:00Z`), which is technically compatible with ISO 8601. But Python's Pydantic serializes with microsecond precision (`2024-01-15T10:30:00.123456+00:00`). If the frontend parses datetime strings strictly, this can break.

Also: Go error responses must match the `{"error": {"code": "...", "message": "...", "details": {...}}}` envelope format, not Go's typical `{"error": "something"}` pattern.

**Why it happens:** Go developers write simple error handlers (`http.Error(w, "bad request", 400)`) without matching the existing error contract. Datetime precision differences seem minor but can break brittle parsers.

**Consequences:** Frontend displays raw error text instead of structured messages. Datetime parsing failures in downstream consumers. API tests from the frontend team fail.

**Prevention:**
- Define Go response structs with exact `json` tags matching Python's schema:
  ```go
  type UploadResponse struct {
      JobID     string    `json:"job_id"`
      FileID    string    `json:"file_id"`
      SHA256    string    `json:"sha256"`
      Status    string    `json:"status"`
      CreatedAt time.Time `json:"created_at"`
  }
  ```
- Define error response helpers that produce the nested `{"error": {...}}` envelope:
  ```go
  type APIError struct {
      Error struct {
          Code    string      `json:"code"`
          Message string      `json:"message"`
          Details interface{} `json:"details,omitempty"`
      } `json:"error"`
  }
  ```
- Test response shapes against the OpenAPI spec (check `openspec/` directory)
- Use `time.Time.UTC()` to ensure consistent timezone representation

**Detection:** Run the existing frontend against the Go service — any 4xx/5xx that doesn't show in the UI error toast is a format mismatch.

**Phase:** Phase 2 (HTTP handler / response serialization)

---

## Moderate Pitfalls

Mistakes that cause bugs, degraded performance, or debugging pain.

---

### Pitfall 8: PostgreSQL Timestamp Timezone Mismatch

**What goes wrong:** Python uses `datetime.now(timezone.utc)` to generate `created_at` and `updated_at` values, producing timezone-aware timestamps stored in `TIMESTAMPTZ` columns. Go's `time.Now()` returns local time. If the Go container's timezone isn't UTC (or if `time.Now()` is used instead of `time.Now().UTC()`), the `created_at` timestamps in the Go service will have an offset. PostgreSQL will store them correctly (it converts to UTC for storage), but the **returned values** may differ in representation compared to Python-inserted rows.

**Prevention:**
- Always use `time.Now().UTC()` in the Go service for any timestamp going into PostgreSQL
- Set `TZ=UTC` in the Dockerfile: `ENV TZ=UTC`
- pgx handles `time.Time` ↔ `timestamptz` correctly as long as the Go `time.Time` is timezone-aware (which it always is — Go's `time.Time` always has a location)
- Verify by inserting from Go and querying from Python — timestamps should match within microsecond tolerance

**Phase:** Phase 2 (database operations)

---

### Pitfall 9: Goroutine Leak on Client Disconnect Mid-Upload

**What goes wrong:** A client disconnects during a 100MB upload. The goroutine handling the upload is blocked on reading from the request body (which now returns an error) or is blocked on `MinIO.PutObject()`. If the `context.Context` from the HTTP request isn't propagated to downstream calls (MinIO upload, DB queries, RabbitMQ publish), the goroutine hangs until the operation times out or the connection drops at the TCP level.

**Prevention:**
- Use `r.Context()` as the base context for ALL downstream operations:
  ```go
  ctx := r.Context()
  _, err := minioClient.PutObject(ctx, bucket, key, reader, size, opts)
  _, err := pool.Exec(ctx, sql, args...)
  ```
- Set appropriate timeouts: `MinIO upload` → context with 5-minute timeout; `DB query` → context with 30-second timeout
- Add middleware that logs when a request context is cancelled (detect mid-upload disconnects)
- Monitor goroutine count in Prometheus — a growing count under stable load indicates leaks

**Phase:** Phase 2 (upload handler), Phase 3 (observability)

---

### Pitfall 10: No Request Body Size Limit by Default

**What goes wrong:** Go's `net/http` server accepts request bodies of arbitrary size by default. Without an explicit limit, an attacker can send a multi-GB request that exhausts disk (via temp files) or memory. The existing Python backend enforces a 150MB request body limit.

**Prevention:**
- Wrap the request body with `http.MaxBytesReader(w, r.Body, 150*1024*1024)` as the FIRST operation in the handler
- Additionally, track bytes read during multipart streaming and abort at 100MB (the file-level limit) — matching the Python behavior of per-chunk size validation
- `MaxBytesReader` returns a `*MaxBytesError` which should be caught and returned as a 413 (or 400 matching Python's behavior with `FILE_TOO_LARGE` code)

**Phase:** Phase 2 (HTTP handler)

---

### Pitfall 11: Graceful Shutdown Killing In-Flight Uploads

**What goes wrong:** Go's `http.Server.Shutdown(ctx)` stops accepting new connections and waits for active requests to complete — but only until the context deadline. A 100MB upload over a slow connection might take 5+ minutes. If the shutdown timeout is too short (e.g., 30 seconds), in-flight uploads are killed and the user gets a broken connection with no indication of what happened.

**Additionally:** The file was partially written to MinIO, the DB transaction was never committed, and the temp file is orphaned.

**Prevention:**
- Set a generous shutdown timeout (2-5 minutes) in the `Shutdown` context
- Track in-flight uploads with a `sync.WaitGroup` — the shutdown handler waits for the group before exiting
- Log all uploads that are killed by shutdown with their job IDs for manual recovery
- Implement a `/healthz` endpoint that returns `503` once shutdown is initiated, so Kubernetes stops routing new requests before killing the pod (pre-stop hook + readiness probe)

**Phase:** Phase 3 (deployment / graceful shutdown)

---

### Pitfall 12: MinIO Bucket Initialization Race with Python Backend

**What goes wrong:** Both the Go service and the Python backend call `init_buckets()` on startup. Python sets a 1-day lifecycle policy on the `uploads` bucket. If Go also sets lifecycle rules (even identical ones), the calls are idempotent for bucket creation but the lifecycle policy set could have subtle differences (e.g., different `RuleId`, `Filter` configuration). This could result in the policy being overwritten or duplicated.

**Prevention:**
- **Go should NOT re-initialize bucket lifecycle rules** — only verify the bucket exists:
  ```go
  exists, err := minioClient.BucketExists(ctx, bucket)
  if !exists {
      // create bucket only — lifecycle is owned by Python backend
  }
  ```
- OR if Go must be independently deployable, match the lifecycle config exactly (same rule ID `"1-day-expiry"`, same prefix, same expiration)
- Document bucket initialization ownership: one service owns the lifecycle, others just verify existence

**Phase:** Phase 2 (MinIO integration)

---

### Pitfall 13: `pgxpool` Connection Pool Default Sizing

**What goes wrong:** Go's `pgxpool.New()` defaults to `MaxConns = max(4, runtime.NumCPU())`. On a 2-vCPU container (common in k8s), that's only 4 connections. With 50 concurrent uploads, each needing a DB connection for the SELECT + INSERT transaction, 46 goroutines queue waiting. Upload latency spikes. The connection acquire timeout (default 0 = wait forever in some versions, or 5s in others) causes either hanging requests or cascading timeouts.

**Prevention:**
- Explicitly configure the pool:
  ```go
  config.MaxConns = 25
  config.MinConns = 5
  config.MaxConnLifetime = 30 * time.Minute
  config.MaxConnIdleTime = 5 * time.Minute
  config.HealthCheckPeriod = 30 * time.Second
  ```
- Size `MaxConns` to approximately `concurrent_uploads / 2` — each upload holds a connection briefly for the DB transaction, not for the entire upload duration
- Monitor `pool.Stat()` via Prometheus — track `AcquiredConns`, `TotalConns`, `EmptyAcquireCount`
- Consider the total PostgreSQL connection budget — Python backend uses 30 (10+20), Python worker uses 15 (5+10), plus the Go service

**Phase:** Phase 1 (configuration), Phase 3 (observability)

---

### Pitfall 14: Temp File Leak on Panic or Unhandled Error

**What goes wrong:** The Go upload handler creates a temp file, writes the upload data, uploads to MinIO, then deletes the temp file. If the process panics between creation and `defer os.Remove(tmpFile.Name())`, the temp file leaks. Worse: if `defer` runs but the file was already closed and another goroutine reused the file descriptor, you could delete the wrong file (extremely rare but possible with `os.CreateTemp`).

**Why it matters more in Go:** The Python code has the same issue (documented in CONCERNS.md: "Temporary file cleanup not guaranteed on crash"), but Go's goroutine panics can be recovered by middleware — the `defer` still runs. However, if the entire process crashes (e.g., OOM kill), temp files accumulate.

**Prevention:**
- Use `defer os.Remove(tmpFile.Name())` immediately after creating the temp file — Go's `defer` runs even on panic recovery
- Use a dedicated temp directory per upload (e.g., `/tmp/malscan-uploads/`) and add a startup cleanup routine that removes stale files older than 1 hour
- Add panic recovery middleware (`recover()`) in the HTTP handler to ensure defers execute
- Set container `emptyDir` volumes for `/tmp` in Kubernetes to bound disk usage

**Phase:** Phase 2 (upload handler), Phase 3 (deployment)

---

### Pitfall 15: Filename Sanitization Behavior Divergence

**What goes wrong:** The Python `_sanitize_filename()` function has specific behavior: replaces backslashes with forward slashes, takes `os.path.basename()`, removes null bytes, truncates to 255 chars, falls back to `"unnamed"`. If the Go implementation differs even slightly (e.g., different Unicode handling, different basename behavior for Windows paths, different whitespace handling), the filename stored in PostgreSQL for the same upload will differ between Go and Python — breaking the API contract.

**Prevention:**
- Port the Python function line-by-line to Go:
  ```go
  func sanitizeFilename(name string) string {
      name = strings.ReplaceAll(name, "\\", "/")
      name = filepath.Base(name)
      name = strings.ReplaceAll(name, "\x00", "")
      if len(name) > 255 {
          name = name[:255]
      }
      if strings.TrimSpace(name) == "" {
          name = "unnamed"
      }
      return name
  }
  ```
- Write test cases using the EXACT same inputs from Python tests
- Note: Go's `filepath.Base` on Linux treats `\` as a regular character (it's only a path separator on Windows). Use `path.Base` (from `path` package, not `path/filepath`) or do the backslash replacement first, then use `path.Base`
- **Critical edge case:** `filepath.Base("")` returns `"."` in Go, not `""`. Must handle this.

**Phase:** Phase 2 (upload handler)

---

## Minor Pitfalls

Mistakes that cause confusion, minor bugs, or maintenance burden.

---

### Pitfall 16: structlog JSON Format Compatibility

**What goes wrong:** The existing Python services use `structlog` with JSON output. Go services typically use `slog`, `zerolog`, or `zap` — all produce JSON but with different default field names. Python's structlog uses `event` as the message key; Go's `slog` uses `msg`. Log aggregation (e.g., in Kubernetes) that parses `event` won't capture Go service log messages.

**Prevention:**
- Choose a Go logger that can be configured to match structlog's output format
- Key mapping: `msg` → `event`, `level` → `level`, `time` → `timestamp`
- Or accept the difference and configure log aggregation to handle both formats
- `zerolog` is the easiest to configure for custom key names

**Phase:** Phase 1 (project scaffolding)

---

### Pitfall 17: Missing `content_type` on RabbitMQ Messages

**What goes wrong:** The Python publisher explicitly sets `content_type="application/json"` on RabbitMQ messages. While the worker doesn't check this header (it just calls `json.loads`), other tooling (RabbitMQ management UI, monitoring, future consumers) relies on it. If the Go publisher omits it, messages appear as `application/octet-stream` in the management UI, complicating debugging.

**Prevention:**
- Always set `ContentType: "application/json"` in `amqp.Publishing`
- Set `DeliveryMode: amqp.Persistent` (value `2`)
- Consider also setting `MessageId` (using the job UUID) and `Timestamp` for observability

**Phase:** Phase 2 (RabbitMQ publishing)

---

### Pitfall 18: Go Module Path Naming

**What goes wrong:** The Go module is named something generic like `module go-ingestion` or `module main`. When the project grows (potentially more Go services), renaming the module path is painful — it requires updating all import paths.

**Prevention:**
- Use a project-scoped module path from the start: `module github.com/<org>/malscanworker/ingestion` (or similar)
- Even for internal-only services, a well-structured module path aids refactoring and potential extraction
- Organize packages: `cmd/ingestion/main.go`, `internal/handler/`, `internal/storage/`, `internal/queue/`, `internal/db/`

**Phase:** Phase 1 (project scaffolding)

---

### Pitfall 19: Docker Multi-Stage Build Caching

**What goes wrong:** Go builds are fast, but if the Dockerfile copies `go.mod`, `go.sum`, AND all source code in a single `COPY . .` step, every code change invalidates the dependency download cache. Builds go from 5 seconds to 60+ seconds.

**Prevention:**
- Standard Go multi-stage pattern:
  ```dockerfile
  FROM golang:1.22-alpine AS builder
  WORKDIR /app
  COPY go.mod go.sum ./
  RUN go mod download
  COPY . .
  RUN CGO_ENABLED=0 go build -o /ingestion ./cmd/ingestion

  FROM alpine:3.19
  COPY --from=builder /ingestion /ingestion
  ENTRYPOINT ["/ingestion"]
  ```
- The `COPY go.mod go.sum` + `RUN go mod download` step is cached unless dependencies change

**Phase:** Phase 3 (containerization)

---

### Pitfall 20: CORS Configuration Must Match Python Backend

**What goes wrong:** The Python backend configures CORS with `allow_origins` from `CORS_ORIGINS` env var. If the Go service doesn't configure the same CORS headers, browser requests to the Go upload endpoint are blocked by the browser's same-origin policy. This is especially tricky because Nginx proxying may strip or modify CORS headers.

**Prevention:**
- If Nginx handles routing, configure CORS at the Nginx level (single source of truth)
- OR if each service handles its own CORS, the Go service must read `CORS_ORIGINS` and set identical headers
- **Recommend Nginx-level CORS** — avoids duplication and inconsistency
- Test from an actual browser (not just curl, which ignores CORS)

**Phase:** Phase 3 (proxy routing / deployment)

---

## Phase-Specific Warnings

| Phase Topic | Likely Pitfall | Mitigation |
|-------------|---------------|------------|
| Project scaffolding | DATABASE_URL format (#1) | Strip `+asyncpg` in config parsing |
| Project scaffolding | Module path naming (#18) | Use project-scoped path from day one |
| Core upload handler | Multipart memory buffering (#5) | Use `MultipartReader()`, never `FormFile()` |
| Core upload handler | File dedup race condition (#2) | `INSERT ... ON CONFLICT DO NOTHING` |
| Core upload handler | Request body size limit (#10) | `MaxBytesReader` as first operation |
| Core upload handler | Filename sanitization divergence (#15) | Port Python logic exactly, test with same inputs |
| RabbitMQ integration | Queue argument mismatch (#3) | Use passive declaration |
| RabbitMQ integration | Message format divergence (#4) | Define struct matching Python exactly |
| RabbitMQ integration | Channel goroutine safety (#6) | Channel pool or dedicated publisher goroutine |
| Database integration | Timestamp timezone (#8) | `time.Now().UTC()` everywhere, `TZ=UTC` in container |
| Database integration | Connection pool sizing (#13) | Explicit `MaxConns=25`, monitor pool stats |
| Response handling | JSON schema mismatch (#7) | Struct tags match Python, test against OpenAPI spec |
| Deployment | Graceful shutdown (#11) | 2-5 min timeout, `WaitGroup` for in-flight uploads |
| Deployment | MinIO bucket init race (#12) | Go verifies existence only, doesn't set lifecycle |
| Deployment | CORS configuration (#20) | Handle at Nginx level |
| Observability | Log format compatibility (#16) | Configure Go logger to match structlog keys |

---

## Sources

- Direct codebase analysis:
  - `backend/src/malscan/api/routes.py` — Python upload handler (lines 86-290)
  - `backend/src/malscan/queue.py` — RabbitMQ publisher with queue arguments (lines 43-49)
  - `backend/src/malscan/storage.py` — MinIO upload with ThreadPoolExecutor
  - `backend/src/malscan/models/file.py` — File model (UUID PK, SHA256 unique index)
  - `backend/src/malscan/models/job.py` — Job model with full schema
  - `backend/src/malscan/schemas/requests.py` — UploadResponse schema
  - `worker/src/malscan_worker/consumer.py` — Message parsing (lines 79-82)
  - `worker/src/malscan_worker/pipeline.py` — Pipeline field usage (lines 207-248)
  - `docker-compose.yml` — DATABASE_URL format (line 80)
  - `.planning/codebase/CONCERNS.md` — Known tech debt and issues
- Go standard library: `net/http` multipart handling, `http.MaxBytesReader` behavior
- `amqp091-go` documentation: Channel goroutine-safety warnings (HIGH confidence — well-documented limitation)
- `pgxpool` documentation: Default `MaxConns` calculation (HIGH confidence)
- RabbitMQ AMQP 0-9-1 specification: Queue declaration argument matching behavior (HIGH confidence)
- Go `filepath.Base` vs `path.Base` behavior differences (HIGH confidence — standard library behavior)

---

*Pitfalls audit: 2025-03-27*
