# Architecture Patterns

**Domain:** Go file ingestion microservice integrated into existing Python malware analysis pipeline
**Researched:** 2025-03-27
**Confidence:** HIGH — based on direct codebase analysis, established Go project conventions, and well-understood integration patterns

## Recommended Architecture

### System Overview: Sidecar Upload Service with Proxy-Based Routing

The Go ingestion service operates as a **sidecar upload service** — a standalone microservice owning exactly one route (`POST /api/v1/files`) while the existing FastAPI backend retains all other endpoints. An Nginx reverse proxy at the edge splits traffic by path, making the split transparent to the frontend.

```
                          ┌─────────────────────────────┐
                          │          Nginx Proxy         │
                          │   (path-based routing)       │
                          └──────┬──────────────┬────────┘
                                 │              │
                    POST /api/v1/files    All other routes
                                 │              │
                                 ▼              ▼
                    ┌────────────────┐  ┌──────────────────┐
                    │  Go Ingestion  │  │  FastAPI Backend  │
                    │  Service       │  │  (Python)         │
                    │  :8080         │  │  :8000            │
                    └───┬───┬───┬───┘  └──────────────────┘
                        │   │   │
              ┌─────────┘   │   └─────────┐
              ▼             ▼             ▼
        ┌──────────┐ ┌───────────┐ ┌───────────┐
        │PostgreSQL│ │   MinIO   │ │ RabbitMQ  │
        │  :5432   │ │   :9000   │ │   :5672   │
        └──────────┘ └───────────┘ └───────────┘
                                         │
                                         ▼
                               ┌──────────────────┐
                               │  Python Worker    │
                               │  (unchanged)      │
                               └──────────────────┘
```

**Key insight:** Both the Go service and the FastAPI backend are **readers and writers** to the same PostgreSQL database. They share no in-process state — coordination happens entirely through the database and RabbitMQ. This is the simplest correct integration pattern.

### Component Boundaries

| Component | Responsibility | Communicates With | Port | Owned By |
|-----------|---------------|-------------------|------|----------|
| **Nginx Proxy** | Path-based routing, CORS headers, request body limit | Go service (upstream), FastAPI (upstream) | 80/443 | New (this milestone) |
| **Go Ingestion Service** | Multipart upload, SHA256 hashing, MinIO storage, File/Job DB writes, RabbitMQ publish | PostgreSQL (pgx), MinIO (minio-go), RabbitMQ (amqp091-go) | 8080 | New (this milestone) |
| **FastAPI Backend** | Job status, reports, SSE streaming, health checks | PostgreSQL (asyncpg), RabbitMQ (aio_pika), MinIO | 8000 | Existing (unchanged) |
| **Python Worker** | Job consumption, pipeline execution, analysis stages | PostgreSQL, MinIO, RabbitMQ, ClamAV, YARA | N/A (consumer) | Existing (unchanged) |
| **PostgreSQL** | Persistent storage: `files` table, `jobs` table | All services | 5432 | Existing (unchanged) |
| **MinIO** | Object storage for uploaded files (SHA256-keyed) | Go service (write), Worker (read), FastAPI (write via sub-jobs) | 9000 | Existing (unchanged) |
| **RabbitMQ** | Job queue (`malscan.jobs`), DLQ (`malscan-dlq`) | Go service (publish), Worker (consume), FastAPI (publish for sub-jobs) | 5672 | Existing (unchanged) |

### Hard Boundary Rules

1. **Go service NEVER reads job status or results** — that's FastAPI's domain
2. **Go service NEVER creates sub-jobs** — the worker's `InternalJobSubmitter` handles recursive analysis
3. **Go service writes to `files` and `jobs` tables ONLY during upload** — insert-only, never update
4. **FastAPI NEVER handles `POST /api/v1/files`** — proxy routes this exclusively to Go
5. **RabbitMQ message format is the contract** — Go must produce identical JSON to what the worker consumer expects

## Data Flow

### Upload Path (Go Service — New)

```
Frontend                   Nginx              Go Service          MinIO        PostgreSQL      RabbitMQ
   │                         │                    │                 │              │              │
   │  POST /api/v1/files     │                    │                 │              │              │
   │  multipart/form-data    │                    │                 │              │              │
   │────────────────────────>│                    │                 │              │              │
   │                         │  proxy_pass :8080  │                 │              │              │
   │                         │───────────────────>│                 │              │              │
   │                         │                    │                 │              │              │
   │                         │        ┌───────────┤ Parse multipart │              │              │
   │                         │        │  Stream   │ form field      │              │              │
   │                         │        │  chunks   │                 │              │              │
   │                         │        │  1MB each │                 │              │              │
   │                         │        │           │                 │              │              │
   │                         │        │  For each chunk:            │              │              │
   │                         │        │  • Accumulate file_size     │              │              │
   │                         │        │  • Check size limit         │              │              │
   │                         │        │  • Update SHA256 hasher     │              │              │
   │                         │        │  • Write to temp file       │              │              │
   │                         │        └───────────┤                 │              │              │
   │                         │                    │                 │              │              │
   │                         │                    │  fput_object()  │              │              │
   │                         │                    │────────────────>│              │              │
   │                         │                    │     OK          │              │              │
   │                         │                    │<────────────────│              │              │
   │                         │                    │                 │              │              │
   │                         │                    │  BEGIN TX                      │              │
   │                         │                    │  SELECT files WHERE sha256=?   │              │
   │                         │                    │──────────────────────────────>│              │
   │                         │                    │  (dedup check)                │              │
   │                         │                    │<──────────────────────────────│              │
   │                         │                    │  INSERT files (if new)        │              │
   │                         │                    │  INSERT jobs (status=queued)  │              │
   │                         │                    │  COMMIT TX                    │              │
   │                         │                    │──────────────────────────────>│              │
   │                         │                    │     OK                        │              │
   │                         │                    │<──────────────────────────────│              │
   │                         │                    │                 │              │              │
   │                         │                    │  Publish persistent message   │              │
   │                         │                    │  {job_id, file_id,            │              │
   │                         │                    │   storage_key, sha256,        │              │
   │                         │                    │   original_filename}          │              │
   │                         │                    │────────────────────────────────────────────>│
   │                         │                    │     ACK                       │              │
   │                         │                    │<────────────────────────────────────────────│
   │                         │                    │                 │              │              │
   │                         │  201 Created       │                 │              │              │
   │                         │<───────────────────│                 │              │              │
   │  {job_id, file_id,      │                    │                 │              │              │
   │   sha256, status,       │                    │                 │              │              │
   │   created_at}           │                    │                 │              │              │
   │<────────────────────────│                    │                 │              │              │
```

### Critical Data Contracts

**RabbitMQ Message (must match exactly — worker depends on these fields):**
```json
{
  "job_id": "uuid-string",
  "file_id": "uuid-string",
  "storage_key": "sha256-hex-string",
  "sha256": "sha256-hex-string",
  "original_filename": "sanitized-filename.ext"
}
```
- Queue: `malscan.jobs` (durable)
- Delivery mode: persistent (delivery_mode=2)
- Content-type: `application/json`
- Exchange: default exchange, routing key = queue name
- DLQ args on queue: `x-dead-letter-exchange: ""`, `x-dead-letter-routing-key: "malscan-dlq"`

**HTTP Response (must match exactly — frontend depends on this schema):**
```json
{
  "job_id": "uuid-string",
  "file_id": "uuid-string",
  "sha256": "sha256-hex-string",
  "status": "queued",
  "created_at": "2025-03-27T12:00:00.000000+00:00"
}
```
- Status code: 201 Created
- Content-Type: `application/json`

**Database Writes (must match existing SQLAlchemy models exactly):**

`files` table INSERT:
| Column | Type | Value |
|--------|------|-------|
| `id` | UUID | Go-generated UUIDv4 |
| `sha256` | VARCHAR(64) | Hex-encoded SHA256 |
| `size` | INTEGER | Total bytes |
| `filename` | VARCHAR(255) | Sanitized filename |
| `content_type` | VARCHAR(100) | MIME from multipart header |
| `created_at` | TIMESTAMPTZ | `NOW()` |

`jobs` table INSERT:
| Column | Type | Value |
|--------|------|-------|
| `id` | UUID | Go-generated UUIDv4 |
| `file_id` | UUID | FK to files.id |
| `status` | VARCHAR(20) | `"queued"` |
| `current_stage` | VARCHAR(50) | `NULL` |
| `stages_done` | INTEGER | `0` |
| `stages_total` | INTEGER | `5` (from config) |
| `error_message` | TEXT | `NULL` |
| `result` | JSONB | `NULL` |
| `created_at` | TIMESTAMPTZ | `NOW()` |
| `updated_at` | TIMESTAMPTZ | `NOW()` |
| `parent_job_id` | UUID | `NULL` or valid parent UUID |
| `depth` | INTEGER | `0` or parent.depth + 1 |
| `total_sub` | INTEGER | `0` |
| `completed_sub` | INTEGER | `0` |
| `malicious_sub` | INTEGER | `0` |

## Go Project Layout

Use the standard Go project layout conventions. This is a single-binary service, not a library — keep it simple.

```
go-ingest/
├── cmd/
│   └── ingest/
│       └── main.go              # Entry point: config load, wire dependencies, start server
│
├── internal/                     # Private application code (not importable externally)
│   ├── config/
│   │   └── config.go            # Env var parsing (DATABASE_URL, MINIO_*, RABBITMQ_URL, etc.)
│   │
│   ├── handler/
│   │   └── upload.go            # HTTP handler: multipart parsing, streaming, orchestrates upload
│   │
│   ├── middleware/
│   │   ├── cors.go              # CORS middleware
│   │   ├── logging.go           # Request logging middleware (JSON structured logs)
│   │   └── recovery.go          # Panic recovery middleware
│   │
│   ├── model/
│   │   ├── file.go              # File struct matching `files` table schema
│   │   └── job.go               # Job struct matching `jobs` table schema + JobStatus constants
│   │
│   ├── storage/
│   │   └── minio.go             # MinIO client: bucket init, fput_object wrapper
│   │
│   ├── queue/
│   │   └── rabbitmq.go          # RabbitMQ publisher: connect, declare queue, publish with retry
│   │
│   ├── db/
│   │   └── postgres.go          # pgx pool: connect, file dedup query, file+job insert in TX
│   │
│   ├── sanitize/
│   │   └── filename.go          # Filename sanitization (port of Python _sanitize_filename)
│   │
│   └── server/
│       └── server.go            # HTTP server setup, graceful shutdown, route registration
│
├── Dockerfile                    # Multi-stage build (builder → scratch/distroless)
├── go.mod
├── go.sum
└── README.md
```

### Layout Rationale

| Decision | Rationale |
|----------|-----------|
| `cmd/ingest/main.go` | Standard Go convention for binary entry points. Allows future `cmd/` additions (e.g., `cmd/migrate/`) |
| `internal/` over `pkg/` | This is a private service, not a library. `internal/` enforces that nothing outside this module imports these packages |
| Flat `internal/` packages | One package per concern (handler, storage, queue, db). No nested subpackages — the service is small enough |
| No `api/` or `proto/` dirs | No shared API definitions needed — the contract is the existing Python schema. Go just matches it |
| `model/` separate from `db/` | Models are plain Go structs used by handler and db. DB package handles SQL. Clean separation |
| `sanitize/` package | Filename sanitization is a clear, testable unit. Exact port of Python's `_sanitize_filename()` |

### Why NOT These Alternatives

| Rejected Pattern | Reason |
|-----------------|--------|
| Monolithic `main.go` | Untestable. Handler, DB, queue logic all tangled together |
| `pkg/` directory | Nothing should be importable outside this module. `internal/` enforces this at the language level |
| Domain-driven / hexagonal | Overkill for a single-endpoint service. Clean Architecture adds indirection without value here |
| Interface-heavy design | Only abstract where tests need it (DB and queue for mocking). Concrete types everywhere else |
| Repository pattern | One table insert and one dedup check don't warrant a repository. Direct pgx queries in `db/` are fine |

## Patterns to Follow

### Pattern 1: Streaming Multipart Without Full Buffering

**What:** Read the multipart file field as a stream, writing to a temp file in 1MB chunks while simultaneously computing the SHA256 hash. Never hold the entire file in memory.

**Why:** Files up to 100MB. Buffering kills memory under concurrent load (50 uploads × 100MB = 5GB).

**Example:**
```go
// internal/handler/upload.go
func (h *UploadHandler) handleUpload(w http.ResponseWriter, r *http.Request) {
    // Limit total request body (150MB matches existing Python config)
    r.Body = http.MaxBytesReader(w, r.Body, 150*1024*1024)

    // Parse multipart form — maxMemory controls memory threshold before temp files
    // 1MB means only 1MB buffered in memory; rest spills to disk automatically
    if err := r.ParseMultipartForm(1 << 20); err != nil {
        // handle error
    }

    file, header, err := r.FormFile("file")
    if err != nil {
        // handle error
    }
    defer file.Close()

    // Create temp file for streaming
    tmpFile, err := os.CreateTemp("", "ingest-*")
    if err != nil { /* handle */ }
    defer os.Remove(tmpFile.Name())
    defer tmpFile.Close()

    hasher := sha256.New()
    // io.TeeReader: every byte read goes to both hasher and temp file
    tee := io.TeeReader(file, hasher)

    written, err := io.Copy(tmpFile, tee)
    if err != nil { /* handle */ }

    if written > int64(h.cfg.MaxFileSize) {
        // Return 400 FILE_TOO_LARGE
    }

    sha256Hex := hex.EncodeToString(hasher.Sum(nil))
    // ... proceed to MinIO upload, DB insert, RabbitMQ publish
}
```

**Confidence:** HIGH — standard Go I/O composition pattern

### Pattern 2: Database Transaction for Atomic File+Job Creation

**What:** Wrap the file dedup check, file insert (if new), and job insert in a single PostgreSQL transaction. If any step fails, nothing is committed.

**Why:** Matches the existing Python behavior where `db.flush()` + `db.commit()` ensures atomicity. A partial write (file without job, or job without file) would leave orphaned records.

**Example:**
```go
// internal/db/postgres.go
func (d *DB) CreateFileAndJob(ctx context.Context, f *model.File, j *model.Job) error {
    tx, err := d.pool.Begin(ctx)
    if err != nil {
        return fmt.Errorf("begin tx: %w", err)
    }
    defer tx.Rollback(ctx) // no-op if committed

    // Dedup check
    var existingFileID uuid.UUID
    err = tx.QueryRow(ctx,
        `SELECT id FROM files WHERE sha256 = $1`, f.SHA256,
    ).Scan(&existingFileID)

    if err == pgx.ErrNoRows {
        // Insert new file
        _, err = tx.Exec(ctx,
            `INSERT INTO files (id, sha256, size, filename, content_type, created_at)
             VALUES ($1, $2, $3, $4, $5, $6)`,
            f.ID, f.SHA256, f.Size, f.Filename, f.ContentType, f.CreatedAt,
        )
        if err != nil {
            return fmt.Errorf("insert file: %w", err)
        }
        j.FileID = f.ID
    } else if err == nil {
        j.FileID = existingFileID
    } else {
        return fmt.Errorf("dedup check: %w", err)
    }

    // Insert job
    _, err = tx.Exec(ctx,
        `INSERT INTO jobs (id, file_id, status, stages_total, created_at, updated_at,
                          parent_job_id, depth, total_sub, completed_sub, malicious_sub)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 0, 0, 0)`,
        j.ID, j.FileID, "queued", j.StagesTotal, j.CreatedAt, j.UpdatedAt,
        j.ParentJobID, j.Depth,
    )
    if err != nil {
        return fmt.Errorf("insert job: %w", err)
    }

    return tx.Commit(ctx)
}
```

**Confidence:** HIGH — standard pgx transaction pattern

### Pattern 3: RabbitMQ Publish with Exponential Backoff Retry

**What:** Publish to RabbitMQ with up to 5 retries using exponential backoff (1s → 2s → 4s → 8s → 16s). If all retries fail, mark the job as FAILED in the database.

**Why:** Exactly matches the existing Python tenacity retry logic in `backend/src/malscan/queue.py`. The worker expects messages on `malscan.jobs` with persistent delivery mode.

**Example:**
```go
// internal/queue/rabbitmq.go
func (q *Publisher) PublishWithRetry(ctx context.Context, msg JobMessage) error {
    body, _ := json.Marshal(msg)

    var lastErr error
    for attempt := 0; attempt < 5; attempt++ {
        err := q.ch.PublishWithContext(ctx,
            "",              // default exchange
            q.queueName,     // routing key = queue name
            false,           // mandatory
            false,           // immediate
            amqp091.Publishing{
                DeliveryMode: amqp091.Persistent,
                ContentType:  "application/json",
                Body:         body,
            },
        )
        if err == nil {
            return nil
        }
        lastErr = err
        backoff := time.Duration(1<<attempt) * time.Second // 1, 2, 4, 8, 16
        time.Sleep(backoff)
    }
    return fmt.Errorf("publish failed after 5 attempts: %w", lastErr)
}
```

**Confidence:** HIGH — direct port of existing Python retry logic

### Pattern 4: Dependency Injection via Constructor (No Frameworks)

**What:** Pass concrete dependencies (DB pool, MinIO client, RabbitMQ publisher) into handlers via constructor. No DI framework, no global singletons.

**Why:** Go idiom. Makes testing straightforward — inject mocks or test doubles. Avoids the global-singleton pattern used in the Python codebase (which is harder to test).

**Example:**
```go
// cmd/ingest/main.go
func main() {
    cfg := config.Load()

    dbPool := db.Connect(cfg.DatabaseURL)
    defer dbPool.Close()

    minioClient := storage.NewClient(cfg)
    publisher := queue.NewPublisher(cfg.RabbitMQURL, cfg.RabbitMQQueue)
    defer publisher.Close()

    handler := handler.NewUploadHandler(dbPool, minioClient, publisher, cfg)
    srv := server.New(handler, cfg)
    srv.ListenAndServe() // includes graceful shutdown
}
```

**Confidence:** HIGH — standard Go application wiring

### Pattern 5: Graceful Shutdown with In-Flight Upload Draining

**What:** On SIGTERM/SIGINT, stop accepting new connections but allow in-flight uploads to complete within a deadline (e.g., 30 seconds).

**Why:** Kubernetes sends SIGTERM before killing pods. Uploads are long-running (100MB over slow network). Abruptly killing mid-upload means lost data and stuck-QUEUED jobs.

**Example:**
```go
// internal/server/server.go
func (s *Server) ListenAndServe() error {
    srv := &http.Server{
        Addr:              s.addr,
        Handler:           s.handler,
        ReadHeaderTimeout: 10 * time.Second,
        WriteTimeout:      5 * time.Minute, // large for big uploads
        IdleTimeout:       120 * time.Second,
    }

    go srv.ListenAndServe()

    quit := make(chan os.Signal, 1)
    signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
    <-quit

    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()
    return srv.Shutdown(ctx) // drains in-flight requests
}
```

**Confidence:** HIGH — idiomatic Go server lifecycle

### Pattern 6: Structured JSON Logging (structlog-Compatible)

**What:** Emit all logs as JSON with fields matching the existing structlog format: `msg`, `level`, `job_id`, `file_id`, `sha256`, `duration_ms`, etc.

**Why:** Existing log pipeline (if any) expects JSON. Both services' logs should be parseable by the same tooling. Use `log/slog` (stdlib since Go 1.21) — no external dependency needed.

**Example:**
```go
// cmd/ingest/main.go
logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
    Level: slog.LevelInfo,
}))
slog.SetDefault(logger)

// Usage in handlers:
slog.Info("file_upload_started",
    "filename", filename,
    "content_type", contentType,
)
```

**Confidence:** HIGH — `log/slog` is stdlib since Go 1.21, mature and stable

## Anti-Patterns to Avoid

### Anti-Pattern 1: Sharing Database Connection Pool with FastAPI

**What:** Attempting to share a single PostgreSQL connection pool between Go and Python services.

**Why bad:** Impossible across process boundaries. Each service must have its own pool. The DATABASE_URL env var is shared, but each service creates its own pool from it.

**Instead:** Go service creates its own `pgxpool.Pool`. Python keeps `asyncpg`. Both connect to the same PostgreSQL server. Connection pool sizing matters — Go service should use `max_conns=10-20` (not hundreds) since the database is shared.

### Anti-Pattern 2: Using Go's `net/http` Default Client for MinIO

**What:** Using `http.DefaultClient` or letting the MinIO Go SDK use defaults with no timeout configuration.

**Why bad:** Default Go HTTP client has no timeout. A hung MinIO connection blocks a goroutine forever, eventually exhausting resources under load.

**Instead:** Configure the MinIO client with explicit transport timeouts:
```go
transport := &http.Transport{
    MaxIdleConns:        100,
    MaxIdleConnsPerHost: 10,
    IdleConnTimeout:     90 * time.Second,
}
minioClient, _ := minio.New(endpoint, &minio.Options{
    Transport: transport,
    // ...
})
```

### Anti-Pattern 3: Buffering Entire File Before Processing

**What:** Reading the entire multipart file into a `[]byte` before hashing or uploading.

**Why bad:** 50 concurrent 100MB uploads = 5GB memory. OOM kill.

**Instead:** Stream to temp file + hash simultaneously (Pattern 1 above). Then `FPutObject` the temp file to MinIO — MinIO Go SDK streams from disk.

### Anti-Pattern 4: Using `asyncpg` Connection String Format Directly

**What:** Passing `DATABASE_URL=postgresql+asyncpg://...` directly to pgx.

**Why bad:** The `+asyncpg` dialect prefix is SQLAlchemy-specific. `pgx` won't parse it.

**Instead:** The Go config loader must strip/replace the dialect prefix:
```go
// "postgresql+asyncpg://user:pass@host/db" → "postgresql://user:pass@host/db"
dsn = strings.Replace(dsn, "postgresql+asyncpg://", "postgresql://", 1)
```

### Anti-Pattern 5: Global Mutable State for Connections

**What:** Package-level `var db *pgxpool.Pool` globals initialized in `init()`.

**Why bad:** Untestable, hidden dependencies, race conditions during init, can't control lifecycle.

**Instead:** Construct in `main()`, pass to handlers (Pattern 4 above).

## Deployment Architecture

### Docker Compose (Local Development)

Add the Go service and Nginx proxy as new services alongside existing ones:

```yaml
# New services added to existing docker-compose.yml

  go-ingest:
    build:
      context: ./go-ingest
      dockerfile: Dockerfile
    ports:
      - "8080:8080"           # Direct access for debugging
    environment:
      DATABASE_URL: postgresql://postgres:postgres@postgres:5432/malscan
      MINIO_ENDPOINT: minio:9000
      MINIO_ACCESS_KEY: minioadmin
      MINIO_SECRET_KEY: minioadmin
      MINIO_BUCKET: uploads
      MINIO_SECURE: "false"
      RABBITMQ_URL: amqp://guest:guest@rabbitmq:5672/
      RABBITMQ_QUEUE: malscan.jobs
      STAGES_TOTAL: "5"
      MAX_FILE_SIZE: "104857600"
      CORS_ORIGINS: "http://localhost:5173,http://localhost:3000"
      LOG_LEVEL: info
    depends_on:
      postgres:
        condition: service_healthy
      minio:
        condition: service_healthy
      rabbitmq:
        condition: service_healthy

  nginx:
    image: nginx:alpine
    ports:
      - "8888:80"             # Frontend hits this unified endpoint
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
    depends_on:
      - api
      - go-ingest
```

**Note:** The `DATABASE_URL` for Go uses `postgresql://` not `postgresql+asyncpg://`. The Go config must handle this difference.

### Nginx Routing Config

```nginx
upstream go_ingest {
    server go-ingest:8080;
}

upstream fastapi {
    server api:8000;
}

server {
    listen 80;
    client_max_body_size 150M;

    # Upload route → Go service
    location = /api/v1/files {
        proxy_pass http://go_ingest;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_request_buffering off;    # Stream body directly to Go
        proxy_read_timeout 300s;        # 5 min for large uploads
    }

    # Health check for Go service
    location = /healthz {
        proxy_pass http://go_ingest;
    }

    # Everything else → FastAPI
    location / {
        proxy_pass http://fastapi;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header Connection '';
        proxy_http_version 1.1;
        chunked_transfer_encoding off;  # Required for SSE
        proxy_buffering off;            # Required for SSE
        proxy_cache off;                # Required for SSE
    }
}
```

**Critical Nginx setting:** `proxy_request_buffering off` — without this, Nginx buffers the entire upload body before forwarding to Go, defeating streaming.

### Kubernetes Deployment

New manifests in `k8s/go-ingest/`:

```yaml
# k8s/go-ingest/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: malscan-go-ingest
  namespace: malscan
spec:
  replicas: 2                      # Scale independently of FastAPI
  selector:
    matchLabels:
      app: malscan-go-ingest
  template:
    metadata:
      labels:
        app: malscan-go-ingest
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "9090"
        prometheus.io/path: "/metrics"
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
      containers:
        - name: go-ingest
          image: ghcr.io/daluoter/malscan-go-ingest:latest
          ports:
            - containerPort: 8080
            - containerPort: 9090   # Prometheus metrics
          envFrom:
            - configMapRef:
                name: malscan-config
            - secretRef:
                name: malscan-secrets
          resources:
            requests:
              memory: "64Mi"        # Go is lightweight
              cpu: "50m"
            limits:
              memory: "256Mi"       # Temp file I/O, not RAM-heavy
              cpu: "500m"
          startupProbe:
            httpGet:
              path: /healthz
              port: 8080
            initialDelaySeconds: 2
            periodSeconds: 5
            failureThreshold: 6
          livenessProbe:
            httpGet:
              path: /healthz
              port: 8080
            periodSeconds: 10
          readinessProbe:
            httpGet:
              path: /healthz
              port: 8080
            periodSeconds: 5
          securityContext:
            readOnlyRootFilesystem: true
            allowPrivilegeEscalation: false
          volumeMounts:
            - name: tmp-volume
              mountPath: /tmp
      volumes:
        - name: tmp-volume
          emptyDir:
            sizeLimit: 500Mi       # Prevent temp files from filling node
```

**Resource sizing rationale:**
- 64Mi request / 256Mi limit — Go binary is ~15MB. Each upload streams to temp file then deletes it. Memory steady-state is low.
- 50m CPU request / 500m limit — SHA256 hashing is the only CPU work. Network I/O dominates.
- Startup probe: 2s initial delay (Go starts in <1s, not like Python/JVM).
- emptyDir with sizeLimit: prevents a flood of uploads from filling the node's disk.

### Dockerfile (Multi-Stage Build)

```dockerfile
# Build stage
FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /ingest ./cmd/ingest/

# Runtime stage
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /ingest /ingest
EXPOSE 8080 9090
ENTRYPOINT ["/ingest"]
```

**Why distroless over scratch:** Scratch has no CA certificates (needed for HTTPS to MinIO if `MINIO_SECURE=true`), no timezone data, no `/tmp`. Distroless includes these while remaining minimal (~2MB).

## Concurrency Model

### Go Service Concurrency (How It Handles 50 Simultaneous Uploads)

```
                 ┌──────────────────────────────────────────────────┐
                 │              Go HTTP Server (net/http)           │
                 │                                                  │
                 │  Request arrives → goroutine spawned per request │
                 │                                                  │
                 │  goroutine 1: Upload A (hashing + streaming)     │
                 │  goroutine 2: Upload B (MinIO put_object)        │
                 │  goroutine 3: Upload C (DB transaction)          │
                 │  goroutine 4: Upload D (RabbitMQ publish)        │
                 │  ...                                             │
                 │  goroutine 50: Upload Z (reading chunks)         │
                 │                                                  │
                 │  All goroutines share:                           │
                 │  • pgxpool.Pool (connection pool, thread-safe)   │
                 │  • amqp091 Channel (thread-safe for publish)     │
                 │  • minio.Client (thread-safe)                    │
                 └──────────────────────────────────────────────────┘
```

**Why this beats the Python approach:**
- Python: `asyncio` event loop + 4-thread `ThreadPoolExecutor` for MinIO. Upload #5 blocks waiting for a thread.
- Go: Each upload is a goroutine. I/O blocks only that goroutine. 50 uploads = 50 goroutines, all progressing concurrently. No thread pool bottleneck.

### Connection Pool Sizing

| Resource | Pool Size | Rationale |
|----------|-----------|-----------|
| PostgreSQL (pgxpool) | `min=2, max=15` | 50 concurrent uploads but each TX is fast (~5ms). 15 connections handle spikes. Don't starve FastAPI/worker. |
| MinIO HTTP transport | `MaxIdleConnsPerHost=10` | MinIO uploads are the slowest part (~seconds). 10 idle connections covers burst without waste. |
| RabbitMQ | 1 connection, 1 channel | AMQP channel multiplexes. One channel handles thousands of publishes/sec. Channel is goroutine-safe for publish. |

## Suggested Build Order

Dependencies between components dictate the implementation sequence:

### Phase 1: Core Foundation (No External Dependencies)
Build order: config → model → sanitize

1. **`internal/config/config.go`** — Environment variable parsing. Everything else depends on config.
2. **`internal/model/file.go` + `job.go`** — Plain structs. No dependencies. Define once, use everywhere.
3. **`internal/sanitize/filename.go`** — Pure function, port of Python's `_sanitize_filename()`. Unit test immediately.

**Why first:** These are leaf dependencies. Every other package imports them. Building these first lets you write tests for the entire chain.

### Phase 2: Infrastructure Clients (External Connections)
Build order: db → storage → queue (order within phase doesn't matter)

4. **`internal/db/postgres.go`** — pgx pool creation, dedup query, atomic file+job insert. Test with a real PostgreSQL instance.
5. **`internal/storage/minio.go`** — MinIO client creation, bucket init, `FPutObject` wrapper. Test with a real MinIO instance.
6. **`internal/queue/rabbitmq.go`** — AMQP connection, queue declaration, publish with retry. Test with a real RabbitMQ instance.

**Why second:** These depend on config + model. Integration tests need Docker containers for PostgreSQL, MinIO, RabbitMQ — can use the existing docker-compose infra.

### Phase 3: HTTP Layer
Build order: handler → middleware → server

7. **`internal/handler/upload.go`** — The core upload handler. Orchestrates streaming → hashing → MinIO → DB → RabbitMQ → response. Depends on all Phase 2 components.
8. **`internal/middleware/`** — CORS, logging, recovery. Generic, handler-independent.
9. **`internal/server/server.go`** — HTTP server setup, route registration, graceful shutdown.

**Why third:** The handler is the integration point that wires together DB + storage + queue. Can't build it until those exist. The server is just wiring.

### Phase 4: Entry Point + Deployment

10. **`cmd/ingest/main.go`** — Wire everything together. Load config, create clients, create handler, start server.
11. **`Dockerfile`** — Multi-stage build.
12. **`docker-compose.yml` update** — Add go-ingest service.
13. **`nginx/nginx.conf`** — Proxy routing config.

**Why last:** Pure integration and deployment. Nothing to implement, just wiring and config.

### Phase 5: Kubernetes + Observability

14. **`k8s/go-ingest/deployment.yaml`** — Deployment + Service manifests.
15. **Prometheus metrics endpoint** — `/metrics` on port 9090. Upload count, latency histogram, error rate, in-flight gauge.
16. **Health check endpoint** — `GET /healthz` checks PostgreSQL, MinIO, RabbitMQ connectivity.

**Why last:** Requires working service to validate. Metrics and health are additive, not foundational.

### Build Order Dependency Graph

```
Phase 1 (foundation):
  config ─────────────────────────────┐
  model ──────────────────────────────┤
  sanitize ───────────────────────────┤
                                      │
Phase 2 (clients):                    │
  db ← config, model                  │
  storage ← config                    │
  queue ← config, model               │
                                      │
Phase 3 (HTTP):                       │
  handler ← db, storage, queue,       │
             sanitize, model, config   │
  middleware ← config                  │
  server ← handler, middleware         │
                                      │
Phase 4 (wiring):                     │
  main.go ← everything                │
  Dockerfile                           │
  docker-compose update                │
  nginx config                         │
                                      │
Phase 5 (ops):                        │
  k8s manifests                        │
  prometheus metrics ← handler         │
  health check ← db, storage, queue    │
```

## Scalability Considerations

| Concern | At 10 users | At 100 concurrent uploads | At 1000 concurrent uploads |
|---------|-------------|---------------------------|----------------------------|
| **Go service CPU** | Negligible | SHA256 hashing saturates ~2 cores | Need multiple replicas (k8s HPA) |
| **Go service memory** | ~20MB | ~50MB (goroutine stacks) | ~200MB (goroutine stacks + overhead) |
| **Temp disk** | Trivial | 10GB peak (100 × 100MB) | 100GB peak — need PV, not emptyDir |
| **PostgreSQL connections** | 2-3 | Pool max=15 sufficient | Pool max=25 + PgBouncer |
| **MinIO throughput** | No concern | Network-bound | MinIO cluster or multi-node |
| **RabbitMQ** | 1 channel | 1 channel still fine | Multiple channels or connections |
| **Nginx** | Default config | Tune worker_connections | Dedicated Ingress controller |

**Practical ceiling without changes:** The Go service on a single pod with defaults handles ~100 concurrent uploads comfortably. Beyond that, horizontal scaling (more pods) is the answer — the service is stateless.

## Sources

- **Codebase analysis:** Direct inspection of `backend/src/malscan/api/routes.py`, `queue.py`, `storage.py`, `models/`, `schemas/`, `config.py`
- **Worker contract:** Direct inspection of `worker/src/malscan_worker/consumer.py`, `pipeline.py`
- **Deployment patterns:** Direct inspection of `docker-compose.yml`, `k8s/api/deployment.yaml`, `k8s/configmap.yaml`
- **Go project layout:** [golang-standards/project-layout](https://github.com/golang-standards/project-layout) conventions — `cmd/`, `internal/`
- **Go stdlib:** `net/http` server, `crypto/sha256`, `io.TeeReader`, `log/slog` — all stdlib since Go 1.21+
- **pgx:** Standard Go PostgreSQL driver with native connection pooling via `pgxpool`
- **minio-go:** Official MinIO Go SDK with `FPutObject` for file-path uploads
- **amqp091-go:** Maintained AMQP 0.9.1 client for Go (successor to streadway/amqp)

---

*Architecture analysis: 2025-03-27*
