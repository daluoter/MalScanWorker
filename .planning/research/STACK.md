# Technology Stack

**Project:** MalScanWorker — Go Ingestion Layer
**Researched:** 2026-03-27
**Overall Confidence:** HIGH — All versions verified against Go module proxy (`proxy.golang.org`), all libraries are well-established with active maintenance.

## Recommended Stack

### Language & Runtime

| Technology | Version | Purpose | Why | Confidence |
|------------|---------|---------|-----|------------|
| Go | 1.26.x | Language runtime | Latest stable (1.26.1 confirmed via go.dev/dl). Goroutines provide true parallelism for concurrent uploads — the entire reason for this microservice. Go 1.22+ added method-based routing to stdlib ServeMux. Go 1.21+ includes `log/slog` for structured logging. | HIGH |

**Go version rationale:** The project targets 10–50 simultaneous uploads. Go's goroutine scheduler handles this natively without thread pool ceilings. The Python service hits its `ThreadPoolExecutor(max_workers=4)` limit on MinIO uploads and runs SHA256 hashing on the event loop (CPU-bound blocking async). Go eliminates both bottlenecks.

### HTTP Framework

| Technology | Version | Purpose | Why | Confidence |
|------------|---------|---------|-----|------------|
| go-chi/chi/v5 | v5.2.5 | HTTP router + middleware | Idiomatic — implements `net/http.Handler` interface (no proprietary context types). Built-in middleware chain with `r.Use(...)` for CORS, recovery, request size limit, logging. Only 2–3 routes but middleware composition is critical for production quality. Zero magic, trivial to understand. | HIGH |
| go-chi/cors | v1.2.2 | CORS middleware | Chi-native CORS middleware. Matches existing FastAPI CORS config (configurable origins, all methods). Keeps everything in the chi ecosystem. | HIGH |

### Database

| Technology | Version | Purpose | Why | Confidence |
|------------|---------|---------|-----|------------|
| jackc/pgx/v5 | v5.9.1 | PostgreSQL driver + connection pool | THE Go PostgreSQL driver. pgxpool (same module) provides connection pooling. Native PostgreSQL wire protocol (not `database/sql` adapter) = lower overhead. Supports UUID, TIMESTAMPTZ, JSONB natively. Matches existing asyncpg driver behavior. | HIGH |

**pgx usage pattern:** Use `pgxpool.Pool` directly (not `database/sql`). The service runs exactly 3 queries per upload: 1 SELECT (dedup check), 1-2 INSERTs (file + job), inside a transaction. Raw SQL with `pgx.CollectOneRow` / named args — no ORM needed.

**Connection string:** The existing `DATABASE_URL` uses `postgresql+asyncpg://...` format. Go's pgx accepts standard `postgresql://` or `postgres://` URIs. Strip the `+asyncpg` prefix in config parsing or use a separate env var.

### Object Storage

| Technology | Version | Purpose | Why | Confidence |
|------------|---------|---------|-----|------------|
| minio/minio-go/v7 | v7.0.99 | MinIO / S3-compatible object storage SDK | Official MinIO Go SDK. `PutObject` accepts `io.Reader` + size — enables streaming upload without buffering entire file in memory. Handles bucket operations, lifecycle config. Matches existing Python `minio` 7.2.0 SDK behavior exactly. | HIGH |

**Key pattern:** The existing Python service uses `fput_object` (upload from file path). The Go service should use `PutObject` with an `io.Reader` wrapping the temp file — more idiomatic and enables future zero-temp-file streaming.

### Message Queue

| Technology | Version | Purpose | Why | Confidence |
|------------|---------|---------|-----|------------|
| rabbitmq/amqp091-go | v1.10.0 | RabbitMQ AMQP 0-9-1 client | Official RabbitMQ Go client (maintained by RabbitMQ team). Supports persistent messages, queue declaration with DLX arguments, connection recovery. Must match existing queue config: durable queue `malscan.jobs`, DLX routing to `malscan-dlq`. | HIGH |

**Message format (must match exactly):**
```json
{
  "job_id": "uuid-string",
  "file_id": "uuid-string",
  "storage_key": "sha256-hex",
  "sha256": "sha256-hex",
  "original_filename": "sanitized-name"
}
```
Published to default exchange with routing key `malscan.jobs`, delivery mode = persistent.

### Logging

| Technology | Version | Purpose | Why | Confidence |
|------------|---------|---------|-----|------------|
| log/slog (stdlib) | Go 1.21+ stdlib | Structured JSON logging | Zero dependencies. Built into Go since 1.21. `slog.NewJSONHandler(os.Stdout, nil)` produces JSON output compatible with existing structlog format. Supports key-value structured fields natively. The Go ecosystem has standardized on slog as the logging interface — zerolog and zap now provide slog adapters. | HIGH |

**Why not zerolog/zap:** Both are excellent, but slog is stdlib — no dependency, no version management, no breaking changes across updates. For a microservice with straightforward logging needs (request start, upload progress, DB operations, errors), slog is sufficient. The performance difference is irrelevant when the bottleneck is file I/O and network calls.

### Metrics

| Technology | Version | Purpose | Why | Confidence |
|------------|---------|---------|-----|------------|
| prometheus/client_golang | v1.23.2 | Prometheus metrics | Standard Go Prometheus client. Exposes `/metrics` endpoint. Define histograms for upload latency, counters for upload count/errors, gauge for in-flight uploads. Matches existing FastAPI prometheus-fastapi-instrumentator pattern. | HIGH |

**Metrics to expose:**
- `ingest_upload_duration_seconds` (histogram) — end-to-end upload time
- `ingest_uploads_total` (counter, labels: status=success|error) — upload count
- `ingest_uploads_inflight` (gauge) — concurrent uploads in progress
- `ingest_upload_bytes_total` (counter) — total bytes ingested
- `ingest_minio_duration_seconds` (histogram) — MinIO upload time
- `ingest_db_duration_seconds` (histogram) — DB transaction time
- `ingest_rabbitmq_duration_seconds` (histogram) — RabbitMQ publish time

### Configuration

| Technology | Version | Purpose | Why | Confidence |
|------------|---------|---------|-----|------------|
| caarlos0/env/v11 | v11.4.0 | Environment variable parsing | Struct tag-based env var binding: `env:"DATABASE_URL,required"`. Type conversion, defaults, required validation. Equivalent to Python's pydantic-settings. Actively maintained (latest: Feb 2026). | HIGH |

**Config struct pattern:**
```go
type Config struct {
    DatabaseURL    string `env:"DATABASE_URL,required"`
    MinioEndpoint  string `env:"MINIO_ENDPOINT,required"`
    MinioAccessKey string `env:"MINIO_ACCESS_KEY,required"`
    MinioSecretKey string `env:"MINIO_SECRET_KEY,required"`
    MinioSecure    bool   `env:"MINIO_SECURE"         envDefault:"false"`
    MinioBucket    string `env:"MINIO_BUCKET_UPLOADS"  envDefault:"uploads"`
    RabbitmqURL    string `env:"RABBITMQ_URL,required"`
    RabbitmqQueue  string `env:"RABBITMQ_QUEUE"        envDefault:"malscan.jobs"`
    MaxFileSize    int64  `env:"MAX_FILE_SIZE"          envDefault:"104857600"`
    CORSOrigins    string `env:"CORS_ORIGINS"           envDefault:"*"`
    LogLevel       string `env:"LOG_LEVEL"              envDefault:"INFO"`
    Port           int    `env:"PORT"                   envDefault:"8080"`
    StagesTotal    int    `env:"STAGES_TOTAL"           envDefault:"5"`
    MetricsPort    int    `env:"METRICS_PORT"           envDefault:"9090"`
}
```

### Supporting Libraries

| Library | Version | Purpose | Why | Confidence |
|---------|---------|---------|-----|------------|
| google/uuid | v1.6.0 | UUID v4 generation | Standard Go UUID library. Existing schema uses UUID4 PKs — must generate compatible values. `uuid.New()` produces v4. | HIGH |
| cenkalti/backoff/v5 | v5.0.3 | Exponential backoff retry | Equivalent to Python's `tenacity`. Used for RabbitMQ publish retries (5 attempts, 1s→16s exponential). Clean API: `backoff.Retry(operation, backoff.NewExponentialBackOff())`. | HIGH |

### Testing

| Technology | Version | Purpose | Why | Confidence |
|------------|---------|---------|-----|------------|
| testing (stdlib) | Go stdlib | Unit test framework | Go's built-in test runner. Table-driven tests are idiomatic. `go test ./...` runs everything. | HIGH |
| stretchr/testify | v1.11.1 | Test assertions + mocking | `assert.Equal`, `require.NoError` reduce boilerplate. `mock.Mock` for interface mocking. De facto standard in Go testing. | HIGH |
| testcontainers/testcontainers-go | v0.41.0 | Integration test containers | Spin up real PostgreSQL, MinIO, RabbitMQ containers in tests. Tests against real infrastructure, not mocks. Critical for verifying schema compatibility with existing Python service. | MEDIUM |

### Build & Quality

| Technology | Version | Purpose | Why | Confidence |
|------------|---------|---------|-----|------------|
| golangci-lint | v1.64.8 | Linter aggregator | Runs 50+ linters in one pass: `govet`, `staticcheck`, `errcheck`, `gosec`, etc. Standard in Go CI pipelines. | HIGH |
| Docker multi-stage build | — | Container image | `golang:1.26-alpine` for build → `alpine:3.19` for runtime. Produces ~15MB final image (vs ~200MB for Python). | HIGH |

## Alternatives Considered

| Category | Recommended | Alternative | Why Not |
|----------|-------------|-------------|---------|
| HTTP Router | chi v5 | **stdlib net/http.ServeMux** | Go 1.22+ ServeMux supports `POST /path` patterns, but lacks middleware chaining. Composing CORS + recovery + size limit + logging + metrics manually is error-prone. Chi adds ~500 LOC of dependency for significant DX improvement. |
| HTTP Router | chi v5 | **Gin** | Gin uses its own `gin.Context` instead of `http.Request`/`http.ResponseWriter`. Breaks stdlib compatibility. Heavier. Brings opinions we don't need (binding, rendering). Popular ≠ right. |
| HTTP Router | chi v5 | **Fiber** | Uses `fasthttp` instead of `net/http`. Incompatible with standard Go middleware ecosystem. Optimized for benchmark charts, not real-world upload handling. |
| HTTP Router | chi v5 | **Echo** | Similar to Gin — custom context type. Less ecosystem adoption than chi. No compelling advantage for this use case. |
| Database | pgx v5 (native) | **database/sql + pgx adapter** | Adds overhead of `database/sql` abstraction layer. We don't need driver portability (Postgres-only). pgx native is ~20% faster for scans and supports Postgres-specific types directly. |
| Database | pgx v5 (raw SQL) | **GORM** | Massive overkill for 3 queries. Adds reflection overhead, query generation complexity, and debugging difficulty. This service does: 1 SELECT, 1-2 INSERTs. Raw SQL with pgx is ~15 LOC. |
| Database | pgx v5 (raw SQL) | **sqlc** | Code-generation from SQL queries. Good for larger projects. Overkill for 3 queries. Adds build step complexity. Consider if query count grows beyond 10. |
| Database | pgx v5 (raw SQL) | **sqlx** | Wraps `database/sql` — same overhead concern. Struct scanning is nice but pgx v5 has `pgx.CollectOneRow` with `pgx.RowToStructByName` which does the same thing natively. |
| Logging | slog (stdlib) | **zerolog** | Faster allocation-free logging. But: (1) slog is stdlib with zero deps, (2) logging is not the bottleneck in a file upload service, (3) ecosystem is converging on slog as the standard interface. |
| Logging | slog (stdlib) | **zap** | Same reasoning as zerolog. Zap is excellent but adds dependency for marginal benefit. Both zerolog and zap now offer slog adapters — the ecosystem has spoken. |
| Config | caarlos0/env | **viper** | Viper supports YAML, TOML, JSON, remote config, file watching. We need: env vars. Only env vars. Viper is 10x the complexity for 1/10 the need. |
| Config | caarlos0/env | **kelseyhightower/envconfig** | Less actively maintained. caarlos0/env has more features (nested structs, slices, custom parsers) and recent releases (Feb 2026 vs envconfig's last in 2022). |
| Config | caarlos0/env | **Manual os.Getenv** | Works for 3 vars. With 10+ vars, validation, defaults, and type conversion — caarlos0/env eliminates boilerplate and bugs. |
| RabbitMQ | amqp091-go | **streadway/amqp** | Deprecated. amqp091-go IS the official fork, maintained by the RabbitMQ team. streadway/amqp's README redirects to amqp091-go. |
| Retry | cenkalti/backoff | **Manual retry loop** | Works, but cenkalti/backoff handles jitter, max elapsed time, context cancellation, and provides a clean functional API. Well-tested library vs hand-rolled retry logic. |
| UUID | google/uuid | **gofrs/uuid** | Both work. google/uuid is more widely adopted and has simpler API. No functional difference for UUID v4 generation. |

## Architecture-Relevant Stack Decisions

### Streaming Upload Pattern (Critical)

The service must handle 100MB files without buffering entirely in memory. The Go stack enables:

1. **`http.Request.Body`** → `io.Reader` for multipart parsing
2. **`mime/multipart.Reader.NextPart()`** → Stream individual form parts
3. **`io.TeeReader`** → Fork stream to SHA256 hasher + temp file simultaneously
4. **`os.CreateTemp`** → Write to disk as chunks arrive (1MB chunks, matching Python)
5. **`minio.PutObject(reader, size)`** → Upload from temp file to MinIO

This eliminates the Python bottleneck where the entire file was buffered before MinIO upload.

### Connection Pool Sizing

| Service | Pool Config | Rationale |
|---------|------------|-----------|
| PostgreSQL (pgxpool) | Min: 2, Max: 10 | Each upload needs 1 connection for ~10ms (SELECT + INSERT + COMMIT). At 50 concurrent uploads, 10 connections with ~10ms hold time = 50 ops/sec capacity. Matches existing Python pool (10 base + 20 overflow) scaled for Go's lower per-query overhead. |
| RabbitMQ (amqp091-go) | 1 connection, 1 channel | AMQP connections are expensive. One persistent connection with one channel handles the publish load. amqp091-go supports channel-level flow control. If publish throughput becomes an issue, add channels (not connections). |
| MinIO (minio-go) | Default (no pool, per-request HTTP) | minio-go uses Go's `http.Client` with `http.Transport` internally. `http.Transport` has connection pooling built in (default: 100 idle conns, 2 per host). No manual pool needed. |

### Graceful Shutdown Sequence

Go's `context.Context` + `signal.NotifyContext` + `http.Server.Shutdown` provide native graceful shutdown:

1. Receive SIGTERM/SIGINT
2. Stop accepting new HTTP connections (`server.Shutdown(ctx)`)
3. Wait for in-flight uploads to complete (context timeout: 30s)
4. Close RabbitMQ connection
5. Close pgxpool
6. Exit

This is simpler than Python's shutdown dance with asyncio + uvicorn.

## Installation

```bash
# Initialize Go module
go mod init github.com/your-org/malscan-ingest

# Core dependencies
go get github.com/go-chi/chi/v5@v5.2.5
go get github.com/go-chi/cors@v1.2.2
go get github.com/jackc/pgx/v5@v5.9.1
go get github.com/minio/minio-go/v7@v7.0.99
go get github.com/rabbitmq/amqp091-go@v1.10.0
go get github.com/prometheus/client_golang@v1.23.2
go get github.com/google/uuid@v1.6.0
go get github.com/caarlos0/env/v11@v11.4.0
go get github.com/cenkalti/backoff/v5@v5.0.3

# Test dependencies
go get github.com/stretchr/testify@v1.11.1
go get github.com/testcontainers/testcontainers-go@v0.41.0

# Dev tools (install, not go get)
go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.64.8
```

## Dockerfile (Multi-Stage)

```dockerfile
# Build stage
FROM golang:1.26-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /ingest ./cmd/ingest

# Runtime stage
FROM alpine:3.19
RUN apk add --no-cache ca-certificates
COPY --from=builder /ingest /ingest
EXPOSE 8080 9090
ENTRYPOINT ["/ingest"]
```

Target image size: ~15-20MB (vs ~350MB for Python 3.11-slim + dependencies).

## Dependency Count

| Component | Dependencies Added |
|-----------|-------------------|
| chi v5 | 0 transitive (pure Go, no deps) |
| pgx v5 | ~5 transitive (jackc/* family) |
| minio-go v7 | ~10 transitive (crypto, XML parsing) |
| amqp091-go | 0 transitive (pure Go) |
| prometheus/client_golang | ~5 transitive (protobuf, procfs) |
| google/uuid | 0 transitive |
| caarlos0/env v11 | 0 transitive |
| cenkalti/backoff v5 | 0 transitive |
| **Total** | **~9 direct, ~20 transitive** |

This is a lean dependency tree. The Python backend has 50+ transitive dependencies.

## Sources

All versions verified against Go module proxy (`proxy.golang.org`) on 2026-03-27:

- Go 1.26.1: https://go.dev/dl/ (confirmed latest stable)
- pgx v5.9.1: `proxy.golang.org/github.com/jackc/pgx/v5/@latest` (2026-03-22)
- minio-go v7.0.99: `proxy.golang.org/github.com/minio/minio-go/v7/@latest` (2026-03-04)
- amqp091-go v1.10.0: `proxy.golang.org/github.com/rabbitmq/amqp091-go/@latest` (2024-05-08)
- chi v5.2.5: `proxy.golang.org/github.com/go-chi/chi/v5/@latest` (2026-02-05)
- chi/cors v1.2.2: `proxy.golang.org/github.com/go-chi/cors/@latest` (2025-07-01)
- zerolog v1.34.0 (evaluated, not selected): `proxy.golang.org/github.com/rs/zerolog/@latest`
- zap v1.27.1 (evaluated, not selected): `proxy.golang.org/go.uber.org/zap/@latest`
- prometheus/client_golang v1.23.2: `proxy.golang.org/github.com/prometheus/client_golang/@latest` (2025-09-05)
- google/uuid v1.6.0: `proxy.golang.org/github.com/google/uuid/@latest` (2024-01-23)
- caarlos0/env v11.4.0: `proxy.golang.org/github.com/caarlos0/env/v11/@latest` (2026-02-22)
- cenkalti/backoff v5.0.3: `proxy.golang.org/github.com/cenkalti/backoff/v5/@latest` (2025-07-23)
- testify v1.11.1: `proxy.golang.org/github.com/stretchr/testify/@latest` (2025-08-27)
- testcontainers-go v0.41.0: `proxy.golang.org/github.com/testcontainers/testcontainers-go/@latest` (2026-03-10)
- golangci-lint v1.64.8: `proxy.golang.org/github.com/golangci/golangci-lint/@latest` (2025-03-17)
