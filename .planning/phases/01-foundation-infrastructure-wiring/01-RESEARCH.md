# Phase 1: Foundation & Infrastructure Wiring - Research

**Researched:** 2026-03-27
**Domain:** Go service scaffolding, Docker containerization, backend connectivity (PostgreSQL, MinIO, RabbitMQ), health check, structured logging
**Confidence:** HIGH

## Summary

Phase 1 is pure infrastructure wiring with zero business logic. The goal is a Go binary that builds, runs in Docker Compose alongside existing Python services, connects to all three backends (PostgreSQL via pgxpool, MinIO via minio-go, RabbitMQ via amqp091-go), serves a `/health` endpoint that pings all backends, emits JSON-structured logs, and auto-creates the MinIO `uploads` bucket with a 1-day lifecycle expiration policy if missing.

All libraries are canonical Go choices with verified versions. The primary risks are: (1) `DATABASE_URL` format mismatch (`+asyncpg` prefix), (2) Go module path naming affecting future phases, (3) matching the MinIO lifecycle config exactly to the Python backend's `init_buckets()`, and (4) Docker not currently available in the WSL2 environment (requires Docker Desktop WSL integration activation). The Go code lives in `ingest/` at the project root with `cmd/ingest/main.go` + `internal/{config,server,health}` layout.

**Primary recommendation:** Build Phase 1 as a sequence: Go module init → config parsing → slog logging → backend clients (pgxpool, minio-go, amqp091-go) → health endpoint → Dockerfile → Docker Compose entry. Each step is independently verifiable via `go build` and `go test`. Docker Compose testing depends on Docker Desktop WSL2 integration being enabled.

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions
- **Location:** Top-level `ingest/` directory (mirrors `backend/`, `worker/`, `frontend/` pattern)
- **Internal structure:** Standard Go layout
  - `ingest/cmd/ingest/main.go` — entrypoint
  - `ingest/internal/config/` — configuration parsing
  - `ingest/internal/server/` — HTTP server setup
  - `ingest/internal/health/` — health check handler
- **Port:** 8080 (Go convention, avoids conflict with Python's 8000)
- **Docker Compose service name:** `ingest`
- **Container image:** `ghcr.io/daluoter/malscan-ingest:latest`
- **Same .env file** as Python backend — single source of truth
- Go strips `+asyncpg` from `DATABASE_URL` at parse time
- All existing env vars reused: `DATABASE_URL`, `MINIO_ENDPOINT`, `MINIO_ACCESS_KEY`, `MINIO_SECRET_KEY`, `MINIO_BUCKET_UPLOADS`, `RABBITMQ_URL`, `RABBITMQ_QUEUE`, `MAX_FILE_SIZE`, `LOG_LEVEL`, `CORS_ORIGINS`
- Use `caarlos0/env` for env parsing
- **Fail-fast:** Service refuses to start if any backend unreachable; no retry/backoff on startup
- Connections validated sequentially: PostgreSQL → MinIO → RabbitMQ
- **Single `/health` endpoint** checking all three backends; returns 200 + `{"status": "ok"}` or 503 + `{"status": "unhealthy", "details": {...}}`
- `log/slog` with JSON handler (zero-dependency)
- Structured fields: `service=ingest`, `version`, `request_id` (when applicable)
- Level controlled by `LOG_LEVEL` env var
- **Multi-stage build:** `golang:1.22-alpine` builder → `alpine:3.19` runtime
- Non-root user (uid 1000)
- Expose port 8080

### Locked Out of Scope for This Phase
- File upload handling (Phase 2)
- Database writes (Phase 3)
- RabbitMQ publishing (Phase 3)
- Nginx proxy routing (Phase 5)
- K8s manifests (Phase 5)
- Prometheus metrics, /ready endpoint (v2)

### Constraints Carried Forward
- Exact DB schema compatibility with existing `files` and `jobs` tables
- Same RabbitMQ message format for Python worker consumption
- MinIO bucket structure unchanged
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| OPS-03 | All configuration via environment variables: `DATABASE_URL`, `MINIO_*`, `RABBITMQ_URL`, `CORS_ORIGINS`, `MAX_FILE_SIZE`, `STAGES_TOTAL`, `LOG_LEVEL`, `PORT` | Config struct with `caarlos0/env` v11 struct tags; mirrors Python `config.py` exactly. See Config Pattern section. |
| DB-07 | `DATABASE_URL` parsing strips `+asyncpg` dialect prefix (`postgresql+asyncpg://` → `postgresql://` for pgx) | `strings.Replace(url, "+asyncpg", "", 1)` in config loader after env parse. Critical pitfall #1. |
| DB-06 | PostgreSQL connection pool via `pgxpool` configured for 10–50 concurrent uploads | `pgxpool.NewWithConfig()` with explicit `MaxConns=15`, `MinConns=2`, `MaxConnLifetime=30m`. Phase 1 establishes the pool; sizing validated in later phases. |
| OPS-02 | JSON structured logging via `log/slog` with fields: `level`, `msg`, `time` | `slog.NewJSONHandler(os.Stdout, opts)` with level from `LOG_LEVEL` env var. Default fields added via `slog.With()`. |
| OPS-01 | `GET /healthz` endpoint returns HTTP 200 when service is alive | Chi router with single `/health` route (CONTEXT.md says `/health` not `/healthz`). Pings pgxpool, MinIO `BucketExists`, and amqp091-go connection check. |
| OPS-05 | Multi-stage Dockerfile (`golang:alpine` → `alpine`) producing minimal static binary | `golang:1.22-alpine` builder with `CGO_ENABLED=0`, `alpine:3.19` runtime with non-root user (uid 1000). ~15-20MB image. |
| OPS-06 | Docker Compose service entry for `ingest` alongside existing `api`, `worker`, and infrastructure | New `ingest` service block in `docker-compose.yml` with env vars from shared `.env`, `depends_on` with healthcheck conditions for postgres, minio, rabbitmq. |
| STORE-02 | On startup, create MinIO `uploads` bucket if missing with 1-day lifecycle expiration policy | minio-go `BucketExists()` + `MakeBucket()` + `SetBucketLifecycle()` matching Python's exact config: rule ID `"1-day-expiry"`, `Expiration(days=1)`, filter prefix `""`. |
</phase_requirements>

## Project Constraints (from copilot-instructions.md)

- **GSD Workflow Enforcement:** Changes must go through GSD commands (`/gsd-execute-phase`), not direct edits
- **Go code conventions:** Follow existing project naming (snake_case for Python, but Go code follows Go conventions: camelCase for unexported, PascalCase for exported)
- **Configuration:** All config from `.env` files; backend config pattern in `backend/src/malscan/config.py` is the reference
- **Logging:** Structured JSON output; Python uses `structlog` with `event` key for message — Go `slog` uses `msg` key (accepted difference per CONTEXT.md)
- **Container images:** `ghcr.io/{OWNER}/malscan-*:latest` naming pattern
- **Security context:** K8s deploys with `runAsNonRoot: true, runAsUser: 1000`

## Standard Stack

### Core (Phase 1 Only)

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| Go | 1.22+ | Language runtime | Installed locally as 1.22.2. Provides `log/slog` (1.21+), goroutines, stdlib `net/http`. CONTEXT.md specifies `golang:1.22-alpine` Docker image. |
| go-chi/chi/v5 | v5.2.5 | HTTP router + middleware | Idiomatic `net/http.Handler` interface. Needed for `/health` endpoint routing and future middleware (CORS, recovery, logging). Zero transitive deps. |
| jackc/pgx/v5 | v5.9.1 | PostgreSQL driver + pool | Native PostgreSQL driver; `pgxpool` for connection pooling. Phase 1: connect + ping on startup. |
| minio/minio-go/v7 | v7.0.99 | MinIO S3 SDK | Official SDK. Phase 1: bucket existence check, bucket creation, lifecycle policy. |
| rabbitmq/amqp091-go | v1.10.0 | RabbitMQ AMQP client | Official RabbitMQ Go client. Phase 1: connect + confirm connection alive. |
| caarlos0/env/v11 | v11.4.0 | Env var parsing | Struct tag–based config binding. Equivalent to Python's pydantic-settings. Zero transitive deps. |
| log/slog (stdlib) | Go 1.21+ | Structured JSON logging | Zero deps. `slog.NewJSONHandler` produces `{"level","msg","time"}` JSON lines. |

### Phase 1 Only — Not Needed Yet

| Library | Version | Purpose | When Needed |
|---------|---------|---------|-------------|
| google/uuid | v1.6.0 | UUID v4 generation | Phase 3 (DB records) |
| cenkalti/backoff/v5 | v5.0.3 | Exponential retry | Phase 3 (RabbitMQ publish) |
| go-chi/cors | v1.2.2 | CORS middleware | Phase 4 (API contract) |
| prometheus/client_golang | v1.23.2 | Metrics | v2 (deferred) |

### Alternatives Considered

| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| chi v5 | stdlib `net/http.ServeMux` | Go 1.22+ ServeMux supports method routing, but lacks middleware chaining. Phase 1 only needs 1 route, but later phases need CORS, recovery, logging middleware. Start with chi to avoid rewrite. |
| caarlos0/env | `os.Getenv()` manual | Works for 3 vars but Phase 1 has 10+ with validation, defaults, type conversion. env eliminates boilerplate. |
| caarlos0/env | viper | 10x complexity for env-only config. Viper supports YAML, TOML, remote config — none needed. |

**Installation (Phase 1 deps only):**
```bash
cd ingest/
go mod init github.com/daluoter/malscan-ingest
go get github.com/go-chi/chi/v5@v5.2.5
go get github.com/jackc/pgx/v5@v5.9.1
go get github.com/minio/minio-go/v7@v7.0.99
go get github.com/rabbitmq/amqp091-go@v1.10.0
go get github.com/caarlos0/env/v11@v11.4.0
```

## Architecture Patterns

### Project Structure (Phase 1 Scope)

```
ingest/
├── cmd/
│   └── ingest/
│       └── main.go              # Entry point: config load, connect backends, start server
│
├── internal/
│   ├── config/
│   │   └── config.go            # Env var struct + DATABASE_URL transform
│   │
│   ├── server/
│   │   └── server.go            # HTTP server setup, chi router, graceful shutdown skeleton
│   │
│   └── health/
│       └── health.go            # /health handler: ping PG, MinIO, RabbitMQ
│
├── Dockerfile                    # Multi-stage: golang:1.22-alpine → alpine:3.19
├── go.mod
├── go.sum
└── .gitignore
```

**Note on CONTEXT.md endpoint path:** CONTEXT.md says `/health` endpoint. REQUIREMENTS.md (OPS-01) says `/healthz`. CONTEXT.md takes precedence as a locked decision. Use `/health`. The success criteria in the ROADMAP also says `GET /healthz` but CONTEXT.md is more specific: "Single `/health` endpoint." **Use `/health` as the primary path.** Optionally register both `/health` and `/healthz` to satisfy both documents.

### Pattern 1: Config Struct with caarlos0/env + DATABASE_URL Transform

**What:** Parse all env vars into a typed struct, then strip `+asyncpg` from DATABASE_URL.
**When to use:** At the very start of `main()`, before any connections.

```go
// internal/config/config.go
package config

import (
    "fmt"
    "log/slog"
    "strings"

    "github.com/caarlos0/env/v11"
)

type Config struct {
    DatabaseURL   string `env:"DATABASE_URL,required"`
    MinioEndpoint string `env:"MINIO_ENDPOINT,required"`
    MinioAccessKey string `env:"MINIO_ACCESS_KEY,required"`
    MinioSecretKey string `env:"MINIO_SECRET_KEY,required"`
    MinioSecure   bool   `env:"MINIO_SECURE"          envDefault:"false"`
    MinioBucket   string `env:"MINIO_BUCKET_UPLOADS"   envDefault:"uploads"`
    RabbitmqURL   string `env:"RABBITMQ_URL,required"`
    RabbitmqQueue string `env:"RABBITMQ_QUEUE"         envDefault:"malscan.jobs"`
    MaxFileSize   int64  `env:"MAX_FILE_SIZE"           envDefault:"104857600"`
    CORSOrigins   string `env:"CORS_ORIGINS"            envDefault:"*"`
    LogLevel      string `env:"LOG_LEVEL"               envDefault:"INFO"`
    Port          int    `env:"PORT"                    envDefault:"8080"`
    StagesTotal   int    `env:"STAGES_TOTAL"            envDefault:"5"`
}

func Load() (*Config, error) {
    cfg := &Config{}
    if err := env.Parse(cfg); err != nil {
        return nil, fmt.Errorf("parse config: %w", err)
    }

    // Strip SQLAlchemy asyncpg dialect from shared DATABASE_URL
    // "postgresql+asyncpg://..." → "postgresql://..."
    cfg.DatabaseURL = strings.Replace(cfg.DatabaseURL, "+asyncpg", "", 1)

    return cfg, nil
}
```

**Key points:**
- Python `config.py` has `database_url`, `minio_endpoint`, `minio_access_key`, `minio_secret_key`, `minio_bucket_uploads="uploads"`, `minio_secure=False`, `rabbitmq_url`, `rabbitmq_queue="malscan.jobs"`, `cors_origins="*"`, `log_level="INFO"`, `max_file_size=104857600`, `stages_total=5`
- Go config must match these exact env var names and defaults
- The `+asyncpg` strip MUST happen before any pgx connection attempt

**Confidence:** HIGH — direct port of Python config.py with well-documented env library

### Pattern 2: Fail-Fast Sequential Backend Connection

**What:** Connect to PostgreSQL, MinIO, RabbitMQ sequentially on startup. If any fails, log the error and exit immediately.
**When to use:** In `main()` after config load, before server start.

```go
// cmd/ingest/main.go (connection wiring)
func run() error {
    cfg, err := config.Load()
    if err != nil {
        return fmt.Errorf("load config: %w", err)
    }

    // PostgreSQL
    poolCfg, err := pgxpool.ParseConfig(cfg.DatabaseURL)
    if err != nil {
        return fmt.Errorf("parse database url: %w", err)
    }
    poolCfg.MaxConns = 15
    poolCfg.MinConns = 2
    poolCfg.MaxConnLifetime = 30 * time.Minute
    poolCfg.MaxConnIdleTime = 5 * time.Minute

    pool, err := pgxpool.NewWithConfig(context.Background(), poolCfg)
    if err != nil {
        return fmt.Errorf("create pg pool: %w", err)
    }
    defer pool.Close()

    if err := pool.Ping(context.Background()); err != nil {
        return fmt.Errorf("ping postgres: %w", err)
    }
    slog.Info("connected to PostgreSQL")

    // MinIO
    minioClient, err := minio.New(cfg.MinioEndpoint, &minio.Options{
        Creds:  credentials.NewStaticV4(cfg.MinioAccessKey, cfg.MinioSecretKey, ""),
        Secure: cfg.MinioSecure,
    })
    if err != nil {
        return fmt.Errorf("create minio client: %w", err)
    }
    // Verify connectivity by checking bucket
    exists, err := minioClient.BucketExists(context.Background(), cfg.MinioBucket)
    if err != nil {
        return fmt.Errorf("check minio bucket: %w", err)
    }
    if !exists {
        // Auto-create bucket + lifecycle (STORE-02)
        if err := minioClient.MakeBucket(context.Background(), cfg.MinioBucket, minio.MakeBucketOptions{}); err != nil {
            return fmt.Errorf("create bucket: %w", err)
        }
        // Set 1-day lifecycle expiration
        lcConfig := lifecycle.NewConfiguration()
        lcConfig.Rules = []lifecycle.Rule{
            {
                ID:     "1-day-expiry",
                Status: "Enabled",
                Expiration: lifecycle.Expiration{
                    Days: 1,
                },
            },
        }
        if err := minioClient.SetBucketLifecycle(context.Background(), cfg.MinioBucket, lcConfig); err != nil {
            return fmt.Errorf("set bucket lifecycle: %w", err)
        }
        slog.Info("created MinIO bucket with lifecycle", "bucket", cfg.MinioBucket, "expiry_days", 1)
    }
    slog.Info("connected to MinIO", "bucket", cfg.MinioBucket)

    // RabbitMQ
    amqpConn, err := amqp091.Dial(cfg.RabbitmqURL)
    if err != nil {
        return fmt.Errorf("connect rabbitmq: %w", err)
    }
    defer amqpConn.Close()
    slog.Info("connected to RabbitMQ")

    // ... start HTTP server
}
```

**Confidence:** HIGH — standard Go error handling pattern

### Pattern 3: Health Check Handler Pinging All Backends

**What:** `/health` endpoint that pings PostgreSQL, checks MinIO bucket exists, and verifies RabbitMQ connection is open.
**When to use:** Registered on chi router, called by Docker Compose/K8s health checks.

```go
// internal/health/health.go
type Checker struct {
    pool       *pgxpool.Pool
    minio      *minio.Client
    amqpConn   *amqp091.Connection
    bucket     string
}

func (c *Checker) Handle(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    details := make(map[string]string)
    healthy := true

    // PostgreSQL
    if err := c.pool.Ping(ctx); err != nil {
        details["postgres"] = err.Error()
        healthy = false
    } else {
        details["postgres"] = "ok"
    }

    // MinIO
    if _, err := c.minio.BucketExists(ctx, c.bucket); err != nil {
        details["minio"] = err.Error()
        healthy = false
    } else {
        details["minio"] = "ok"
    }

    // RabbitMQ
    if c.amqpConn.IsClosed() {
        details["rabbitmq"] = "connection closed"
        healthy = false
    } else {
        details["rabbitmq"] = "ok"
    }

    w.Header().Set("Content-Type", "application/json")
    if healthy {
        w.WriteHeader(http.StatusOK)
        json.NewEncoder(w).Encode(map[string]any{"status": "ok"})
    } else {
        w.WriteHeader(http.StatusServiceUnavailable)
        json.NewEncoder(w).Encode(map[string]any{"status": "unhealthy", "details": details})
    }
}
```

**Confidence:** HIGH — straightforward HTTP handler pattern

### Pattern 4: slog JSON Logger Setup with Level from Env

**What:** Configure `log/slog` default logger with JSON output, level from `LOG_LEVEL` env var.

```go
// In main() before any logging
func setupLogger(levelStr string) {
    var level slog.Level
    switch strings.ToUpper(levelStr) {
    case "DEBUG":
        level = slog.LevelDebug
    case "INFO":
        level = slog.LevelInfo
    case "WARN", "WARNING":
        level = slog.LevelWarn
    case "ERROR":
        level = slog.LevelError
    default:
        level = slog.LevelInfo
    }

    handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
        Level: level,
    })
    logger := slog.New(handler).With("service", "ingest")
    slog.SetDefault(logger)
}
```

**Output format:**
```json
{"time":"2026-03-27T12:00:00.000Z","level":"INFO","msg":"connected to PostgreSQL","service":"ingest"}
```

**Note:** Python structlog uses `event` for message key; Go slog uses `msg`. This is an accepted difference per the CONTEXT.md logging decision. Both produce JSON with `level` and `time` fields.

**Confidence:** HIGH — stdlib slog, no configuration pitfalls

### Pattern 5: Docker Multi-Stage Build

```dockerfile
# Build stage
FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /ingest ./cmd/ingest

# Runtime stage
FROM alpine:3.19
RUN adduser -D -u 1000 ingest
RUN apk add --no-cache ca-certificates
COPY --from=builder /ingest /ingest
USER ingest
EXPOSE 8080
ENTRYPOINT ["/ingest"]
```

**Key details:**
- `CGO_ENABLED=0` for static binary (no libc dependency)
- `-ldflags="-s -w"` strips debug info, reduces binary ~30%
- `ca-certificates` needed for TLS connections to MinIO if MINIO_SECURE=true
- Non-root `ingest` user with uid 1000 (matches K8s `runAsUser: 1000`)
- ~15-20MB final image

**Confidence:** HIGH — standard Go Docker pattern

### Pattern 6: Docker Compose Service Entry

```yaml
  ingest:
    build:
      context: ./ingest
      dockerfile: Dockerfile
    ports:
      - "8080:8080"
    env_file:
      - .env
    environment:
      # Override DATABASE_URL only if .env has the +asyncpg format
      # Go config strips +asyncpg at parse time, so this is safe to pass as-is
      PORT: 8080
    depends_on:
      postgres:
        condition: service_healthy
      minio:
        condition: service_healthy
      rabbitmq:
        condition: service_healthy
```

**Important:** The existing `docker-compose.yml` hardcodes env vars per service (not `env_file`). The `ingest` service should follow the same pattern OR use `env_file: .env` for simplicity — both work since the Go config strips `+asyncpg`. The CONTEXT.md says "same .env file" so `env_file` is the right approach.

**Confidence:** HIGH

### Anti-Patterns to Avoid

- **Global mutable state for connections:** Don't use `var db *pgxpool.Pool` at package level. Construct in `main()`, pass to handlers via struct fields.
- **Using `http.DefaultClient` for MinIO:** Default Go HTTP client has no timeouts. Configure MinIO with explicit transport timeouts.
- **Hardcoding connection strings:** All config from env vars, no defaults for required secrets.
- **Using `postgresql+asyncpg://` directly:** pgx cannot parse the `+asyncpg` dialect. Strip it.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Env var parsing with defaults + required + types | Manual `os.Getenv` + `strconv` for 10+ vars | `caarlos0/env/v11` struct tags | Eliminates boilerplate, handles required validation, type conversion, defaults. Exact equivalent of Python's pydantic-settings. |
| PostgreSQL connection pooling | Manual connection management | `pgxpool.Pool` from `jackc/pgx/v5` | Handles pool sizing, health checks, connection recycling, context cancellation. Battle-tested. |
| HTTP routing + middleware | Raw `http.ServeMux` | `go-chi/chi/v5` | Middleware chaining (CORS, recovery, logging) is needed by Phase 4. Starting with chi avoids rewrite. |
| MinIO bucket lifecycle configuration | Raw S3 XML API calls | `minio-go/v7` `SetBucketLifecycle()` | SDK handles XML serialization, auth signing, error handling. |

## Common Pitfalls

### Pitfall 1: DATABASE_URL `+asyncpg` Format Incompatibility
**What goes wrong:** The shared `DATABASE_URL` env var uses `postgresql+asyncpg://` (SQLAlchemy format). pgx cannot parse this — service crashes on startup with an opaque parse error.
**Why it happens:** Python and Go share the same `.env` file. The `+asyncpg` is a SQLAlchemy dialect marker.
**How to avoid:** `strings.Replace(cfg.DatabaseURL, "+asyncpg", "", 1)` immediately after env parse, before any pgx call. Log the transformed URL (with password masked).
**Warning signs:** pgx returns "cannot parse" error during `pgxpool.ParseConfig()`.

### Pitfall 2: pgxpool Default Sizing Too Low
**What goes wrong:** `pgxpool.New()` defaults to `max(4, runtime.NumCPU())` max connections. On a 2-vCPU container, that's 4 connections — too few for 50 concurrent uploads.
**Why it happens:** Developers use `pgxpool.New()` without explicit config.
**How to avoid:** Use `pgxpool.NewWithConfig()` with explicit `MaxConns=15`, `MinConns=2`. Total PostgreSQL connection budget: Python backend (30) + worker (15) + Go (15) = 60. Verify `max_connections` setting.
**Warning signs:** Connection acquire timeouts under load in later phases.

### Pitfall 3: MinIO Lifecycle Config Mismatch with Python
**What goes wrong:** Python's `init_buckets()` in `storage.py` sets lifecycle with rule ID `"1-day-expiry"`, `Expiration(days=1)`, filter prefix `""`. If Go sets different rule ID or filter, MinIO may create duplicate rules or overwrite.
**Why it happens:** Lifecycle API is idempotent for bucket creation but NOT for lifecycle rules — setting rules replaces the entire lifecycle config.
**How to avoid:** Match Python's lifecycle config exactly: rule ID `"1-day-expiry"`, status `"Enabled"`, expiration days 1, filter prefix empty. OR skip lifecycle setting if bucket already exists (Python owns lifecycle). CONTEXT.md requirement STORE-02 says Go must set it, so match exactly.
**Warning signs:** MinIO bucket has unexpected lifecycle rules; files not expiring as expected.

### Pitfall 4: Go Module Path Naming
**What goes wrong:** Using a generic module path like `module ingest` makes future extraction or refactoring painful.
**Why it happens:** Quick setup without thinking about module identity.
**How to avoid:** Use `github.com/daluoter/malscan-ingest` (matches container image naming pattern). Even if never published to a registry, a scoped path prevents import collisions.
**Warning signs:** None immediately — pain comes during multi-module refactoring.

### Pitfall 5: Docker Build Cache Invalidation
**What goes wrong:** `COPY . .` before `go mod download` means every code change re-downloads all dependencies, making builds slow (60s+ instead of 5s).
**Why it happens:** Single COPY step instead of separating dependency download from code compilation.
**How to avoid:** Two-step pattern: `COPY go.mod go.sum ./` → `RUN go mod download` → `COPY . .` → `RUN go build`. Dependencies are cached unless go.mod/go.sum change.
**Warning signs:** Docker builds take 60+ seconds for small code changes.

### Pitfall 6: RabbitMQ Connection vs Channel Confusion
**What goes wrong:** Phase 1 only needs to verify RabbitMQ connectivity. Opening a channel unnecessarily and not closing it properly can leave phantom channels. But checking only `amqp091.Dial()` success isn't enough — it could succeed but the vhost be inaccessible.
**Why it happens:** Incomplete connection validation.
**How to avoid:** In Phase 1, `Dial()` the connection and optionally open+close a channel to fully verify. Store the `*amqp091.Connection` for the health checker to call `.IsClosed()`. Don't create channels that persist — Phase 3 handles channel management.
**Warning signs:** Health check shows RabbitMQ as "ok" but channel operations fail in later phases.

### Pitfall 7: Health Endpoint Path Disagreement
**What goes wrong:** CONTEXT.md says `/health`, REQUIREMENTS.md (OPS-01) says `/healthz`, ROADMAP success criteria says `/healthz`. Using only one path may fail verification.
**Why it happens:** Different documents written at different times.
**How to avoid:** Register BOTH `/health` AND `/healthz` pointing to the same handler. Primary is `/health` per CONTEXT.md (locked decision). `/healthz` as an alias satisfies OPS-01.
**Warning signs:** Verification step fails because it checks the wrong path.

## Code Examples

### Example 1: Complete main.go for Phase 1

```go
// cmd/ingest/main.go
package main

import (
    "context"
    "fmt"
    "log/slog"
    "net/http"
    "os"
    "os/signal"
    "syscall"
    "time"

    "github.com/go-chi/chi/v5"
    "github.com/go-chi/chi/v5/middleware"
    "github.com/jackc/pgx/v5/pgxpool"
    amqp091 "github.com/rabbitmq/amqp091-go"
    "github.com/minio/minio-go/v7"
    "github.com/minio/minio-go/v7/pkg/credentials"

    "github.com/daluoter/malscan-ingest/internal/config"
    "github.com/daluoter/malscan-ingest/internal/health"
)

func main() {
    if err := run(); err != nil {
        slog.Error("fatal", "error", err)
        os.Exit(1)
    }
}

func run() error {
    // Load config (strips +asyncpg from DATABASE_URL)
    cfg, err := config.Load()
    if err != nil {
        return fmt.Errorf("load config: %w", err)
    }

    // Setup structured JSON logging
    setupLogger(cfg.LogLevel)
    slog.Info("starting ingest service", "port", cfg.Port)

    // Connect backends (fail-fast, sequential)
    pool, err := connectPostgres(cfg)
    if err != nil {
        return err
    }
    defer pool.Close()

    minioClient, err := connectMinio(cfg)
    if err != nil {
        return err
    }

    amqpConn, err := connectRabbitMQ(cfg)
    if err != nil {
        return err
    }
    defer amqpConn.Close()

    // Setup router
    r := chi.NewRouter()
    r.Use(middleware.Recoverer)

    checker := &health.Checker{
        Pool:     pool,
        Minio:    minioClient,
        AmqpConn: amqpConn,
        Bucket:   cfg.MinioBucket,
    }
    r.Get("/health", checker.Handle)
    r.Get("/healthz", checker.Handle) // alias for K8s compatibility

    // Start server with graceful shutdown
    srv := &http.Server{
        Addr:              fmt.Sprintf(":%d", cfg.Port),
        Handler:           r,
        ReadHeaderTimeout: 10 * time.Second,
    }

    go func() {
        slog.Info("server listening", "addr", srv.Addr)
        if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
            slog.Error("server error", "error", err)
        }
    }()

    // Wait for shutdown signal
    quit := make(chan os.Signal, 1)
    signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
    <-quit

    slog.Info("shutting down")
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()
    return srv.Shutdown(ctx)
}
```

### Example 2: MinIO Bucket Auto-Creation with Lifecycle (STORE-02)

```go
// Matching Python's storage.py init_buckets() exactly
import (
    "github.com/minio/minio-go/v7/pkg/lifecycle"
)

func ensureBucket(ctx context.Context, client *minio.Client, bucket string) error {
    exists, err := client.BucketExists(ctx, bucket)
    if err != nil {
        return fmt.Errorf("check bucket exists: %w", err)
    }

    if !exists {
        if err := client.MakeBucket(ctx, bucket, minio.MakeBucketOptions{}); err != nil {
            return fmt.Errorf("create bucket %q: %w", bucket, err)
        }
        slog.Info("bucket_created", "bucket", bucket)
    }

    // Always set lifecycle (idempotent — replaces existing config)
    // Matches Python: Rule(status="Enabled", rule_id="1-day-expiry",
    //                      expiration=Expiration(days=1), rule_filter=Filter(prefix=""))
    config := lifecycle.NewConfiguration()
    config.Rules = []lifecycle.Rule{
        {
            ID:     "1-day-expiry",
            Status: "Enabled",
            Expiration: lifecycle.Expiration{
                Days: lifecycle.ExpirationDays(1),
            },
        },
    }
    if err := client.SetBucketLifecycle(ctx, bucket, config); err != nil {
        return fmt.Errorf("set bucket lifecycle: %w", err)
    }
    slog.Info("bucket_lifecycle_configured", "bucket", bucket, "days", 1)

    return nil
}
```

**Note on lifecycle.Expiration.Days type:** In minio-go v7, `Expiration.Days` uses `ExpirationDays` type (an int alias). Verify at implementation time — the research-phase STACK.md confirmed minio-go v7.0.99.

### Example 3: caarlos0/env v11 Parsing

```go
import "github.com/caarlos0/env/v11"

// env.Parse populates struct from environment
cfg := &Config{}
if err := env.Parse(cfg); err != nil {
    // Returns descriptive error: 'env: required environment variable "DATABASE_URL" is not set'
    return nil, fmt.Errorf("parse config: %w", err)
}
```

The `env:"...,required"` tag causes `Parse` to return an error if the var is unset. `envDefault:"value"` provides defaults for optional vars.

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| `log` stdlib | `log/slog` (structured) | Go 1.21 (Aug 2023) | Phase 1 uses slog — no external logging lib needed |
| `net/http.ServeMux` (basic) | `net/http.ServeMux` with method routing | Go 1.22 (Feb 2024) | Could use stdlib router, but chi still better for middleware |
| `streadway/amqp` | `rabbitmq/amqp091-go` | 2021 (fork) | streadway is deprecated; amqp091-go is the official successor |

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Go | Build binary | ✓ | 1.22.2 | — |
| Docker | Build image, Compose | ✗ (WSL2 not integrated) | — | Enable Docker Desktop WSL integration; or build/test binary natively with `go build` and test against local services |
| docker compose | Run service stack | ✗ (WSL2 not integrated) | — | Same as Docker — requires Docker Desktop WSL integration |
| PostgreSQL client | Health check testing | ✗ (via Docker only) | — | Test with `go test` against Docker-hosted PG when Docker available |
| MinIO | Bucket creation testing | ✗ (via Docker only) | — | Same as PG |
| RabbitMQ | Connection testing | ✗ (via Docker only) | — | Same as PG |

**Missing dependencies with no fallback:**
- Docker/Docker Compose: Required for success criteria #1 (`docker compose up ingest`). The Dockerfile and docker-compose.yml can be written and validated syntactically, but actual container testing requires Docker Desktop WSL integration to be enabled. `go build` works natively for verifying the binary compiles.

**Missing dependencies with fallback:**
- None — all other dependencies are Go libraries resolved via `go get`.

**Implication for planning:** Tasks should be structured so Go code compilation (`go build ./...`) and unit tests (`go test ./...`) can be verified without Docker. Docker Compose integration is a separate verification step that may need the user to enable Docker Desktop WSL integration.

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | Go stdlib `testing` (Go 1.22.2) |
| Config file | None needed — Go test runner is built in |
| Quick run command | `cd ingest && go test ./...` |
| Full suite command | `cd ingest && go test -v -race ./...` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| OPS-03 | Config struct parses all env vars with correct defaults | unit | `go test ./internal/config/ -run TestConfigParse -v` | ❌ Wave 0 |
| DB-07 | DATABASE_URL strips `+asyncpg` prefix | unit | `go test ./internal/config/ -run TestDatabaseURLTransform -v` | ❌ Wave 0 |
| DB-06 | pgxpool created with explicit MaxConns/MinConns | unit | `go test ./internal/config/ -run TestPoolConfig -v` | ❌ Wave 0 |
| OPS-02 | slog produces JSON with level, msg, time fields | unit | `go test ./cmd/ingest/ -run TestLoggerOutput -v` | ❌ Wave 0 |
| OPS-01 | /health returns 200 when all backends healthy | unit (mock) | `go test ./internal/health/ -run TestHealthy -v` | ❌ Wave 0 |
| OPS-01 | /health returns 503 when any backend unhealthy | unit (mock) | `go test ./internal/health/ -run TestUnhealthy -v` | ❌ Wave 0 |
| OPS-05 | Dockerfile builds successfully | smoke | `docker build -t test-ingest ./ingest` | ❌ Wave 0 |
| OPS-06 | Docker Compose starts ingest service | integration | `docker compose up -d ingest && curl http://localhost:8080/health` | ❌ Wave 0 |
| STORE-02 | MinIO bucket created with lifecycle on startup | integration | `docker compose up -d ingest && mc ls myminio/uploads` | ❌ Wave 0 |

### Sampling Rate
- **Per task commit:** `cd ingest && go build ./... && go test ./...`
- **Per wave merge:** `cd ingest && go test -v -race ./... && go vet ./...`
- **Phase gate:** Full suite green + Docker Compose smoke test (if Docker available)

### Wave 0 Gaps
- [ ] `ingest/internal/config/config_test.go` — covers OPS-03, DB-07
- [ ] `ingest/internal/health/health_test.go` — covers OPS-01 (mock backends)
- [ ] Go module initialization: `go mod init` in `ingest/`
- [ ] No framework install needed — Go testing is stdlib

## Open Questions

1. **Health endpoint path: `/health` vs `/healthz`**
   - What we know: CONTEXT.md says `/health`, OPS-01 says `/healthz`, roadmap success criteria says `/healthz`
   - What's unclear: Which is authoritative
   - Recommendation: Register both paths to the same handler. Primary is `/health` per CONTEXT.md locked decision. `/healthz` as alias.

2. **Go version: 1.22 (local) vs 1.26 (research STACK.md)**
   - What we know: Local Go is 1.22.2. STACK.md recommends 1.26.x. CONTEXT.md says `golang:1.22-alpine` Docker image.
   - What's unclear: Whether to target 1.22 or 1.26 in go.mod
   - Recommendation: Use `go 1.22` in go.mod (matches installed version and CONTEXT.md Docker image). All needed features (slog, chi, pgx) work on 1.22. The Docker image can be updated later.

3. **MinIO lifecycle: always set vs only-if-new-bucket**
   - What we know: Python always sets lifecycle on startup (idempotent). STORE-02 says "auto-created with 1-day lifecycle if missing."
   - What's unclear: Whether to set lifecycle only when creating bucket or always
   - Recommendation: Always set lifecycle (matches Python behavior, is idempotent via `SetBucketLifecycle`). This ensures consistency even if lifecycle was manually removed.

4. **Docker availability in WSL2**
   - What we know: Docker commands fail — WSL2 integration not enabled
   - What's unclear: Whether user has Docker Desktop installed but not integrated, or no Docker at all
   - Recommendation: Plan assumes Docker will be available. Flag to user if Docker Compose steps cannot be verified. All Go code can be built and unit-tested without Docker.

## Sources

### Primary (HIGH confidence)
- **Direct codebase analysis:** `backend/src/malscan/config.py` (env var names, defaults), `backend/src/malscan/storage.py` (MinIO init_buckets lifecycle config), `backend/src/malscan/queue.py` (RabbitMQ queue args), `backend/src/malscan/main.py` (startup pattern, CORS, health endpoint)
- **Project research:** `.planning/research/STACK.md` (all Go library versions verified against proxy.golang.org), `.planning/research/ARCHITECTURE.md` (project layout, patterns), `.planning/research/PITFALLS.md` (20 pitfalls catalogued)
- **CONTEXT.md:** Phase 1 locked decisions (project layout, port, Docker, config approach)
- **docker-compose.yml:** Existing service definitions, env var patterns, healthcheck configs
- **k8s/api/deployment.yaml:** Security context pattern (runAsNonRoot, uid 1000)

### Secondary (MEDIUM confidence)
- **Go standard library docs:** `log/slog`, `net/http`, `os/signal` — all stdlib since Go 1.21+
- **caarlos0/env v11 README:** Struct tag syntax, required/default behavior

### Tertiary (LOW confidence)
- **minio-go lifecycle API:** `lifecycle.ExpirationDays` type needs verification at implementation time — API may have changed between minio-go versions
- **pgxpool default MaxConns calculation:** Based on research docs; verify with actual `pgxpool.Config` inspection at implementation

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — all versions from pre-verified STACK.md research, Go 1.22 available locally
- Architecture: HIGH — standard Go patterns, direct port of Python config/startup
- Pitfalls: HIGH — 7 Phase 1–specific pitfalls identified from codebase analysis + ecosystem knowledge

**Research date:** 2026-03-27
**Valid until:** 2026-04-27 (stable — Go libraries are well-versioned, no fast-moving APIs)
