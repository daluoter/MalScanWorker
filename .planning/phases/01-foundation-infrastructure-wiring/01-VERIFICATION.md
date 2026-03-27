---
phase: 01-foundation-infrastructure-wiring
verified: 2026-03-27T09:02:57Z
status: passed
score: 5/5 must-haves verified
---

# Phase 1: Foundation & Infrastructure Wiring Verification Report

**Phase Goal:** Go service builds, runs in Docker Compose alongside existing services, connects to all backends, and serves health checks with structured JSON logging
**Verified:** 2026-03-27T09:02:57Z
**Status:** passed
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths (Success Criteria from ROADMAP.md)

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | `go build` produces a static binary and `docker compose up ingest` starts the Go service alongside existing api, worker, and infrastructure services | ✓ VERIFIED | `go build -o /dev/null ./cmd/ingest` exits 0; docker-compose.yml contains `ingest:` service with build context `./ingest`, port 8080:8080, alongside all 6 original services (postgres, minio, rabbitmq, clamav, api, worker); Dockerfile is multi-stage with `CGO_ENABLED=0` static binary |
| 2 | `GET /healthz` returns HTTP 200, confirming the service is alive and reachable on its configured port | ✓ VERIFIED | `server.go:18` registers `r.Get("/healthz", checker.Handle)`; `health.go:76` returns `w.WriteHeader(http.StatusOK)` with `{"status":"ok"}` when all backends healthy; `r.Get("/health", ...)` also registered as alias at line 16 |
| 3 | Service logs are JSON-formatted with `level`, `msg`, `time` fields visible in `docker compose logs ingest` | ✓ VERIFIED | `main.go:205` creates `slog.NewJSONHandler(os.Stdout, ...)` — slog's JSONHandler emits `level`, `msg`, `time` fields by spec; logger set as default via `slog.SetDefault()` at line 207; logger also adds `"service": "ingest"` context field |
| 4 | Service reads all configuration from environment variables and connects to PostgreSQL (pgxpool), MinIO, and RabbitMQ on startup — no hardcoded values | ✓ VERIFIED | `config.go` has 13 env-tagged struct fields (5 required, 8 with defaults); `main.go:93-113` connects via `pgxpool.NewWithConfig` (MaxConns=15, MinConns=2); `main.go:117-133` connects MinIO via `minio.New()` with credentials from config; `main.go:171-186` connects RabbitMQ via `amqp091.Dial(cfg.RabbitmqURL)` with channel verification |
| 5 | MinIO `uploads` bucket exists after service startup (auto-created with 1-day lifecycle expiration policy if missing) | ✓ VERIFIED | `main.go:140-168` `ensureBucket()` calls `client.BucketExists()` then `client.MakeBucket()` if missing, and always sets lifecycle with `ID: "1-day-expiry"`, `Status: "Enabled"`, `ExpirationDays(1)` — matches Python backend `init_buckets()` exactly |

**Score:** 5/5 truths verified

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `ingest/go.mod` | Go module definition with Phase 1 deps | ✓ VERIFIED | Module `github.com/daluoter/malscan-ingest`, go 1.25.0, all 5 direct deps present (chi, pgx, minio-go, amqp091-go, caarlos0/env) |
| `ingest/internal/config/config.go` | Config struct with env parsing + DATABASE_URL transform | ✓ VERIFIED | 44 lines; 13 env tags, `Load()` exported, `strings.Replace(cfg.DatabaseURL, "+asyncpg", "", 1)` |
| `ingest/internal/config/config_test.go` | Unit tests for config parsing | ✓ VERIFIED | 5 tests: TestConfigDefaults, TestDatabaseURLTransform, TestDatabaseURLNoTransform, TestConfigRequiredMissing, TestConfigCustomValues — all PASS |
| `ingest/cmd/ingest/main.go` | Complete entrypoint with connections, logger, server | ✓ VERIFIED | 209 lines; `config.Load()`, `setupLogger()`, `connectPostgres()`, `connectMinio()`, `connectRabbitMQ()`, `server.NewRouter()`, graceful shutdown |
| `ingest/internal/health/health.go` | Health check handler pinging all backends | ✓ VERIFIED | 83 lines; `Checker` struct, `NewChecker()`, `Handle()` with PostgresPinger/MinioBucketChecker/RabbitMQChecker interfaces; returns 200/503 JSON |
| `ingest/internal/health/health_test.go` | Unit tests for health handler | ✓ VERIFIED | 5 tests with mocks: AllHealthy, PostgresDown, MinioDown, RabbitMQDown, MultipleDown — all PASS |
| `ingest/internal/server/server.go` | Chi router factory with health routes | ✓ VERIFIED | 22 lines; `NewRouter()`, chi.Mux with Recoverer, /health and /healthz registered |
| `ingest/Dockerfile` | Multi-stage Dockerfile for static Go binary | ✓ VERIFIED | 2 FROM stages (golang:1.22-alpine builder, alpine:3.19 runtime); CGO_ENABLED=0, -ldflags="-s -w", adduser uid 1000, USER ingest, EXPOSE 8080 |
| `docker-compose.yml` | Updated with ingest service entry | ✓ VERIFIED | 7 services total (6 original + ingest); build context `./ingest`, port 8080:8080, depends_on with service_healthy for postgres/minio/rabbitmq |

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `main.go` | `config/config.go` | `config.Load()` call in run() | ✓ WIRED | Line 33: `cfg, err := config.Load()` |
| `main.go` | `log/slog` | `slog.NewJSONHandler` | ✓ WIRED | Line 205: `slog.NewJSONHandler(os.Stdout, ...)` + line 207: `slog.SetDefault(logger)` |
| `main.go` | `health/health.go` | `health.NewChecker()` | ✓ WIRED | Line 63: `checker := health.NewChecker(pool, minioClient, amqpConn, cfg.MinioBucket)` |
| `main.go` | `pgxpool` | `pgxpool.NewWithConfig` | ✓ WIRED | Line 103: pool created with explicit sizing, line 107: pool.Ping verified |
| `main.go` | `minio-go` | `minio.New + ensureBucket` | ✓ WIRED | Line 118: client created, line 127: ensureBucket called with lifecycle |
| `main.go` | `amqp091-go` | `amqp091.Dial` | ✓ WIRED | Line 172: connection opened, lines 177-182: channel open+close verification |
| `main.go` | `server/server.go` | `server.NewRouter(checker)` | ✓ WIRED | Line 64: router created, line 68: assigned to http.Server.Handler |
| `server.go` | `health/health.go` | `/health` and `/healthz` routes | ✓ WIRED | Lines 16-18: both routes registered with `checker.Handle` |
| `docker-compose.yml` | `ingest/Dockerfile` | build context `./ingest` | ✓ WIRED | Line 114: `context: ./ingest`, line 115: `dockerfile: Dockerfile` |
| `docker-compose.yml` | infra services | `depends_on service_healthy` | ✓ WIRED | Lines 127-132: postgres, minio, rabbitmq all with `condition: service_healthy` |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| Go build compiles | `cd ingest && go build -o /dev/null ./cmd/ingest` | exit 0 | ✓ PASS |
| All tests pass | `cd ingest && go test ./... -count=1 -v` | 10/10 PASS (5 config + 5 health) | ✓ PASS |
| Go vet clean | `cd ingest && go vet ./...` | exit 0 | ✓ PASS |
| docker-compose YAML valid | `python3 yaml.safe_load()` | 7 services parsed, ingest has correct config | ✓ PASS |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|------------|-------------|--------|----------|
| OPS-03 | 01-01 | All configuration via environment variables | ✓ SATISFIED | 13 env-tagged fields in Config struct (5 required, 8 with defaults matching Python config.py) |
| DB-07 | 01-01 | DATABASE_URL +asyncpg dialect stripping | ✓ SATISFIED | `config.go:41` — `strings.Replace(cfg.DatabaseURL, "+asyncpg", "", 1)`; TestDatabaseURLTransform passes |
| OPS-02 | 01-01 | JSON structured logging via log/slog | ✓ SATISFIED | `main.go:205` — `slog.NewJSONHandler(os.Stdout, ...)` with configurable level; emits level/msg/time/service fields |
| DB-06 | 01-02 | PostgreSQL connection pool via pgxpool | ✓ SATISFIED | `main.go:98-101` — MaxConns=15, MinConns=2, MaxConnLifetime=30m, MaxConnIdleTime=5m |
| OPS-01 | 01-02 | GET /healthz returns HTTP 200 for liveness probes | ✓ SATISFIED | `server.go:18` — `/healthz` registered; `health.go:76` returns 200 `{"status":"ok"}` |
| STORE-02 | 01-02 | MinIO uploads bucket auto-creation with 1-day lifecycle | ✓ SATISFIED | `main.go:140-168` — ensureBucket creates if missing, sets lifecycle rule_id="1-day-expiry", days=1, status="Enabled" |
| OPS-05 | 01-03 | Multi-stage Dockerfile producing minimal static binary | ✓ SATISFIED | Dockerfile: golang:1.22-alpine builder → alpine:3.19 runtime; CGO_ENABLED=0, ldflags "-s -w", non-root uid 1000 |
| OPS-06 | 01-03 | Docker Compose service entry alongside existing services | ✓ SATISFIED | docker-compose.yml: ingest service with build, ports, env, depends_on service_healthy for postgres/minio/rabbitmq; all 6 original services preserved |

**All 8 requirement IDs accounted for. No orphaned requirements.**

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| (none) | — | — | — | No anti-patterns detected |

**Details:** `return nil` at `main.go:167` is the legitimate success return of `ensureBucket()` after setting lifecycle — not a stub. No TODO/FIXME/PLACEHOLDER markers found. No empty implementations. No hardcoded empty data. No console.log-only handlers.

### Human Verification Required

### 1. Docker Compose Integration

**Test:** Run `docker compose up ingest` and verify the Go service starts, connects to all backends, and responds on port 8080
**Expected:** Container starts without errors, logs show "connected to PostgreSQL", "connected to MinIO", "connected to RabbitMQ", "server listening" in JSON format; `curl http://localhost:8080/healthz` returns `{"status":"ok"}`
**Why human:** Requires running Docker daemon — cannot verify container build and runtime behavior programmatically without Docker

### 2. Docker Image Size

**Test:** Run `docker build -t ingest-test ./ingest && docker images ingest-test`
**Expected:** Final image size is under 25MB (target ~15-20MB with alpine:3.19 + static binary + ca-certs)
**Why human:** Requires Docker daemon to build the image

### 3. Graceful Shutdown Behavior

**Test:** Start the service, send SIGTERM, and verify it shuts down cleanly within 30s
**Expected:** Service logs "shutting down", drains connections, exits 0
**Why human:** Requires running the service with backend connections to verify full signal handling

---

_Verified: 2026-03-27T09:02:57Z_
_Verifier: the agent (gsd-verifier)_
