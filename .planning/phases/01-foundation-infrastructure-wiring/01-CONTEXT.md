# Phase 1: Foundation & Infrastructure Wiring — Context

## Phase Goal
Go service builds, runs in Docker Compose alongside existing services, connects to all backends (PostgreSQL, MinIO, RabbitMQ), and serves a health check endpoint with structured JSON logging.

## Requirements
OPS-01, OPS-02, OPS-03, OPS-05, OPS-06, DB-06, DB-07, STORE-02

## Decisions

### Project Layout
- **Location:** Top-level `ingest/` directory (mirrors `backend/`, `worker/`, `frontend/` pattern)
- **Internal structure:** Standard Go layout
  - `ingest/cmd/ingest/main.go` — entrypoint
  - `ingest/internal/config/` — configuration parsing
  - `ingest/internal/server/` — HTTP server setup
  - `ingest/internal/health/` — health check handler

### Service Identity
- **Port:** 8080 (Go convention, avoids conflict with Python's 8000)
- **Docker Compose service name:** `ingest`
- **Container image:** `ghcr.io/daluoter/malscan-ingest:latest`

### Configuration
- **Same .env file** as Python backend — single source of truth
- Go strips `+asyncpg` from `DATABASE_URL` at parse time (e.g., `postgresql+asyncpg://` → `postgresql://`)
- All existing env vars reused: `DATABASE_URL`, `MINIO_ENDPOINT`, `MINIO_ACCESS_KEY`, `MINIO_SECRET_KEY`, `MINIO_BUCKET_UPLOADS`, `RABBITMQ_URL`, `RABBITMQ_QUEUE`, `MAX_FILE_SIZE`, `LOG_LEVEL`, `CORS_ORIGINS`
- Use `caarlos0/env` for env parsing (per stack research)

### Startup Behavior
- **Fail-fast:** Service refuses to start if any backend (PostgreSQL, MinIO, RabbitMQ) is unreachable
- No retry/backoff on startup — K8s/Docker restart policy handles recovery
- Connections validated sequentially: PostgreSQL → MinIO → RabbitMQ

### Health Check
- **Single `/health` endpoint** that pings all three backends
- Returns 200 + JSON `{"status": "ok"}` when all healthy
- Returns 503 + JSON `{"status": "unhealthy", "details": {...}}` when any backend fails
- Separate `/ready` endpoint deferred to v2

### Logging
- `log/slog` with JSON handler (zero-dependency, per stack research)
- Structured fields: `service=ingest`, `version`, `request_id` (when applicable)
- Level controlled by `LOG_LEVEL` env var

### Docker
- Multi-stage build: `golang:1.22-alpine` builder → `alpine:3.19` runtime
- Non-root user (matches existing K8s `runAsNonRoot: true, runAsUser: 1000`)
- Expose port 8080

## Constraints Carried Forward
- Exact DB schema compatibility with existing `files` and `jobs` tables
- Same RabbitMQ message format for Python worker consumption
- MinIO bucket structure unchanged

## Out of Scope for This Phase
- File upload handling (Phase 2)
- Database writes (Phase 3)
- RabbitMQ publishing (Phase 3)
- Nginx proxy routing (Phase 5)
- K8s manifests (Phase 5)
- Prometheus metrics, /ready endpoint (v2)

## Key References
- `backend/src/malscan/config.py` — Python config pattern to mirror
- `docker-compose.yml` — existing service definitions
- `k8s/api/deployment.yaml` — K8s patterns to follow
- `.planning/research/STACK.md` — Go package versions
- `.planning/research/PITFALLS.md` — DATABASE_URL transform pitfall
