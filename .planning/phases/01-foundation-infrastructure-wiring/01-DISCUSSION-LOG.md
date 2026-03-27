# Phase 1: Discussion Log

## Session: Foundation & Infrastructure Wiring

### Gray Areas Identified
1. Project layout — directory and internal Go structure
2. Service identity — port, docker-compose name, image path
3. Startup behavior — fail-fast vs retry vs degraded
4. Health check design — single vs split endpoints
5. DATABASE_URL handling — shared env vs separate

### Decisions Made

**Project Layout**
- Q: Where should the Go service live?
- A: `ingest/` — mirrors existing `backend/`, `worker/`, `frontend/` top-level pattern
- Q: Internal structure?
- A: Standard Go layout: `cmd/ingest/main.go` + `internal/{config,server,health}`

**Service Identity**
- Q: Port number?
- A: 8080 — Go convention, no conflict with Python's 8000
- Q: Docker Compose service name?
- A: `ingest` — matches directory
- Q: Container image path?
- A: `ghcr.io/daluoter/malscan-ingest:latest` — matches existing `malscan-api` pattern

**Startup Behavior**
- Q: What happens when a backend is unreachable?
- A: Fail-fast — refuse to start. K8s restart policy handles recovery.

**Health Check**
- Q: Single or split health endpoints?
- A: Single `/health` that checks all backends. Separate `/ready` deferred to v2.

**Configuration**
- Q: How to handle DATABASE_URL format mismatch?
- A: Same .env file, Go strips `+asyncpg` at parse time. Single source of truth.

### Deferred Ideas
- Separate `/ready` endpoint (v2)
- Prometheus metrics endpoint (v2)
- Graceful connection retry with backoff (v2)
