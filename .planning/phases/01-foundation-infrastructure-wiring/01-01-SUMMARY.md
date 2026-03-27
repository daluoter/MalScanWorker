---
phase: 01-foundation-infrastructure-wiring
plan: 01
subsystem: ingest-config
tags: [go, config, slog, chi, tdd]
dependency_graph:
  requires: []
  provides: [go-module, config-package, main-entrypoint, json-logging]
  affects: [01-02, 01-03]
tech_stack:
  added: [go-1.25, chi-v5.2.5, pgx-v5.9.1, minio-go-v7.0.99, amqp091-go-v1.10.0, caarlos0-env-v11.4.0]
  patterns: [env-struct-tags, slog-json-handler, chi-router, graceful-shutdown]
key_files:
  created:
    - ingest/go.mod
    - ingest/go.sum
    - ingest/internal/config/config.go
    - ingest/internal/config/config_test.go
    - ingest/cmd/ingest/main.go
    - ingest/.gitignore
  modified: []
decisions:
  - go-mod-version-1.25: "pgx/v5@v5.9.1 requires go >= 1.25.0; auto-upgraded from planned go 1.22 via Go toolchain download"
metrics:
  duration: 5m27s
  completed: "2026-03-27T08:47:51Z"
  tasks: 2
  files: 6
---

# Phase 1 Plan 1: Go Module Init, Config & Main Skeleton Summary

Config package parses 13 env vars with caarlos0/env struct tags, strips +asyncpg from DATABASE_URL for pgx compatibility, and main.go provides chi router with JSON slog logging and SIGINT/SIGTERM graceful shutdown.

## What Was Built

### Config Package (`ingest/internal/config/`)
- `Config` struct with 5 required fields (`DATABASE_URL`, `MINIO_ENDPOINT`, `MINIO_ACCESS_KEY`, `MINIO_SECRET_KEY`, `RABBITMQ_URL`) and 8 optional fields with defaults matching `backend/src/malscan/config.py`
- `Load()` function that parses env vars via `caarlos0/env/v11` and transforms `postgresql+asyncpg://` → `postgresql://` (DB-07 requirement)
- 5 unit tests covering defaults, DATABASE_URL transform, no-transform passthrough, required-missing error, and custom value override

### Main Entrypoint (`ingest/cmd/ingest/main.go`)
- `main()` → `run()` pattern with slog.Error + os.Exit(1) on failure
- `setupLogger()` configures slog with JSONHandler at configured level (DEBUG/INFO/WARN/WARNING/ERROR)
- Chi router with Recoverer middleware
- HTTP server with `ReadHeaderTimeout: 10s` (slowloris protection)
- Graceful shutdown on SIGINT/SIGTERM with 30s drain timeout

### Project Structure
- Go module `github.com/daluoter/malscan-ingest` at `ingest/`
- All Phase 1 dependencies installed: chi, pgx, minio-go, amqp091-go, env
- Directory scaffolding: `cmd/ingest/`, `internal/config/`, `internal/server/`, `internal/health/`

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] go.mod version upgraded from 1.22 to 1.25.0**
- **Found during:** Task 1 (dependency installation)
- **Issue:** `pgx/v5@v5.9.1` requires `go >= 1.25.0`. Go's toolchain download feature auto-upgraded the go directive.
- **Fix:** Accepted the upgrade. Go 1.22.2 (locally installed) transparently downloads Go 1.25.0 toolchain as needed. All builds and tests pass.
- **Files modified:** `ingest/go.mod`
- **Commit:** b66530a

**2. [Rule 1 - Bug] Fixed .gitignore binary pattern matching directory**
- **Found during:** Task 2 (git commit)
- **Issue:** `.gitignore` pattern `ingest` matched the `cmd/ingest/` directory, preventing `cmd/ingest/main.go` from being committed.
- **Fix:** Changed pattern to `/ingest` (root-anchored) to only match the compiled binary, not directories.
- **Files modified:** `ingest/.gitignore`
- **Commit:** 5ac6ed3

**3. [Rule 1 - Bug] Fixed TestConfigRequiredMissing using empty string instead of unset**
- **Found during:** Task 1 TDD GREEN phase
- **Issue:** `t.Setenv("DATABASE_URL", "")` sets the var to empty string, but `caarlos0/env` considers empty strings as "set" for `required` fields. Test was always failing in GREEN phase.
- **Fix:** Changed test to use `t.Setenv()` for cleanup registration followed by `os.Unsetenv()` to actually remove the variables.
- **Files modified:** `ingest/internal/config/config_test.go`
- **Commit:** b66530a

## Decisions Made

1. **go.mod version 1.25.0** — Accepted auto-upgrade from planned 1.22 because pgx/v5@v5.9.1 requires it. Go toolchain download handles build transparency.

## Verification Results

| Check | Result |
|-------|--------|
| `go build ./...` | ✅ PASS |
| `go test ./... -count=1` | ✅ PASS (5/5 tests) |
| `go vet ./...` | ✅ PASS |
| Config struct has 13 env vars | ✅ Verified |
| DATABASE_URL transform works | ✅ TestDatabaseURLTransform PASS |
| Defaults match Python config.py | ✅ TestConfigDefaults PASS |

## Task Commits

| Task | Type | Commit | Description |
|------|------|--------|-------------|
| 1 (RED) | test | 2485d07 | Add failing tests for config package |
| 1 (GREEN) | feat | b66530a | Implement config package with env parsing and DATABASE_URL transform |
| 2 | feat | 5ac6ed3 | Create main.go with JSON logger, chi router, and graceful shutdown |

## Known Stubs

None — all code is fully functional. No placeholder data, TODO markers, or unconnected components. The router has no routes (by design — routes are added in Plan 02).
