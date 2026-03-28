---
phase: 04-api-contract-production-readiness
plan: 03
subsystem: infra
tags: [graceful-shutdown, kubernetes, configuration, time-duration]

# Dependency graph
requires:
  - phase: 04-01
    provides: "API contract and response format in main.go"
  - phase: 04-02
    provides: "CORS middleware and router wiring in main.go"
provides:
  - "Configurable SHUTDOWN_TIMEOUT env var with 30s default"
  - "Clean shutdown logging (start with timeout, completion, error)"
  - "srv.Shutdown() draining in-flight uploads before exit"
affects: [05-deployment, kubernetes-manifests]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "time.Duration config field parsed natively by caarlos0/env"
    - "Structured shutdown logging with timeout and completion"

key-files:
  created: []
  modified:
    - "ingest/internal/config/config.go"
    - "ingest/internal/config/config_test.go"
    - "ingest/cmd/ingest/main.go"

key-decisions:
  - "caarlos0/env natively parses time.Duration — no custom parser needed"
  - "Shutdown logs both start (with timeout value) and completion for observability"

patterns-established:
  - "time.Duration env vars: use envDefault with duration string (e.g., '30s')"
  - "Shutdown logging: log intent + timeout, then log completion or error"

requirements-completed: [OPS-04]

# Metrics
duration: 2min
completed: 2026-03-28
---

# Phase 4 Plan 3: Graceful Shutdown Summary

**Configurable SHUTDOWN_TIMEOUT env var (default 30s) replacing hardcoded timeout, with structured shutdown logging for Kubernetes rolling updates**

## Performance

- **Duration:** 2 min
- **Started:** 2026-03-28T06:29:11Z
- **Completed:** 2026-03-28T06:31:01Z
- **Tasks:** 2
- **Files modified:** 3

## Accomplishments
- Added `ShutdownTimeout time.Duration` config field parsed from `SHUTDOWN_TIMEOUT` env var with 30s default
- Replaced hardcoded `30*time.Second` in main.go with configurable `cfg.ShutdownTimeout`
- Added structured shutdown logging: start (with timeout duration), completion, and error cases
- Full TDD cycle for config field with 3 test cases (default, 45s custom, 10s custom)

## Task Commits

Each task was committed atomically:

1. **Task 1: Add ShutdownTimeout config field (RED)** - `7b2df88` (test)
2. **Task 1: Add ShutdownTimeout config field (GREEN)** - `10ea249` (feat)
3. **Task 2: Wire configurable shutdown timeout into main.go** - `3115bb9` (feat)

**Plan metadata:** [pending] (docs: complete plan)

_Note: Task 1 used TDD — RED commit (failing tests) then GREEN commit (implementation)_

## Files Created/Modified
- `ingest/internal/config/config.go` - Added ShutdownTimeout time.Duration field with SHUTDOWN_TIMEOUT env tag and 30s default
- `ingest/internal/config/config_test.go` - Added 3 tests: default (30s), custom (45s), custom short (10s)
- `ingest/cmd/ingest/main.go` - Replaced hardcoded 30s with cfg.ShutdownTimeout, added shutdown start/complete/error logging

## Decisions Made
- caarlos0/env natively parses time.Duration strings ("30s", "1m", "45s") — no custom parsing needed
- Log shutdown timeout value at start for operational visibility during Kubernetes rolling updates
- Log "shutdown complete" for clean drain confirmation in logs

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None

## User Setup Required

None - no external service configuration required. Default behavior (30s timeout) matches existing behavior.

## Known Stubs

None - all functionality is fully wired.

## Next Phase Readiness
- Graceful shutdown is configurable for Kubernetes pod termination grace periods
- Phase 04 complete — all 3 plans (API contract, CORS, graceful shutdown) done
- Ready for Phase 05 deployment (Kubernetes manifests, Nginx routing)

---
*Phase: 04-api-contract-production-readiness*
*Completed: 2026-03-28*
