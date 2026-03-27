# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-03-27)

**Core value:** Fast, reliable file ingestion that never drops uploads under concurrent load — the gateway through which every malware sample enters the analysis pipeline.
**Current focus:** Phase 1 — Foundation & Infrastructure Wiring

## Current Position

Phase: 1 of 5 (Foundation & Infrastructure Wiring)
Plan: 0 of TBD in current phase
Status: Context complete — ready to plan
Last activity: 2026-03-27 — Phase 1 context discussed and committed

Progress: [░░░░░░░░░░] 0%

## Performance Metrics

**Velocity:**
- Total plans completed: 0
- Average duration: —
- Total execution time: 0 hours

**By Phase:**

| Phase | Plans | Total | Avg/Plan |
|-------|-------|-------|----------|
| - | - | - | - |

**Recent Trend:**
- Last 5 plans: —
- Trend: —

*Updated after each plan completion*

## Accumulated Context

### Decisions

Decisions are logged in PROJECT.md Key Decisions table.
Recent decisions affecting current work:

- [Phase 1 Context]: Go code in `ingest/` with `cmd/internal` layout, port 8080, fail-fast startup, single `/health` endpoint
- [Phase 1 Context]: Shared `.env` — Go strips `+asyncpg` from DATABASE_URL at parse time
- [Phase 1 Context]: Docker Compose service name `ingest`, image `ghcr.io/daluoter/malscan-ingest:latest`
- [Roadmap]: 5-phase structure following data flow — foundation → streaming → persistence → contract → deployment
- [Roadmap]: Split research's monolithic Phase 2 into Phases 2+3 (streaming vs persistence) for better verifiability
- [Research]: DATABASE_URL `+asyncpg` prefix must be stripped at config load (pitfall #1)
- [Research]: Use `r.MultipartReader()` not `ParseMultipartForm()` to avoid 32MB/upload memory buffering

### Pending Todos

None yet.

### Blockers/Concerns

- PostgreSQL connection budget: Python backend (30) + worker (15) + Go (15) = 60 total — verify `max_connections` during Phase 1
- Structured log key: Python structlog uses `event`, Go slog uses `msg` — decide in Phase 1

## Session Continuity

Last session: 2026-03-27
Stopped at: Phase 1 context complete, ready for planning
Resume file: .planning/phases/01-foundation-infrastructure-wiring/01-CONTEXT.md
