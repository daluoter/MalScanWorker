---
phase: quick
plan: 260328-tcw
subsystem: docs
tags: [readme, i18n, go, ingest, architecture]

# Dependency graph
requires:
  - phase: 05-integration-deployment
    provides: "Go ingest service, Nginx proxy, k8s manifests — the architecture this README documents"
provides:
  - "Optimized Chinese README with Go ingest layer in architecture"
  - "Complete English README translation (README.en.md)"
  - "Language-switch links between both READMEs"
affects: []

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Bilingual README pattern: README.md (Chinese) + README.en.md (English) with cross-links"

key-files:
  created:
    - README.en.md
  modified:
    - README.md

key-decisions:
  - "Architecture diagram uses box-drawing characters for clearer routing visualization (Nginx → Ingest / Backend split)"
  - "Added Ingest .env example with Go-native postgres DSN (sslmode=disable) vs Python asyncpg DSN"
  - "API endpoints table now includes 'Service' column to clarify Go vs Python ownership"

patterns-established:
  - "Bilingual docs: language switch at top line, identical heading hierarchy"

requirements-completed: [README-OPT, README-EN]

# Metrics
duration: 3min
completed: 2026-03-28
---

# Quick Task 260328-tcw: README Optimization + English Translation Summary

**Updated architecture diagram and docs to reflect Go ingest layer, added English README with cross-language navigation**

## Performance

- **Duration:** 3 min
- **Started:** 2026-03-28T13:11:10Z
- **Completed:** 2026-03-28T13:14:05Z
- **Tasks:** 2/2
- **Files modified:** 2

## Accomplishments
- README.md updated with accurate architecture showing Go Ingest Service, Nginx reverse proxy, and service routing
- Tech stack section now includes Ingest (Go 1.25 + chi + pgx + minio-go + amqp091-go)
- API endpoints table clarifies which service handles each route
- Local development section includes Ingest service startup and .env configuration
- README.en.md created as complete, idiomatic English translation with identical structure
- Both READMEs cross-link at the top for language switching

## Task Commits

Each task was committed atomically:

1. **Task 1: Optimize README.md (Chinese) with updated architecture** - `1fa5acb` (docs)
2. **Task 2: Create README.en.md (English version)** - `ce91d30` (docs)

## Files Created/Modified
- `README.md` - Optimized Chinese README with Go ingest architecture, updated tech stack, local dev instructions, and API service ownership
- `README.en.md` - Complete English translation with language switch link back to README.md

## Decisions Made
- Architecture diagram redesigned to clearly show Nginx routing split (POST files → Ingest, GET queries → FastAPI) rather than a simple linear flow
- Added Ingest-specific `.env` example in local dev section using Go-native PostgreSQL DSN format
- Docker build and k8s manifest sections updated to include ingest service alongside api and worker

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered
None

## Known Stubs
None - both READMEs are complete with all sections fully written.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- Both READMEs accurately document the current v1.0 architecture
- Ready for any future architecture changes to be reflected in both language versions

## Self-Check: PASSED

All files exist, all commits verified, cross-links working, content checks passed.

---
*Quick Task: 260328-tcw-readme-md*
*Completed: 2026-03-28*
