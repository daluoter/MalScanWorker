---
phase: 05-integration-deployment
plan: 01
subsystem: infra
tags: [nginx, reverse-proxy, docker-compose, traffic-routing]

# Dependency graph
requires:
  - phase: 04-api-contract-production-readiness
    provides: CORS middleware, graceful shutdown, API contract compliance
provides:
  - Nginx reverse proxy config splitting POST /api/v1/files to Go ingest, all else to FastAPI
  - Docker Compose nginx service taking over port 8000 from api
affects: [05-02-PLAN, production-deployment]

# Tech tracking
tech-stack:
  added: [nginx:1.25-alpine]
  patterns: [method+path proxy routing via limit_except, upstream backends]

key-files:
  created: [nginx/nginx.conf]
  modified: [docker-compose.yml]

key-decisions:
  - "limit_except POST for method-based routing — non-POST on /api/v1/files goes to FastAPI"
  - "150m client_max_body_size matching Go 150MB MaxBytesReader"
  - "proxy_request_buffering off for streaming upload support"
  - "Both api and ingest lose host port mappings — only Nginx exposes 8000"

patterns-established:
  - "Nginx method+path routing: limit_except POST inside location = /api/v1/files"
  - "Docker Compose proxy pattern: nginx depends_on api + ingest, takes over host port"

requirements-completed: [DEPLOY-01]

# Metrics
duration: 2min
completed: 2026-03-28
---

# Phase 5 Plan 01: Nginx Reverse Proxy Summary

**Nginx reverse proxy with method+path routing splitting POST /api/v1/files to Go ingest, all other traffic to FastAPI, integrated into Docker Compose**

## Performance

- **Duration:** 2 min
- **Started:** 2026-03-28T07:24:50Z
- **Completed:** 2026-03-28T07:26:40Z
- **Tasks:** 1
- **Files modified:** 2

## Accomplishments
- Nginx config routes POST /api/v1/files to Go ingest:8080, all other requests to FastAPI api:8000
- Docker Compose updated with nginx service on port 8000, api/ingest ports removed from host
- Streaming upload support via proxy_request_buffering off and 150m body size limit

## Task Commits

Each task was committed atomically:

1. **Task 1: Create Nginx reverse proxy config and Docker Compose nginx service** - `c66526c` (feat)

## Files Created/Modified
- `nginx/nginx.conf` - Reverse proxy config with upstream definitions, method+path routing, streaming support
- `docker-compose.yml` - Added nginx service, removed api/ingest host port mappings

## Decisions Made
- Used `limit_except POST` inside `location = /api/v1/files` for precise method-based routing
- Set `client_max_body_size 150m` to match Go's 150MB MaxBytesReader (two-layer defense)
- Disabled request buffering for streaming uploads with 300s read/send timeouts
- No CORS in Nginx — services handle their own CORS (per D-05)

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered
None

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- Nginx proxy is ready for local development via `docker compose up`
- Frontend can hit localhost:8000 with transparent routing to Go ingest for file uploads

---
*Phase: 05-integration-deployment*
*Completed: 2026-03-28*
