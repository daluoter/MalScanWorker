---
phase: 04-api-contract-production-readiness
plan: 01
subsystem: api
tags: [go, api-contract, json, error-handling, http, pydantic-compat]

# Dependency graph
requires:
  - phase: 03-persistence-pipeline
    provides: "Handler with map[string]any response, error codes, store/queue integration"
provides:
  - "Typed UploadResponse struct matching Python UploadResponse exactly"
  - "CodeQueuePublishFailed error code matching Python QUEUE_PUBLISH_FAILED"
  - "MaxBytesError detection returning JSON error instead of Go default page"
  - "ISO 8601 microsecond-precision timestamps matching Pydantic datetime serialization"
affects: [04-api-contract-production-readiness, deployment]

# Tech tracking
tech-stack:
  added: []
  patterns: ["Typed response structs over map[string]any", "http.MaxBytesError detection with errors.As"]

key-files:
  created: []
  modified:
    - ingest/internal/upload/handler.go
    - ingest/internal/upload/errors.go
    - ingest/internal/upload/handler_test.go
    - ingest/internal/upload/errors_test.go

key-decisions:
  - "Keep both CodeQueueUnavailable and CodeQueuePublishFailed — former for generic MQ connectivity, latter matches Python exactly for publish failures"
  - "Timestamp format 2006-01-02T15:04:05.999999+00:00 matches Python Pydantic datetime serialization with microsecond precision"
  - "MaxBytesError checked in three paths: MultipartReader(), NextPart(), and streaming Read() for complete coverage"

patterns-established:
  - "Typed response structs with json tags matching Python Pydantic schemas exactly"
  - "errors.As pattern for http.MaxBytesError detection at all read boundaries"

requirements-completed: [API-01, API-02, API-03]

# Metrics
duration: 4min
completed: 2026-03-28
---

# Phase 04 Plan 01: API Contract Response & Error Code Alignment Summary

**Typed UploadResponse struct replacing map[string]any, QUEUE_PUBLISH_FAILED error code, and MaxBytesError JSON handling for exact Python API parity**

## Performance

- **Duration:** 3m42s
- **Started:** 2026-03-28T06:22:00Z
- **Completed:** 2026-03-28T06:25:42Z
- **Tasks:** 1 (TDD: RED + GREEN)
- **Files modified:** 4

## Accomplishments
- Replaced `map[string]any` success response with typed `UploadResponse` struct matching Python's Pydantic `UploadResponse` exactly (field names: `job_id`, `file_id`, `sha256`, `status`, `created_at`)
- Added `CodeQueuePublishFailed = "QUEUE_PUBLISH_FAILED"` constant matching Python routes.py exactly; MQ publish failure now uses this code with a user-friendly message
- `created_at` timestamp now uses `2006-01-02T15:04:05.999999+00:00` format matching Python Pydantic's datetime serialization (microsecond precision, UTC offset)
- `http.MaxBytesError` detected at three read boundaries (MultipartReader, NextPart, stream Read) — returns JSON `{"error":{"code":"FILE_TOO_LARGE",...}}` instead of Go's default HTML error page

## Task Commits

Each task was committed atomically:

1. **Task 1 (RED): Failing tests for UploadResponse, CodeQueuePublishFailed, MaxBytesError** - `e41df44` (test)
2. **Task 1 (GREEN): Implementation of typed response, error codes, MaxBytesError handling** - `c797c33` (feat)

## Files Created/Modified
- `ingest/internal/upload/handler.go` - Added UploadResponse struct, replaced map[string]any with typed response, added MaxBytesError detection in three read paths, updated MQ error to CodeQueuePublishFailed
- `ingest/internal/upload/errors.go` - Added CodeQueuePublishFailed constant
- `ingest/internal/upload/handler_test.go` - Updated ValidUpload to unmarshal into UploadResponse, updated MQ test to expect QUEUE_PUBLISH_FAILED, added TestMaxBytesError
- `ingest/internal/upload/errors_test.go` - Added TestErrorCodeConstants verifying all error code constants

## Decisions Made
- **Keep both QUEUE_UNAVAILABLE and QUEUE_PUBLISH_FAILED**: `QUEUE_UNAVAILABLE` for generic MQ connectivity issues, `QUEUE_PUBLISH_FAILED` for when publish fails after retries (matches Python exactly)
- **Timestamp microsecond format**: `2006-01-02T15:04:05.999999+00:00` — Go's `999999` trims trailing zeros up to microsecond precision, matching Python Pydantic's default datetime serialization
- **Three-point MaxBytesError detection**: Checked in `MultipartReader()`, `NextPart()`, and streaming `Read()` error paths for complete coverage

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered
None

## User Setup Required
None - no external service configuration required.

## Known Stubs
None - all data paths are fully wired.

## Next Phase Readiness
- API contract for success responses and error codes now matches Python exactly
- Frontend error parsing (`errorData?.error?.message`) will work with Go error envelope
- Ready for remaining Phase 04 plans (graceful shutdown, content-type negotiation, etc.)

---
*Phase: 04-api-contract-production-readiness*
*Completed: 2026-03-28*
