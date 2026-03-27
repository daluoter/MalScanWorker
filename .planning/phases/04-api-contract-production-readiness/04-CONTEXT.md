# Phase 4: API Contract & Production Readiness - Context

**Gathered:** 2026-03-27
**Status:** Ready for planning

<domain>
## Phase Boundary

API responses are format-compatible with the Python endpoint so the frontend works without changes, CORS allows frontend access, and the service shuts down gracefully without dropping in-flight uploads. This phase covers requirements API-01, API-02, API-03, API-04, and OPS-04.

</domain>

<decisions>
## Implementation Decisions

### Response format compliance
- **D-01:** Define a typed `UploadResponse` struct with JSON tags (`job_id`, `file_id`, `sha256`, `status`, `created_at`) — replace the current `map[string]any` in handler.go:234 for compile-time safety
- **D-02:** Timestamp format: agent's discretion — match Python Pydantic output as closely as reasonable (ISO 8601 with timezone). `time.RFC3339Nano` or a custom format like `"2006-01-02T15:04:05.999999+00:00"` are both acceptable
- **D-03:** Response fields are exactly: `job_id` (string), `file_id` (string), `sha256` (string), `status` (string, always "queued"), `created_at` (string, ISO 8601) — flat JSON, no envelope wrapper
- **D-04:** HTTP 201 status code for successful upload (already implemented)

### CORS middleware setup
- **D-05:** Use `github.com/go-chi/cors` middleware — same ecosystem as the existing chi router
- **D-06:** Mirror Python FastAPI CORS configuration exactly:
  - `allow_origins`: parsed from `CORS_ORIGINS` env var (comma-split, or `["*"]` if `"*"`)
  - `allow_credentials`: false (must be false when origins is `["*"]`)
  - `allow_methods`: `["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"]` (match Python, even though Go service only serves GET and POST)
  - `allow_headers`: `["*"]`
  - `expose_headers`: `["*"]`
  - `max_age`: 600 seconds (10 min preflight cache)
- **D-07:** CORS middleware added to chi router in `server.go`, using `cfg.CORSOrigins` (already parsed in config.go)

### Graceful shutdown behavior
- **D-08:** Shutdown timeout configurable via `SHUTDOWN_TIMEOUT` env var (default 30s) — add to config.go
- **D-09:** Use `http.Server.Shutdown()` to drain in-flight uploads — stops accepting new connections, waits for active requests to complete within timeout. No need for explicit WaitGroup tracking
- **D-10:** Keep defer-based cleanup for backend connections — after `srv.Shutdown()` returns, `run()` exits and defers fire: MQ channel close → MQ connection close → DB pool close. This order is correct since uploads are already drained

### Error response audit
- **D-11:** Audit Python error codes precisely and align Go constants — read `backend/src/malscan/api/routes.py` to find exact error code strings used and match them in `upload/errors.go`
- **D-12:** Catch `http.MaxBytesError` when `MaxBytesReader` (150MB) triggers — detect the specific error type and return clean JSON 400 with `FILE_TOO_LARGE` error code instead of letting a generic error propagate
- **D-13:** All error paths must return the envelope format `{"error": {"code": "ERROR_CODE", "message": "...", "details": {...}}}` — audit every WriteError call and ensure consistency

### Agent's Discretion
- Exact timestamp format choice (RFC3339Nano vs custom format with microseconds)
- Error code string values — agent will audit Python source and align
- CORS middleware placement in router middleware chain (before or after Recoverer)
- Whether to add shutdown logging for each backend close step (nice-to-have)

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### API contract (Python source of truth)
- `backend/src/malscan/schemas/requests.py` — `UploadResponse`, `ApiError`, `ApiErrorResponse` Pydantic schemas defining exact field names, types, and serialization
- `backend/src/malscan/api/routes.py` — Upload endpoint implementation with exact error codes, HTTP status codes, and response construction

### CORS configuration
- `backend/src/malscan/main.py` lines 34-52 — Python CORS middleware setup: origins parsing, allowed methods/headers, credentials, max_age
- `backend/src/malscan/config.py` line 27 — `cors_origins` setting definition

### Existing Go code to modify
- `ingest/internal/upload/handler.go` lines 232-242 — Current success response (replace map[string]any with typed struct)
- `ingest/internal/upload/errors.go` — Error code constants and WriteError helper (audit and align codes)
- `ingest/internal/server/server.go` — Router setup (add CORS middleware)
- `ingest/cmd/ingest/main.go` lines 98-106 — Current shutdown logic (make timeout configurable)
- `ingest/internal/config/config.go` — Config struct (add SHUTDOWN_TIMEOUT field)

### Frontend error handling (verify compatibility)
- `frontend/src/api/client.ts` — Frontend error parsing: checks `errorData?.error?.message` and `errorData?.detail?.error?.message` paths

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `upload/errors.go`: `WriteError()` helper and `ApiErrorResponse` struct — already implements the error envelope format, just needs code constant alignment
- `upload/handler.go`: Success response at lines 232-242 — needs typed struct but logic is correct
- `config/config.go`: `CORSOrigins` field already parsed from env with default `"*"` — CORS middleware just needs to consume it
- `server/server.go`: chi router with `middleware.Recoverer` — add `cors` middleware before routes

### Established Patterns
- Interface-based dependencies (ObjectUploader, FileStore, JobPublisher) — CORS is router-level, no interface needed
- Error response envelope already consistently used across all error paths in handler.go
- Config loaded via `caarlos0/env` with struct tags — add `ShutdownTimeout` field following existing pattern

### Integration Points
- `server.NewRouter()` signature may need `cfg` parameter (or just CORS origins) for CORS setup
- `main.go` shutdown section needs to read `cfg.ShutdownTimeout` instead of hardcoded 30s
- `go-chi/cors` needs to be added to `go.mod` dependencies

</code_context>

<specifics>
## Specific Ideas

No specific requirements — standard approach: match Python behavior exactly for API contract compatibility, use established Go patterns for CORS and shutdown.

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope

</deferred>

---

*Phase: 04-api-contract-production-readiness*
*Context gathered: 2026-03-27*
