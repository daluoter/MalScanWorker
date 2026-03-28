---
phase: 04-api-contract-production-readiness
verified: 2026-03-28T14:35:00Z
status: passed
score: 7/7 must-haves verified
must_haves:
  truths:
    - "Successful upload returns HTTP 201 with typed UploadResponse JSON matching Python schema exactly"
    - "All error paths return the envelope format {\"error\": {\"code\", \"message\", \"details\"}} with correct HTTP status codes"
    - "MaxBytesReader 150MB limit produces clean JSON error instead of a Go default error page"
    - "Error codes match Python endpoint exactly: FILE_TOO_LARGE, NO_FILE, INVALID_REQUEST, INTERNAL_ERROR, STORAGE_ERROR, QUEUE_UNAVAILABLE, QUEUE_PUBLISH_FAILED"
    - "CORS preflight requests to /api/v1/files return Access-Control-Allow-Origin matching configured origins"
    - "CORS origins are configurable via CORS_ORIGINS env var, defaulting to * (matching Python behavior)"
    - "On SIGTERM, the service stops accepting new connections and waits for in-flight uploads to finish within the configurable timeout"
  artifacts:
    - path: "ingest/internal/upload/handler.go"
      provides: "Typed UploadResponse struct with JSON tags, replaces map[string]any"
    - path: "ingest/internal/upload/errors.go"
      provides: "Aligned error code constants and MaxBytesError detection"
    - path: "ingest/internal/server/server.go"
      provides: "CORS middleware wired into chi router"
    - path: "ingest/internal/config/config.go"
      provides: "ShutdownTimeout field parsed from SHUTDOWN_TIMEOUT env var"
    - path: "ingest/cmd/ingest/main.go"
      provides: "Configurable shutdown timeout replacing hardcoded 30s"
  key_links:
    - from: "ingest/internal/upload/handler.go"
      to: "UploadResponse"
      via: "Typed struct with json tags matching Python schema"
    - from: "ingest/internal/upload/errors.go"
      to: "Python error codes"
      via: "CodeQueuePublishFailed = QUEUE_PUBLISH_FAILED"
    - from: "ingest/internal/server/server.go"
      to: "ingest/internal/config/config.go"
      via: "CORSOrigins param in NewRouter"
    - from: "ingest/cmd/ingest/main.go"
      to: "ingest/internal/config/config.go"
      via: "cfg.ShutdownTimeout in signal handler"
---

# Phase 4: API Contract & Production Readiness Verification Report

**Phase Goal:** API responses are format-compatible with the Python endpoint so the frontend works without changes, CORS allows frontend access, and the service shuts down gracefully without dropping in-flight uploads
**Verified:** 2026-03-28T14:35:00Z
**Status:** passed
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | Successful upload returns HTTP 201 with typed UploadResponse JSON matching Python schema exactly | ✓ VERIFIED | `handler.go:29` defines `type UploadResponse struct` with json tags `job_id`, `file_id`, `sha256`, `status`, `created_at`; line 258 writes `StatusCreated`; line 259-265 uses struct not `map[string]any`; timestamp format `2006-01-02T15:04:05.999999+00:00` matches Pydantic; `TestHandler_ValidUpload` passes with unmarshal into `UploadResponse` |
| 2 | All error paths return the envelope format `{"error": {"code", "message", "details"}}` with correct HTTP status codes | ✓ VERIFIED | `errors.go:32` `WriteError` produces `ApiErrorResponse{Error: ApiError{...}}`; tests verify 400 (FILE_TOO_LARGE, INVALID_REQUEST), 422 (NO_FILE), 500 (STORAGE_ERROR, INTERNAL_ERROR), 503 (QUEUE_PUBLISH_FAILED) |
| 3 | MaxBytesReader 150MB limit produces clean JSON error instead of a Go default error page | ✓ VERIFIED | `handler.go` checks `errors.As(err, &maxBytesErr)` at 3 points (line 81, 102, 172); `server.go:63` wraps body with `http.MaxBytesReader(w, req.Body, 150MB)`; `TestHandler_MaxBytesError` confirms JSON 400 with `FILE_TOO_LARGE` |
| 4 | Error codes match Python endpoint exactly | ✓ VERIFIED | `errors.go` constants: `FILE_TOO_LARGE`, `NO_FILE`, `INVALID_REQUEST`, `INTERNAL_ERROR`, `STORAGE_ERROR`, `QUEUE_UNAVAILABLE`, `QUEUE_PUBLISH_FAILED`; `TestErrorCodeConstants` verifies all 7 codes |
| 5 | CORS preflight requests return Access-Control-Allow-Origin matching configured origins | ✓ VERIFIED | `server.go:40-47` `gocors.Handler` with `AllowedOrigins: origins`; 5 test functions (8 subtests) pass: wildcard, specific origins, methods, actual requests, no-credentials |
| 6 | CORS origins configurable via CORS_ORIGINS env var, defaulting to * | ✓ VERIFIED | `config.go:27` `CORSOrigins string env:"CORS_ORIGINS" envDefault:"*"`; `server.go:28-36` parses `*` vs comma-separated; `main.go:83` passes `cfg.CORSOrigins` to `NewRouter` |
| 7 | On SIGTERM, service stops accepting new connections and waits within configurable timeout | ✓ VERIFIED | `main.go:99` `signal.Notify(quit, SIGINT, SIGTERM)`; line 102-110 uses `cfg.ShutdownTimeout` with `srv.Shutdown()`; `config.go:32` `ShutdownTimeout time.Duration env:"SHUTDOWN_TIMEOUT" envDefault:"30s"`; hardcoded `30*time.Second` eliminated; 3 config tests pass |

**Score:** 7/7 truths verified

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `ingest/internal/upload/handler.go` | Typed UploadResponse struct with JSON tags | ✓ VERIFIED | Contains `type UploadResponse struct` at line 29 with correct json tags; success path at line 259 uses `UploadResponse{}` not `map[string]any`; 269 lines, substantive |
| `ingest/internal/upload/errors.go` | Error code constants including QUEUE_PUBLISH_FAILED | ✓ VERIFIED | Contains all 7 error code constants at lines 9-17; `CodeQueuePublishFailed = "QUEUE_PUBLISH_FAILED"` at line 16; `WriteError` function at line 32 |
| `ingest/internal/upload/handler_test.go` | Tests for UploadResponse, MaxBytesError, error codes | ✓ VERIFIED | 586 lines; `TestHandler_ValidUpload` unmarshals into `UploadResponse` struct; `TestHandler_MaxBytesError` at line 526; `TestHandler_MQPublishFailure` checks `QUEUE_PUBLISH_FAILED` |
| `ingest/internal/upload/errors_test.go` | Tests for error envelope and code constants | ✓ VERIFIED | 129 lines; `TestErrorCodeConstants` at line 108 verifies all 7 codes including `QUEUE_PUBLISH_FAILED` |
| `ingest/internal/server/server.go` | CORS middleware wired into chi router | ✓ VERIFIED | Contains `gocors.Handler(gocors.Options{...})` at line 40; `AllowedOrigins`, `AllowedMethods`, `MaxAge: 600`, `AllowCredentials: false`; `NewRouter` accepts `corsOrigins string` parameter |
| `ingest/internal/server/server_test.go` | CORS preflight and actual request tests | ✓ VERIFIED | 139 lines; 5 test functions with 8 subtests covering preflight wildcard, specific origins, methods, actual requests, no-credentials |
| `ingest/internal/config/config.go` | ShutdownTimeout field | ✓ VERIFIED | Contains `ShutdownTimeout time.Duration` at line 32 with `env:"SHUTDOWN_TIMEOUT" envDefault:"30s"` |
| `ingest/internal/config/config_test.go` | ShutdownTimeout tests | ✓ VERIFIED | 3 tests: `TestShutdownTimeoutDefault` (30s), `TestShutdownTimeoutCustom` (45s), `TestShutdownTimeoutCustomShort` (10s) |
| `ingest/cmd/ingest/main.go` | Configurable shutdown using cfg.ShutdownTimeout | ✓ VERIFIED | Line 102: `cfg.ShutdownTimeout` in log; Line 103: `context.WithTimeout(..., cfg.ShutdownTimeout)`; Line 105: `srv.Shutdown(shutdownCtx)`; Line 109: `"shutdown complete"` log; no `30*time.Second` anywhere |
| `ingest/go.mod` | go-chi/cors dependency | ✓ VERIFIED | Contains `github.com/go-chi/cors v1.2.2` |

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `handler.go` | Python `UploadResponse` | Field names and types must match | ✓ WIRED | JSON tags: `job_id`, `file_id`, `sha256`, `status`, `created_at` — exact match with Python Pydantic schema |
| `errors.go` | Python error codes | Error code strings must match | ✓ WIRED | `QUEUE_PUBLISH_FAILED` at line 16; handler uses it at line 249 for MQ failures |
| `server.go` | `config.go` | CORSOrigins consumed by router | ✓ WIRED | `NewRouter(..., corsOrigins string)` at line 23; `main.go:83` passes `cfg.CORSOrigins` |
| `main.go` | `config.go` | ShutdownTimeout consumed in signal handler | ✓ WIRED | `cfg.ShutdownTimeout` at lines 102, 103 |
| `main.go` | `net/http.Server.Shutdown` | context.WithTimeout using configurable duration | ✓ WIRED | Line 103 creates timeout context, line 105 calls `srv.Shutdown(shutdownCtx)` |

### Data-Flow Trace (Level 4)

Not applicable — this phase modifies response formatting, CORS middleware, and shutdown behavior. No new data sources or rendering components introduced.

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| Upload tests pass (API contract) | `go test ./internal/upload/ -count=1` | PASS (0.010s) | ✓ PASS |
| CORS tests pass | `go test ./internal/server/ -count=1` | PASS (0.004s) | ✓ PASS |
| Config tests pass (ShutdownTimeout) | `go test ./internal/config/ -count=1` | PASS (0.002s) | ✓ PASS |
| Full test suite passes | `go test ./... -count=1` | All 6 packages PASS | ✓ PASS |
| Binary builds | `go build ./cmd/ingest/` | BUILD_OK | ✓ PASS |
| No vet issues | `go vet ./...` | VET_OK | ✓ PASS |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|------------|-------------|--------|----------|
| API-01 | 04-01-PLAN | Success response HTTP 201 with JSON body matching UploadResponse schema | ✓ SATISFIED | `UploadResponse` struct with correct json tags; `StatusCreated`; microsecond timestamp format; `TestHandler_ValidUpload` validates all fields |
| API-02 | 04-01-PLAN | Error responses use envelope `{"error": {"code", "message", "details"}}` | ✓ SATISFIED | `WriteError` produces `ApiErrorResponse` envelope; `TestWriteError` validates structure with 3 test cases |
| API-03 | 04-01-PLAN | HTTP status codes match: 201, 400, 422, 500, 503 | ✓ SATISFIED | Tests verify: 201 (ValidUpload), 400 (FileTooLarge, MaxBytesError, InvalidParent), 422 (NoFileField), 500 (MinIOError, CreateRecordError), 503 (MQPublishFailure) |
| API-04 | 04-02-PLAN | CORS middleware with configurable origins matching FastAPI config | ✓ SATISFIED | `go-chi/cors` with `AllowedOrigins`, `AllowedMethods` (6 methods), `MaxAge: 600`, `AllowCredentials: false`; 5 test functions pass |
| OPS-04 | 04-03-PLAN | Graceful shutdown: drain in-flight uploads, configurable timeout | ✓ SATISFIED | `ShutdownTimeout` config field (30s default); `srv.Shutdown()` with configurable context; structured logging; defer chain closes DB/MQ |

**Orphaned requirements check:** ROADMAP.md lists Phase 4 requirements as `API-01, API-02, API-03, API-04, OPS-04`. Plans claim exactly these 5. No orphaned requirements.

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| (none) | — | — | — | — |

No TODOs, FIXMEs, placeholders, stub implementations, or empty return values found in any modified files. No `map[string]any` in the success response path — only used correctly for error `details` parameter.

### Human Verification Required

### 1. Frontend Error Parsing Compatibility

**Test:** Make a real upload request from the frontend (or curl) to the Go service and verify the frontend's error parsing chain (`errorData?.error?.message`) correctly extracts error messages from the Go error envelope.
**Expected:** Frontend displays the Go service's error message string without fallback to "上傳失敗".
**Why human:** Requires running frontend + Go service together and observing actual UI behavior.

### 2. CORS Multipart Upload from Browser

**Test:** Open the frontend in a browser, attempt a file upload that routes to the Go service, and verify the browser does not block the request due to CORS.
**Expected:** File upload succeeds with no CORS errors in browser console. Preflight OPTIONS request returns proper headers.
**Why human:** Browser CORS enforcement cannot be fully simulated in unit tests (needs actual cross-origin request from browser).

### 3. Graceful Shutdown Under Load

**Test:** Start the Go service, begin a file upload, send SIGTERM during upload, verify upload completes before service exits.
**Expected:** In-flight upload finishes successfully; service logs "shutting down" then "shutdown complete"; no dropped connections.
**Why human:** Requires timing-sensitive manual test with concurrent upload and signal delivery.

### Gaps Summary

No gaps found. All 7 observable truths verified. All 5 requirements (API-01, API-02, API-03, API-04, OPS-04) are satisfied with code evidence and passing tests. All artifacts exist, are substantive (not stubs), and are properly wired. Full test suite (6 packages) passes with zero failures. Binary builds and vets clean.

---

_Verified: 2026-03-28T14:35:00Z_
_Verifier: the agent (gsd-verifier)_
