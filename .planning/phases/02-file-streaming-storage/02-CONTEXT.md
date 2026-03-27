# Phase 2: File Streaming & Storage — Context

## Phase Goal
Files can be streamed into the service, incrementally hashed, validated for size and filename, and stored in MinIO — all without buffering entire files in memory.

## Requirements
UPLOAD-01, UPLOAD-02, UPLOAD-03, UPLOAD-04, UPLOAD-05, UPLOAD-06, STORE-01

## Decisions

### Package Layout
- **Upload handler:** `ingest/internal/upload/` — dedicated package, separate from health/ and server/
- Files: `handler.go` (HTTP handler), `sanitize.go` (filename sanitization), `errors.go` (error types/responses)
- Router wiring in `server/server.go` — adds `POST /api/v1/files` route

### Streaming Architecture
- **`r.MultipartReader()`** — NOT `ParseMultipartForm()` (avoids 32MB RAM buffering per upload)
- Read file part in 1MB chunks (matching Python's `CHUNK_SIZE = 1024 * 1024`)
- Compute SHA256 incrementally via `io.TeeReader` during chunk reads
- Write chunks to temp file simultaneously
- After streaming completes: SHA256 is known, temp file is the source

### Temp File Strategy
- **`os.CreateTemp("", "ingest-*")`** — system `/tmp` directory
- Matches Python's `tempfile.mkstemp()` behavior
- **`defer os.Remove(tempPath)`** on all code paths (success, error, panic)
- Temp file opened once, used for both writing (during stream) and reading (for MinIO upload)

### Size Validation
- **HTTP-level limit:** `http.MaxBytesReader` at 150MB — aborts oversized requests before multipart parsing (UPLOAD-04)
- **Per-chunk limit:** Track cumulative size during streaming, reject with HTTP 400 + `FILE_TOO_LARGE` when configurable max (default 100MB) exceeded mid-stream (UPLOAD-03)
- Temp file cleaned up even on size rejection

### Filename Sanitization
- Match Python's `_sanitize_filename()` behavior exactly:
  - Strip path separators (`/`, `\`)
  - Remove null bytes
  - Truncate to 255 characters
  - Fall back to `"unnamed"` for empty filenames
- Reference: `backend/src/malscan/api/routes.py` lines 52-83

### Error Response Format
- **Match Python exactly:** `{"error": {"code": "...", "message": "...", "details": {...}}}`
- Error codes: `FILE_TOO_LARGE`, `INVALID_REQUEST`, `NO_FILE`, `INTERNAL_ERROR`
- HTTP status codes: 400 (validation), 422 (missing file field), 500 (internal), 503 (backend unavailable)
- Shared error helper in `upload/errors.go`

### MinIO Upload
- **PutObject from temp file** after hashing — SHA256 known before upload starts
- Object key: SHA256 hex string (matches Python: `storage_key = sha256_hash`)
- Bucket: `uploads` (already auto-created by Phase 1)
- **Content-Type:** Use multipart header value as-is (matches Python behavior)
- Set `content-type` metadata on MinIO object

### Content-Type Handling
- Use Content-Type from multipart form header directly
- Default to `"application/octet-stream"` if missing
- No server-side detection/sniffing

## Constraints Carried Forward
- All Phase 1 decisions apply (project layout, config, logging, port 8080)
- MinIO client and config already wired in `main.go` from Phase 1
- This phase does NOT write to PostgreSQL or publish to RabbitMQ (Phase 3)
- This phase does NOT handle dedup checking (Phase 3)

## Out of Scope for This Phase
- Database writes (Phase 3)
- RabbitMQ publishing (Phase 3)
- Dedup detection via SHA256 lookup (Phase 3)
- API response body for successful upload (Phase 3 — needs job_id from DB)
- Parent job handling (Phase 3)
- CORS headers (Phase 4)
- Nginx proxy routing (Phase 5)

## Key References
- `backend/src/malscan/api/routes.py` lines 52-83 — `_sanitize_filename()` to port
- `backend/src/malscan/api/routes.py` lines 86-180 — streaming upload flow to mirror
- `backend/src/malscan/schemas/requests.py` — `ApiErrorResponse`, `ApiError` schemas
- `ingest/cmd/ingest/main.go` — existing main.go to extend with upload handler wiring
- `ingest/internal/server/server.go` — router to add POST route
- `.planning/research/PITFALLS.md` — multipart buffering trap (Pitfall #4)
- `.planning/research/ARCHITECTURE.md` — streaming data flow pattern
