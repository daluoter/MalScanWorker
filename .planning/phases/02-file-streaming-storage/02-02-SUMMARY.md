---
phase: 02-file-streaming-storage
plan: 02
status: complete
duration: ~6m
tasks_completed: 2
files_created: 2
files_modified: 2
tests_added: 7
---

# Plan 02-02 Summary: Streaming Upload Handler & Router Wiring

## What was built

### Task 1: Streaming Upload Handler (TDD)

**File:** `ingest/internal/upload/handler.go` (151 lines)

- `ObjectUploader` interface — abstracts `minio.Client.PutObject` for testing
- `Handler` struct with `storage`, `bucket`, `maxSize`, `logger` fields
- `NewHandler(storage, bucket, maxSize, logger) *Handler` constructor
- `ServeHTTP(w, r)` — full streaming pipeline:
  1. `r.MultipartReader()` — true streaming, not `ParseMultipartForm`
  2. Iterates parts to find `"file"` field
  3. `SanitizeFilename()` on uploaded filename
  4. Content-Type from part header, defaults to `"application/octet-stream"`
  5. `os.CreateTemp("", "ingest-*")` with `defer os.Remove()` cleanup
  6. `sha256.New()` + `io.TeeReader()` for concurrent hashing
  7. 1MB chunk reads (`make([]byte, 1024*1024)`) with cumulative size check
  8. Mid-stream 400 FILE_TOO_LARGE rejection if size exceeds `maxSize`
  9. `PutObject()` to MinIO with SHA256 hex as object key
  10. JSON success response: `{sha256, size, filename, content_type}`

**Tests:** `ingest/internal/upload/handler_test.go` — 7 test cases with mock `ObjectUploader`:
1. Valid upload — correct SHA256, size, filename, content_type, mock data
2. Custom content-type — `text/plain` propagated to MinIO
3. Default content-type — empty → `application/octet-stream`
4. File too large — 5-byte limit, 10-byte upload → 400 FILE_TOO_LARGE
5. No file field — field name `"other"` → 422 NO_FILE
6. MinIO error — mock returns error → 500 STORAGE_ERROR
7. Filename sanitization — `../../evil.exe` → `evil.exe` in response

### Task 2: Router & main.go Wiring

**File:** `ingest/internal/server/server.go` (33 lines, modified)

- `NewRouter(checker, uploadHandler)` — now accepts `*upload.Handler`
- `POST /api/v1/files` route with `http.MaxBytesReader(w, r.Body, 150MB)` wrapper
- `maxRequestBody` constant = 150 * 1024 * 1024

**File:** `ingest/cmd/ingest/main.go` (210 lines, modified)

- Added `upload` import
- `upload.NewHandler(minioClient, cfg.MinioBucket, cfg.MaxFileSize, slog.Default())`
- `server.NewRouter(checker, uploadHandler)` with both dependencies

## Verification

```
go build ./cmd/ingest                       → binary compiles
go test ./... -count=1 -race                → 22/22 PASS (config:5, health:5, upload:12)
go vet ./...                                → clean
```

## Requirements covered

| REQ-ID | What |
|--------|------|
| UPLOAD-01 | Streaming multipart upload via `r.MultipartReader()` |
| UPLOAD-02 | SHA256 computed incrementally via `io.TeeReader` |
| UPLOAD-03 | Per-file 100MB limit enforced mid-stream (configurable) |
| UPLOAD-04 | 150MB HTTP-level `MaxBytesReader` abort |
| UPLOAD-06 | Temp file cleanup via `defer os.Remove()` on all paths |
| STORE-01 | MinIO `PutObject` with SHA256 hex as object key |

## Deferred to later phases

- HTTP 201 status (Phase 3 — when DB records are added)
- `job_id` in response (Phase 3 — persistence layer)
- Dedup check (Phase 3)
- CORS headers (Phase 4)
- RabbitMQ job publishing (Phase 3)
