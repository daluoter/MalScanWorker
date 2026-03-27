---
phase: 02-file-streaming-storage
plan: 01
status: complete
duration: ~4m
tasks_completed: 2
files_created: 4
files_modified: 0
tests_added: 12
---

# Plan 02-01 Summary: Filename Sanitization & Error Helpers

## What was built

### Task 1: Filename Sanitization (TDD)

**File:** `ingest/internal/upload/sanitize.go` (37 lines)

- `SanitizeFilename(filename string) string` — exact port of Python `_sanitize_filename()`
- Uses `path.Base()` (not `filepath.Base`) for OS-independent behavior
- Handles: path traversal, Windows paths, null bytes, 255-char truncation, empty/whitespace fallback
- Edge case fix: `path.Base("")` returns `"."` and `path.Base("/")` returns `"/"` — both mapped to `"unnamed"`

**Tests:** `ingest/internal/upload/sanitize_test.go` — 9 table-driven test cases

### Task 2: Structured Error Response Helpers (TDD)

**File:** `ingest/internal/upload/errors.go` (42 lines)

- `WriteError(w, status, code, message, details)` — writes JSON matching Python `ApiErrorResponse` envelope
- `ApiError` struct with `json:"details,omitempty"` — details key absent when nil
- `ApiErrorResponse` struct wrapping `ApiError` in `"error"` envelope
- Constants: `CodeFileTooLarge`, `CodeNoFile`, `CodeInvalidRequest`, `CodeInternalError`, `CodeStorageError`, `CodeQueueUnavailable`

**Tests:** `ingest/internal/upload/errors_test.go` — 3 test cases (with details, without details, 500 status)

## Verification

```
go test ./internal/upload/... -count=1 -v -race  → 12/12 PASS
go vet ./internal/upload/...                      → clean
go build ./...                                    → success
```

## Requirements covered

| REQ-ID | What |
|--------|------|
| UPLOAD-05 | SanitizeFilename strips traversal, null bytes, truncates |
| UPLOAD-03 | FILE_TOO_LARGE error code + 400 status defined |
| UPLOAD-04 | Error response helpers ready for size enforcement |

## Decisions made during execution

- Used `path.Base()` instead of `filepath.Base()` to avoid OS-specific separator behavior
- Added `"."` and `"/"` guard after `path.Base()` — Python's `os.path.basename` returns `""` for these but Go's `path.Base` doesn't
- Added `CodeQueueUnavailable` constant beyond plan spec (anticipated by CONTEXT.md error codes list)
