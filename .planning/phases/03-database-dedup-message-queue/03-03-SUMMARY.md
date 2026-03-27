---
phase: 03-database-dedup-message-queue
plan: 03
status: complete
duration: ~8m
tasks_completed: 2
files_created: 0
files_modified: 4
tests_added: 6
---

# Plan 03-03 Summary: Store + Publisher Integration

## What was built

### Task 1: Integrate Store and Publisher into upload handler

**File:** `ingest/internal/upload/handler.go` (updated, ~242 lines)

- Added `FileStore` interface (abstracts `store.Store` for testing): `CreateFileAndJob`, `ValidateParentJob`, `MarkJobFailed`
- Added `JobPublisher` interface (abstracts `queue.Publisher` for testing): `Publish`
- Updated `Handler` struct: added `store FileStore` and `publisher JobPublisher` fields
- Updated `NewHandler` signature: now takes 6 params (storage, store, publisher, bucket, maxSize, logger)
- Full pipeline in `ServeHTTP`:
  1. Parse multipart stream (existing)
  2. Capture `parent_job_id` text field + `file` part from multipart loop
  3. Stream to temp file with SHA256 hashing (existing)
  4. Size validation (existing)
  5. Parse and validate `parent_job_id` if present (UUID parse, `ValidateParentJob`, depth check)
  6. `CreateFileAndJob` — atomic DB insert with dedup
  7. Conditional MinIO upload — only if `FileRecord.IsNew` (dedup skip)
  8. `Publish` job message to RabbitMQ
  9. On publish failure: `MarkJobFailed` + HTTP 503
  10. Success: HTTP 201 with `job_id`, `file_id`, `sha256`, `status`, `created_at`

**Tests:** `ingest/internal/upload/handler_test.go` (updated, ~400 lines)

- Added `mockFileStore` and `mockJobPublisher` mock implementations
- Updated all 7 existing tests to use new `NewHandler` signature
- Added 6 new test cases:

| New Test | What it verifies |
|----------|-----------------|
| TestServeHTTP_DedupSkipsMinIO | IsNew=false skips PutObject, still returns 201 |
| TestServeHTTP_PublishFailure | Publisher error → MarkJobFailed called + HTTP 503 |
| TestServeHTTP_InvalidParentJobID | Non-UUID parent_job_id → HTTP 400 INVALID_REQUEST |
| TestServeHTTP_ParentNotFound | ValidateParentJob returns ErrNotFound → HTTP 400 |
| TestServeHTTP_DepthExceeded | ValidateParentJob returns ErrDepthExceeded → HTTP 400 |
| TestServeHTTP_DBCreateError | CreateFileAndJob error → HTTP 500 INTERNAL_ERROR |

### Task 2: Wire Store and Publisher in main.go

**File:** `ingest/cmd/ingest/main.go` (updated)

- Opens long-lived AMQP channel from connection
- Creates `queue.NewPublisher(amqpCh, cfg.RabbitmqQueue, slog.Default())`
- Calls `pub.DeclareQueue(ctx)` at startup (fail-fast)
- Creates `store.NewStore(pool, cfg.StagesTotal, cfg.MaxDepth, slog.Default())`
- Passes store + publisher to `upload.NewHandler`

**File:** `ingest/internal/config/config.go` (updated)

- Added `MaxDepth` config field (`MAX_DEPTH` env var, default 3)

## Post-review fixes

- I-1: Log `json.Encode` error in response instead of silently dropping
- M-1: Log `MarkJobFailed` error instead of discarding with `_`
- M-2: Made `maxDepth` configurable via `MAX_DEPTH` env var (was hardcoded `3` in main.go)

## Known limitations (accepted)

- I-2: `parent_job_id` must be sent BEFORE the `file` part in multipart form data — the loop breaks on finding file
- I-3: No test for valid parent_job_id happy-path (parent validation + depth increment)

## Verification

```
go test ./... -count=1 -race          → all packages PASS
go vet ./...                          → clean
go build ./cmd/ingest                 → success
```

## Requirements covered

| REQ-ID | What |
|--------|------|
| STORE-03 | Dedup check before MinIO — IsNew=false skips upload |
| DB-01 | File record created via store.CreateFileAndJob |
| DB-02 | Job record created in same transaction |
| DB-03 | Atomic transaction — Job failure rolls back File |
| MQ-01 | Job published to RabbitMQ after DB commit |
| MQ-04 | Publish failure marks job failed + returns 503 |

## Decisions made during execution

- Used HTTP 201 (Created) instead of plan's 200 — semantically correct for resource creation, accepted in spec review
- Multipart loop breaks on finding `file` part for efficiency — `parent_job_id` must precede file in form data
- Interfaces (`FileStore`, `JobPublisher`) defined in handler package — keeps dependency direction clean (handler doesn't import store/queue concrete types in tests)
