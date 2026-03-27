---
phase: 03-database-dedup-message-queue
plan: 01
status: complete
duration: ~5m
tasks_completed: 1
files_created: 2
files_modified: 0
tests_added: 8
---

# Plan 03-01 Summary: Database Store Package

## What was built

### Task 1: Database store with File/Job CRUD, dedup, and parent validation (TDD)

**File:** `ingest/internal/store/store.go` (172 lines)

- `DB` interface — minimal `Begin`, `QueryRow`, `Exec` abstraction over `*pgxpool.Pool` for testability
- `Store` struct with `db`, `stagesTotal`, `maxDepth`, `logger` fields
- `NewStore(db, stagesTotal, maxDepth, logger)` constructor
- `CreateFileAndJob(ctx, sha256, size, filename, contentType, parentJobID, depth)` — atomic transaction:
  - `INSERT INTO files ... ON CONFLICT (sha256) DO NOTHING RETURNING id, created_at`
  - On dedup hit (no rows returned): `SELECT id, created_at FROM files WHERE sha256 = $1`
  - `INSERT INTO jobs ... RETURNING id, created_at` with all columns matching Python schema
  - Returns `FileRecord` (with `IsNew` flag) and `JobRecord`
- `ValidateParentJob(ctx, parentJobID)` — `SELECT depth FROM jobs WHERE id = $1`, returns `ErrNotFound` or `ErrDepthExceeded` sentinel errors
- `MarkJobFailed(ctx, jobID, errMsg)` — `UPDATE jobs SET status = 'failed'`, warns on zero `RowsAffected()`
- Sentinel errors: `ErrNotFound`, `ErrDepthExceeded` — used by handler for HTTP status code decisions

**Tests:** `ingest/internal/store/store_test.go` — 8 tests with mock DB/Tx/Row

| Test | What it verifies |
|------|-----------------|
| TestCreateFileAndJob_NewFile | New SHA256 creates file + job, IsNew=true |
| TestCreateFileAndJob_DuplicateFile | Existing SHA256 reuses file, IsNew=false |
| TestCreateFileAndJob_RollbackOnJobFailure | Job INSERT error rolls back file INSERT |
| TestCreateFileAndJob_ConcurrentDedup | Two goroutines same SHA256, both succeed |
| TestValidateParentJob_Valid | Existing job with depth < max returns depth |
| TestValidateParentJob_NotFound | Non-existent UUID returns ErrNotFound |
| TestValidateParentJob_DepthExceeded | Parent at max depth returns ErrDepthExceeded |
| TestMarkJobFailed | Updates status and error_message |

## Post-review fixes

- Added sentinel errors `ErrNotFound` and `ErrDepthExceeded` (code quality review)
- Added `RowsAffected()` check in `MarkJobFailed` with warning log (code quality review)

## Verification

```
go test ./internal/store/... -count=1 -v -race  → 8/8 PASS
go vet ./...                                     → clean
go build ./...                                   → success
```

## Requirements covered

| REQ-ID | What |
|--------|------|
| DB-01 | File record creation matching Python files table schema |
| DB-02 | Job record creation matching Python jobs table schema |
| DB-03 | Atomic File+Job creation in single transaction with rollback |
| DB-04 | SHA256 dedup via INSERT ON CONFLICT DO NOTHING + SELECT fallback |
| DB-05 | Parent job validation with depth checking |
| STORE-03 | IsNew flag enables dedup skip at MinIO layer |

## Decisions made during execution

- Used `INSERT ON CONFLICT (sha256) DO NOTHING` + fallback `SELECT` for concurrent-safe dedup (instead of Python's SELECT-then-INSERT pattern)
- File/Job UUIDs generated in Go (`uuid.New()`) matching Python's `uuid.uuid4()` default
- `maxDepth` as constructor param (default 3) matching Python's `getattr(settings, "max_job_depth", 3)`
- Mock-based testing via `DB`, `pgx.Tx`, `pgx.Row` interfaces — no real database needed
