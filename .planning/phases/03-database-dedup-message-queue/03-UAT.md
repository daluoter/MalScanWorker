# Phase 03 — Database, Dedup & Message Queue: UAT

**Phase:** 03-database-dedup-message-queue
**Date:** 2026-03-27
**Status:** COMPLETE — ALL PASSED

---

## UAT-01: Cold-start smoke test
**Category:** Build & Test
**Description:** The ingest service compiles and all tests pass with race detection.
**Steps:**
1. Run `go build ./cmd/ingest` from the `ingest/` directory
2. Run `go test ./... -count=1 -race` from the `ingest/` directory
**Expected:** Build succeeds with no errors. All tests pass (0 failures), including store (8), queue (7), and updated handler tests.
**Result:** :white_check_mark: PASS
**Notes:**

---

## UAT-02: File dedup — duplicate SHA256 reuses existing file record
**Category:** Database Store
**Description:** When a file with the same SHA256 is uploaded twice, the store reuses the existing file record instead of creating a new one (INSERT ON CONFLICT DO NOTHING + SELECT fallback).
**Steps:**
1. Run `go test ./internal/store/... -run TestCreateFileAndJob_DuplicateFile -v -race`
**Expected:** Test passes. The file record returned has `IsNew=false`, the same file ID is reused, and a new job record is still created.
**Result:** :white_check_mark: PASS
**Notes:**

---

## UAT-03: Atomic transaction — job failure rolls back file
**Category:** Database Store
**Description:** If the job INSERT fails after the file INSERT succeeds, the transaction is rolled back atomically.
**Steps:**
1. Run `go test ./internal/store/... -run TestCreateFileAndJob_RollbackOnJobFailure -v -race`
**Expected:** Test passes. When job creation fails, the transaction's Rollback is called, and the error propagates.
**Result:** :white_check_mark: PASS
**Notes:**

---

## UAT-04: Parent job validation — not found
**Category:** Database Store
**Description:** When a non-existent parent_job_id is provided, `ValidateParentJob` returns `ErrNotFound`.
**Steps:**
1. Run `go test ./internal/store/... -run TestValidateParentJob_NotFound -v -race`
**Expected:** Test passes. The sentinel error `ErrNotFound` is returned for a non-existent parent job UUID.
**Result:** :white_check_mark: PASS
**Notes:**

---

## UAT-05: Parent job validation — depth exceeded
**Category:** Database Store
**Description:** When a parent job is already at the maximum depth, `ValidateParentJob` returns `ErrDepthExceeded`.
**Steps:**
1. Run `go test ./internal/store/... -run TestValidateParentJob_DepthExceeded -v -race`
**Expected:** Test passes. The sentinel error `ErrDepthExceeded` is returned when parent's depth >= maxDepth.
**Result:** :white_check_mark: PASS
**Notes:**

---

## UAT-06: MQ queue declared with DLQ arguments
**Category:** Message Queue
**Description:** `DeclareQueue` creates a durable queue with dead-letter exchange and routing key arguments matching the Python backend.
**Steps:**
1. Run `go test ./internal/queue/... -run TestDeclareQueue_Success -v -race`
**Expected:** Test passes. Queue is declared with `durable=true`, `x-dead-letter-exchange=""`, `x-dead-letter-routing-key="malscan-dlq"`.
**Result:** :white_check_mark: PASS
**Notes:**

---

## UAT-07: MQ publish retry with exponential backoff
**Category:** Message Queue
**Description:** When publishing fails, the publisher retries up to 5 times with exponential backoff (1s→2s→4s→8s→16s).
**Steps:**
1. Run `go test ./internal/queue/... -run TestPublish_RetryOnFailure -v -race`
2. Run `go test ./internal/queue/... -run TestPublish_AllRetriesExhausted -v -race`
**Expected:** Both tests pass. First test: fails 3 times then succeeds on 4th. Second test: fails all 5 attempts and returns final error.
**Result:** :white_check_mark: PASS
**Notes:**

---

## UAT-08: Full pipeline — dedup skips MinIO upload
**Category:** Integration (Handler)
**Description:** When a duplicate file is uploaded (IsNew=false from store), the handler skips the MinIO PutObject call but still returns HTTP 201 with the job details.
**Steps:**
1. Run `go test ./internal/upload/... -run TestServeHTTP_DedupSkipsMinIO -v -race`
**Expected:** Test passes. PutObject is NOT called (mock counter = 0), response is HTTP 201 with valid JSON body.
**Result:** :white_check_mark: PASS
**Notes:**

---

## UAT-09: Full pipeline — publish failure marks job failed
**Category:** Integration (Handler)
**Description:** When MQ publish fails, the handler calls `MarkJobFailed` on the store and returns HTTP 503 with an appropriate error.
**Steps:**
1. Run `go test ./internal/upload/... -run TestServeHTTP_PublishFailure -v -race`
**Expected:** Test passes. `MarkJobFailed` is called with the job ID and error message. Response is HTTP 503.
**Result:** :white_check_mark: PASS
**Notes:**

---

## UAT-10: Full pipeline — success response format
**Category:** Integration (Handler)
**Description:** A successful upload through the full pipeline returns HTTP 201 with the correct JSON response body containing job_id, file_id, sha256, status, and created_at.
**Steps:**
1. Run `go test ./internal/upload/... -run TestServeHTTP_Success -v -race`
**Expected:** Test passes. Response is HTTP 201 with JSON body: `{"job_id": "<uuid>", "file_id": "<uuid>", "sha256": "<hex>", "status": "pending", "created_at": "<timestamp>"}`.
**Result:** :white_check_mark: PASS
**Notes:**

---

## Summary

| Test | Category | Result |
|------|----------|--------|
| UAT-01 | Build & Test | :white_check_mark: PASS |
| UAT-02 | Database Store | :white_check_mark: PASS |
| UAT-03 | Database Store | :white_check_mark: PASS |
| UAT-04 | Database Store | :white_check_mark: PASS |
| UAT-05 | Database Store | :white_check_mark: PASS |
| UAT-06 | Message Queue | :white_check_mark: PASS |
| UAT-07 | Message Queue | :white_check_mark: PASS |
| UAT-08 | Integration | :white_check_mark: PASS |
| UAT-09 | Integration | :white_check_mark: PASS |
| UAT-10 | Integration | :white_check_mark: PASS |

**Overall:** 10/10 passed | 0 failed | 0 skipped | 0 blocked
