---
phase: 03-database-dedup-message-queue
plan: 02
status: complete
duration: ~5m
tasks_completed: 1
files_created: 2
files_modified: 0
tests_added: 7
---

# Plan 03-02 Summary: RabbitMQ Publisher

## What was built

### Task 1: RabbitMQ publisher with queue declaration and retry logic (TDD)

**File:** `ingest/internal/queue/publisher.go` (~120 lines)

- `JobMessage` struct with JSON tags matching Python worker's expected fields: `job_id`, `file_id`, `storage_key`, `sha256`, `original_filename`
- `Channel` interface — abstracts `amqp091.Channel` for testability (`QueueDeclare`, `Publish`)
- `Publisher` struct with `ch`, `queueName`, `logger`, `retryBaseDelay` fields
- `NewPublisher(ch, queueName, logger)` constructor (default `retryBaseDelay` = 1s)
- `DeclareQueue(ctx)` — declares durable queue with DLQ arguments:
  - `x-dead-letter-exchange: ""`
  - `x-dead-letter-routing-key: "malscan-dlq"`
  - Checks `ctx.Err()` before proceeding (post-review fix)
- `Publish(ctx, msg)` — JSON marshal, 5-attempt retry with exponential backoff:
  - Delays: 1s → 2s → 4s → 8s → 16s (capped)
  - `amqp091.Persistent` delivery mode, `application/json` content type
  - Logs each retry attempt with attempt number
  - Respects context cancellation between retries

**Tests:** `ingest/internal/queue/publisher_test.go` — 7 tests with mock Channel

| Test | What it verifies |
|------|-----------------|
| TestDeclareQueue_Success | Calls QueueDeclare with durable=true, DLQ args |
| TestPublish_Success | Publishes JSON to default exchange with correct routing key |
| TestPublish_MessageFormat | Body is valid JSON with exact expected keys |
| TestPublish_RetryOnFailure | Fails 3 times then succeeds on 4th attempt |
| TestPublish_AllRetriesExhausted | Fails 5 times, returns error |
| TestPublish_BackoffTiming | Verifies attempt count matches expected delay pattern |
| TestPublish_ContextCancellation | Cancelled context stops retry loop |

## Post-review fixes

- Added `ctx.Err()` check at top of `DeclareQueue` (code quality review)

## Verification

```
go test ./internal/queue/... -count=1 -v -race  → 7/7 PASS
go vet ./...                                     → clean
go build ./...                                   → success
```

## Requirements covered

| REQ-ID | What |
|--------|------|
| MQ-01 | Queue declared with durable=true and DLQ arguments matching Python |
| MQ-02 | Message body JSON with exact fields Python worker expects |
| MQ-03 | Persistent delivery mode + application/json content type |
| MQ-04 | 5-attempt exponential backoff retry (1s→2s→4s→8s→16s) |

## Decisions made during execution

- `retryBaseDelay` field (unexported) allows tests to use 1ms delays instead of 1s — avoids 30+ second test times
- `Channel` interface has only `QueueDeclare` and `Publish` — minimal surface for mock testing
- Backoff formula: `baseDelay * 2^(attempt-1)` capped at 16s, matching Python tenacity config exactly
- Default exchange (`""`) with queue name as routing key — matches Python's `default_exchange.publish()`
