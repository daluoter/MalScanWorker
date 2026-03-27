# Codebase Concerns

**Analysis Date:** 2024-12-20

## Tech Debt

### Sandbox Stage Not Implemented
- **Issue:** Real sandbox analysis adapter is stubbed out with mock implementation only
- **Files:** `worker/src/malscan_worker/stages/sandbox.py:80-81`
- **Impact:** Sandbox stage returns mock/fake behavioral data instead of real dynamic analysis. Production deployments cannot perform actual sandboxed execution of malware samples.
- **Fix approach:** Implement real sandbox adapter (Cuckoo, CAPE, or similar). Create abstraction layer in `sandbox.py` to support pluggable backends. Add configuration to select sandbox provider at runtime.

### Incomplete Readiness Check Endpoint
- **Issue:** `/ready` endpoint does not actually verify critical service connectivity
- **Files:** `backend/src/malscan/main.py:64-68`
- **Current behavior:** Returns `{"status": "ready"}` without checking database, MinIO, or RabbitMQ connections
- **Impact:** Load balancers and orchestrators will mark service as ready even when dependencies are down, causing cascading failures and poor observability
- **Fix approach:** Implement actual health checks for all three services (PostgreSQL, MinIO, RabbitMQ). Cache results with 5-10s TTL to avoid performance impact. Return 503 if any critical service is unavailable.

### Temporary File Cleanup Not Guaranteed
- **Issue:** Temporary files created during upload may not be cleaned up if process crashes between write and deletion
- **Files:** `backend/src/malscan/api/routes.py:151-201`
- **Impact:** Disk space gradually consumed by orphaned temp files, potential disk exhaustion over time
- **Fix approach:** Use context managers or finally blocks (already partially done). Consider periodic cleanup task for `/tmp/{job_id}/` directories older than 1 hour.

### Archive Extraction Hard-coded Limits
- **Issue:** Defense limits are hardcoded in method rather than configuration
- **Files:** `worker/src/malscan_worker/stages/archive_extract.py:85-89`
  - `max_files = 15` (line 86)
  - `max_total_size = 200 * 1024 * 1024` (line 87)
  - `max_expansion_ratio = 100` (line 89)
- **Impact:** Cannot adjust security parameters without code changes. Cannot vary limits per environment.
- **Fix approach:** Move all limits to Settings in `worker/src/malscan_worker/config.py`. Load from environment variables at startup.

### Global Singleton State Pattern Fragility
- **Issue:** Multiple services use global module-level state for singletons (RabbitMQ, MinIO, database, YARA rules)
- **Files:**
  - `backend/src/malscan/queue.py:25-27` (RabbitMQ globals)
  - `backend/src/malscan/storage.py:22-23` (MinIO client)
  - `backend/src/malscan/db/engine.py:7` (DB engine)
  - `backend/src/malscan/db/session.py:14` (session factory)
  - `worker/src/malscan_worker/stages/yara_scan.py:27` (compiled rules)
- **Impact:** Thread-safety concerns in concurrent requests. Difficult to test in isolation. Connection state can become inconsistent if initialization fails partially.
- **Fix approach:** Refactor to dependency injection pattern. Use context managers or async context managers for resource initialization. See `worker/src/malscan_worker/utils/submission.py:21-39` for better singleton pattern example with `get_instance()`.

## Known Bugs

### Parent Job Relationship Not Updated on Sub-job Completion
- **Issue:** When archive extraction creates sub-jobs, parent job's `total_sub`, `completed_sub`, `malicious_sub` counters are not updated as sub-jobs complete
- **Files:**
  - `backend/src/malscan/models/job.py:56-59` (counters defined but never updated)
  - `worker/src/malscan_worker/utils/submission.py:160-170` (sub-job creation)
- **Symptom:** Parent job reports `completed_sub=0` even after all children finish. UI cannot show accurate sub-job completion statistics.
- **Trigger:** Extract archive containing multiple files → analyze each file → completion counters stay at 0
- **Workaround:** Query directly from database with self-joins to count sub-jobs
- **Fix approach:** Add update logic in worker when sub-job completes. Either:
  1. Worker pushes completion event back to API and updates counters
  2. API implements background job to poll sub-job statuses and aggregate results
  3. Use database triggers on job status changes

### Form Parsing May Fail Silently on Multipart Boundary Issues
- **Issue:** FastAPI's `request.form()` parsing can fail on malformed multipart data, but error handling catches broad exceptions
- **Files:** `backend/src/malscan/api/routes.py:99-107`
- **Impact:** Client gets generic "Internal Error" instead of specific "malformed form data" error. Difficult to debug client issues.
- **Fix approach:** Add specific exception handling for multipart parsing errors. Return 400 with detailed error about malformed form boundaries.

## Security Considerations

### CORS Configuration Insecure by Default
- **Risk:** `CORS defaults to allow_origins=["*"]` with credentials=False but no production override is enforced
- **Files:** `backend/src/malscan/config.py:27`, `backend/src/malscan/main.py:35-52`
- **Current mitigation:** Comment recommends restricting in production, but no validation enforces it
- **Recommendations:**
  1. Change default to empty string (deny all) instead of "*"
  2. Add validation: if `cors_origins == "*"` in production (detect via env), log warning or fail startup
  3. Document and require explicit `CORS_ORIGINS` env var in production deployments

### Insufficient Input Validation on Parent Job ID
- **Risk:** `parent_job_id` accepted as string, parsed to UUID, but no validation of depth constraint happens before querying
- **Files:** `backend/src/malscan/api/routes.py:112-134`
- **Issue:** If parent job doesn't exist but depth constraint isn't checked first, returns "Parent job not found" which is correct but logic order could fail silently if query fails
- **Recommendations:**
  1. Always validate UUID format immediately, return 400 if invalid
  2. Check depth constraint before querying database
  3. Add rate limiting on parent_job_id parameter to prevent enumeration attacks

### Filename Sanitization Could Miss Edge Cases
- **Risk:** `_sanitize_filename()` handles most cases but may miss Unicode normalization attacks or null byte injection variants
- **Files:** `backend/src/malscan/api/routes.py:31-55`
- **Current mitigation:** Strips path components, null bytes, truncates to 255 chars
- **Recommendations:**
  1. Add explicit whitelist of allowed characters (alphanumeric, dash, underscore, dot only)
  2. Use `unicodedata.normalize('NFKC')` for Unicode normalization before processing
  3. Add test cases for edge cases: `"..\\..\\etc\\passwd"`, `"/etc/passwd"`, `"file\x00.txt"`, emoji filenames

### No Audit Logging of File Upload Sources
- **Risk:** Cannot determine which client uploaded malicious files or trace origin of submissions
- **Files:** `backend/src/malscan/api/routes.py:86-276`
- **Impact:** Forensics and incident response hampered. No way to identify compromised API keys.
- **Recommendations:**
  1. Extract client IP from request headers (X-Forwarded-For)
  2. Log uploader identity (API key ID, user ID, service account)
  3. Store in database or separate audit log: `(job_id, uploader_id, client_ip, timestamp, filename, sha256)`

### No Rate Limiting on File Upload
- **Risk:** Attacker can submit unlimited large files simultaneously, causing DoS
- **Files:** `backend/src/malscan/api/routes.py:58-85`
- **Impact:** Backend resources exhausted, legitimate requests blocked
- **Recommendations:**
  1. Add per-IP or per-API-key rate limiting (e.g., 10 uploads/min per IP)
  2. Implement concurrent upload queue with backpressure
  3. Use header-based rate limit advertisement (X-RateLimit-Remaining)

## Performance Bottlenecks

### Streaming SSE Status Endpoint Polls Database Every 1 Second
- **Problem:** `stream_job_status()` creates new database session and queries every 1 second, even if status unchanged
- **Files:** `backend/src/malscan/api/routes.py:359-421`
- **Cause:** Polling loop at line 416: `await asyncio.sleep(1.0)` before each check
- **Impact:** Continuous database load. With 100 concurrent streaming connections, 100 queries/sec to database.
- **Improvement path:**
  1. Use PostgreSQL LISTEN/NOTIFY instead of polling (requires schema changes)
  2. Implement server-side event batching: cache result and only query every 5-10 seconds
  3. Use Redis pub/sub for job status updates from worker to API
  4. Add exponential backoff: start with 1s, increase to 10s if status stable

### Archive Extraction Creates Many Hash Calculations
- **Problem:** SHA256 calculated twice for each extracted file (once during extraction, redundantly in submission)
- **Files:** `worker/src/malscan_worker/stages/archive_extract.py:144-149`
- **Impact:** CPU overhead for large archives with many files
- **Improvement path:**
  1. Calculate hash once during extraction, pass to submitter
  2. Cache hash results in extraction metadata
  3. Profile extraction stage to identify bottleneck

### Thread Pool Executor Not Tuned for MinIO Operations
- **Problem:** `ThreadPoolExecutor(max_workers=4)` hardcoded for MinIO operations
- **Files:** `backend/src/malscan/storage.py:20`
- **Impact:** Limited concurrency for upload/download. With 4 workers, I/O waits block others.
- **Improvement path:**
  1. Increase to `max_workers=min(32, (os.cpu_count() or 1) + 4)` per asyncio best practices
  2. Monitor executor queue depth
  3. Consider switching to truly async S3 client (e.g., `aioboto3`)

### Database Connection Pool Size Insufficient for High Concurrency
- **Problem:** `pool_size=10, max_overflow=20` allows only 30 concurrent connections
- **Files:** `backend/src/malscan/db/engine.py:20-21`
- **Impact:** At 50+ concurrent requests, connection pool exhausted, requests queue/timeout
- **Improvement path:**
  1. Increase `pool_size` to at least 20-30 for production
  2. Monitor connection pool stats
  3. Consider connection pooling proxy (PgBouncer) for higher scalability

## Fragile Areas

### Archive Extraction Logic Highly Complex
- **Files:** `worker/src/malscan_worker/stages/archive_extract.py` (476 lines)
- **Why fragile:**
  - Multiple format detections (magic bytes, mime type, extension, YARA results)
  - Platform-specific path handling (Windows vs Unix)
  - Optional dependencies (py7zr, rarfile) silently degraded
  - Zip bomb detection heuristics prone to false positives/negatives
- **Safe modification:** Add comprehensive test coverage for each archive format and edge case (nested archives, bomb detection, large files). Add logging at each detection step.
- **Test coverage:**
  - ✓ Tests exist: `worker/tests/test_stages.py` (217 lines)
  - ✗ Gaps: No tests for RAR format, nested archives, bomb detection heuristics, missing optional dependencies

### API Routes File Too Large and Multipurpose
- **Files:** `backend/src/malscan/api/routes.py` (484 lines)
- **Why fragile:**
  - All endpoints (upload, status, stream, report) in single file
  - Complex business logic mixed with HTTP routing
  - Hard to reason about error paths
- **Safe modification:** Break into separate modules: `routes/upload.py`, `routes/status.py`, `routes/report.py`. Extract business logic to service layer.
- **Test coverage:**
  - ✓ Tests exist: `backend/tests/test_api.py` (206 lines)
  - ✗ Gaps: No SSE stream test, limited error path testing, no concurrent upload tests

### Sub-job Submission Tightly Coupled to Archive Extraction
- **Files:**
  - `worker/src/malscan_worker/stages/archive_extract.py:128-189` (submission logic)
  - `worker/src/malscan_worker/utils/submission.py` (separate but highly coupled)
- **Why fragile:**
  - If `InternalJobSubmitter` initialization fails, entire extraction stage fails
  - Database session management complexity (separate session to avoid expiration)
  - No transactional guarantees across extraction and submission
- **Safe modification:** Extract to interface with mock implementation for testing. Add retry logic for transient submission failures.

## Scaling Limits

### Single Global RabbitMQ Connection
- **Current capacity:** 1 connection shared across entire backend/worker
- **Limit:** RabbitMQ connection has bandwidth and channel limits (~2000 channels per connection)
- **Breaks at:** ~1000 concurrent job submissions in rapid succession
- **Scaling path:**
  1. Implement connection pooling (multiple connections per service instance)
  2. Use RabbitMQ cluster for horizontal scaling
  3. Consider message broker alternative (Kafka) for higher throughput

### Recursive Job Depth Limited to 3
- **Current:** `max_job_depth=3` hardcoded in code, can be tuned via env
- **Breaks at:** Nested archives deeper than 3 levels ignored (by design)
- **Scaling path:**
  - Not a hard limit, but designed conservatively for ZIP bomb defense
  - Increase carefully with better bomb detection heuristics
  - Monitor CPU/memory consumption per recursion level

### Single MinIO Instance Bottleneck
- **Current capacity:** Single MinIO endpoint, connection pool size 4
- **Limit:** Large file uploads block on MinIO write latency
- **Breaks at:** ~100 concurrent uploads of 100MB files
- **Scaling path:**
  1. Use MinIO cluster (HA setup)
  2. Implement S3-compatible CDN/cache layer (CloudFront, Cloudflare)
  3. Switch to serverless object storage (S3, GCS) for elastic scaling

### Database Connection Pool Limited
- **Current capacity:** 10 base connections, 20 overflow = 30 total
- **Limit:** Concurrent queries exceed pool size
- **Breaks at:** ~50+ concurrent requests during peak load
- **Scaling path:**
  1. Use PgBouncer or equivalent connection pooling proxy
  2. Scale database with read replicas for status queries
  3. Implement caching layer (Redis) for frequently accessed job statuses

## Dependencies at Risk

### Optional Dependencies for Archive Extraction
- **Risk:** `py7zr` and `rarfile` are optional but not gracefully degraded
- **Files:** `worker/src/malscan_worker/stages/archive_extract.py:24-37`
- **Impact:** If not installed, 7z and RAR files return "unsupported format" instead of error. Silent degradation.
- **Migration plan:**
  1. Make dependencies explicit in `pyproject.toml` (move from optional to required)
  2. Or: Implement wrapper that raises clear error if dependency missing
  3. Document in README which optional formats require which packages

### Outdated or Transitive Vulnerable Dependencies
- **Risk:** `poetry.lock` not reviewed in analysis, but many common dependencies (aio-pika, sqlalchemy, fastapi) receive regular security patches
- **Files:** `backend/pyproject.toml`, `worker/pyproject.toml`
- **Current mitigation:** Version constraints are mostly permissive (^X.Y.Z)
- **Recommendations:**
  1. Run `poetry audit` in CI/CD pipeline
  2. Regular dependency updates (monthly security reviews)
  3. Pin exact versions in production deployments

## Missing Critical Features

### No Horizontal Scaling Support for Worker
- **Problem:** Worker is single-instance, no clustering or load balancing
- **Blocks:** Cannot scale to handle high throughput of jobs
- **Gap:** No mechanism to spawn multiple worker instances consuming from RabbitMQ

### No Persistent Job Queue if Services Fail
- **Problem:** If worker crashes, in-progress jobs status not persisted to database
- **Blocks:** Cannot resume analysis if worker restarts
- **Gap:** Job status only updated at stage completion, not continuously
- **Fix:** Add intermediate status updates to database every N seconds

### No Dead Letter Queue Monitoring
- **Problem:** RabbitMQ DLQ configured but never monitored or processed
- **Files:** `backend/src/malscan/queue.py:43-49`
- **Blocks:** Failed jobs silently accumulate in DLQ, never retried or reported
- **Fix:** Implement DLQ consumer that logs/alerts on failed jobs

### No Batch Analysis or Bulk Upload API
- **Problem:** Can only submit one file at a time
- **Blocks:** Scanning multiple samples requires N separate requests
- **Gap:** No `/api/v1/files/batch` or similar endpoint

## Test Coverage Gaps

### Sandbox Stage Mock Not Validated Against Real Output
- **What's not tested:** Sandbox stage mock data format matches real sandbox adapter output
- **Files:** `worker/tests/test_stages.py`
- **Risk:** When real sandbox is implemented, mock format differences will break tests
- **Priority:** High
- **Fix approach:** Define schema for sandbox results, validate both mock and real adapter against it

### SSE Stream Endpoint Not Tested
- **What's not tested:** Job status streaming with EventSourceResponse
- **Files:** `backend/tests/test_api.py` (missing SSE test)
- **Risk:** Stream disconnection handling, data format issues won't be caught
- **Priority:** High
- **Fix approach:** Add test using `AsyncClient` with `stream=True` or mock EventSourceResponse

### No Concurrent Upload Tests
- **What's not tested:** Multiple simultaneous file uploads
- **Files:** `backend/tests/test_api.py`
- **Risk:** Race conditions in file deduplication, database index locks, RabbitMQ publish failures under load
- **Priority:** Medium
- **Fix approach:** Use `pytest-asyncio` with `pytest.mark.asyncio` to test concurrent uploads

### Parent Job Aggregation Logic Not Tested
- **What's not tested:** Sub-job completion updates parent job counters
- **Files:** Backend/worker integration tests missing
- **Risk:** Counters stay at 0 indefinitely, feature unusable
- **Priority:** High
- **Fix approach:** Create integration test that extracts archive, analyzes files, verifies parent counters

### Archive Extraction Bomb Detection Not Tested
- **What's not tested:** Zip bomb, zip slip, and other malicious archives
- **Files:** `worker/tests/test_stages.py` (no bomb detection tests)
- **Risk:** Malicious archives bypass defenses, consume resources
- **Priority:** High
- **Fix approach:** Create test fixtures with known malicious archives (carefully), verify they're caught

### No Error Recovery Tests
- **What's not tested:** Graceful handling of service failures (MinIO down, RabbitMQ down, DB down)
- **Files:** Integration tests missing
- **Risk:** Cascading failures, stuck jobs, data corruption
- **Priority:** Medium
- **Fix approach:** Add chaos engineering tests with service simulation failures

---

*Concerns audit: 2024-12-20*
