# Phase 8 Research: Encryption Reporting & Operational Hardening

**Phase:** 8
**Requirements:** DET-06, STM-03
**Researched:** 2026-03-30

## Requirement Analysis

### DET-06: Encryption Method Reporting

**Goal:** Report the specific encryption method (ZipCrypto, AES-256, 7zAES, RAR4, RAR5-AES) in scan metadata for password-protected archives — useful as IOC for threat intelligence.

**Current State:**
- Go ingest layer detects encryption (boolean) but does NOT identify the specific method
- Detection functions return `(bool, error)` — no method granularity
- The handler stores `password_required` status but no encryption method metadata
- The `JobRecord` and `UploadResponse` have no `encryption_method` field
- The RabbitMQ `JobMessage` has no encryption method field

**Implementation Approach:**

Change detection functions from `(bool, error)` to `(string, error)` where the string is the encryption method name (empty string = not encrypted):

1. **ZIP detection** (`zip_detect.go`):
   - Go's `archive/zip` exposes `File.Method` (compression method) but NOT encryption method directly
   - However, bit 0 of `Flags` = encrypted. The encryption method is determined by:
     - If `CreatorVersion` >= 51 AND the extra field contains WinZip AES marker (0x9901): **AES-256** (or AES-128/AES-192 based on the AES strength byte)
     - Otherwise: **ZipCrypto** (traditional PKZIP encryption)
   - Extra field parsing: look for header ID `0x9901` in `f.Extra`, read the AES encryption strength byte (1=AES-128, 2=AES-192, 3=AES-256)
   - Most common: ZipCrypto (legacy) or AES-256 (WinZip AES-2 extension)

2. **7z detection** (`sevenz_detect.go`):
   - Current code already checks for `0x17` (kEncodedHeader) and AES method bytes `{0x06, 0xF1, 0x07}`
   - The 7z AES method is always AES-256 + SHA-256 (codec ID 0x06F10701)
   - If kEncodedHeader (0x17) found: return `"7zAES"` (header encryption, implies AES-256)
   - If AES method bytes found in unencrypted header: return `"7zAES"` (file encryption)
   - 7z only supports one encryption method: AES-256-SHA-256

3. **RAR detection** (`rar_detect.go`):
   - RAR4: Archive flag 0x0080 (encrypted headers) or file flag 0x04 (file encryption)
     - RAR4 encryption uses AES-128 in CBC mode → return `"RAR4"` (known weak encryption)
   - RAR5: Encryption header type 4 or file flag 0x04
     - RAR5 uses AES-256 in CBC mode with HMAC-SHA-256 PBKDF2 → return `"RAR5-AES"`
   - The format version is already distinguished by signature (7 bytes = RAR4, 8 bytes = RAR5)

**Storage Path:**
- Add `encryption_method` field to `JobRecord`, `UploadResponse`, and `JobMessage`
- Go handler stores in DB column (requires SQL migration) or in the JSONB `result` column
- **Preferred: Use a new `encryption_method` nullable varchar column on the jobs table** — simple, queryable, aligns with existing pattern of additive columns
- SQL migration: `ALTER TABLE jobs ADD COLUMN encryption_method VARCHAR(20);`
- The Python JobStatusResponse and ReportResponse should expose it

### STM-03: Stuck Job Auto-Cleanup

**Goal:** Jobs stuck in `password_required` for >24 hours are auto-failed with clear error message.

**Current State:**
- No background cleanup task exists anywhere
- Worker (`main.py`) runs consumer loop only, no periodic tasks
- Backend (`routes.py`) serves HTTP requests only
- No cron, no scheduler, no background task infrastructure

**Implementation Options:**

1. **Python asyncio background task in worker `main.py`** (RECOMMENDED)
   - Add a periodic coroutine that runs alongside the consumer
   - Every 15 minutes: `UPDATE jobs SET status='failed', error_message='...' WHERE status='password_required' AND updated_at < NOW() - INTERVAL '24 hours'`
   - Uses existing `_engine` from `db.py` — no new connections needed
   - Runs inside the worker process — no new service needed
   - Respects `shutdown_event` for graceful shutdown

2. **Cron job / external script**
   - Separate script that runs via cron
   - Adds operational complexity (another thing to deploy/monitor)
   - Not preferred for a single query

3. **PostgreSQL scheduled job (pg_cron extension)**
   - Requires pg_cron extension, not standard in all deployments
   - Not portable

**Decision: Option 1** — asyncio background task in worker. Simplest, leverages existing infrastructure, no new dependencies.

**Implementation Details:**
- New function `cleanup_stuck_jobs()` in `worker/src/malscan_worker/db.py`
- Background task `run_stuck_job_cleanup()` in `main.py` that loops every 15 minutes
- SQL: `UPDATE jobs SET status = 'failed', error_message = 'Automatically failed: password not submitted within 24 hours', updated_at = NOW() WHERE status = 'password_required' AND updated_at < NOW() - INTERVAL '24 hours' RETURNING id`
- Log each failed job ID for observability
- Must handle the `password_required → failed` transition validation (already in `ALLOWED_TRANSITIONS`)

## Technical Risks

1. **ZIP AES detection**: Go's `archive/zip` doesn't parse the WinZip AES extra field natively — we need to parse `f.Extra` manually (straightforward: find 0x9901 header, read AES strength byte)
2. **Schema migration**: Adding `encryption_method` column requires running the migration on existing databases — use idempotent `DO $$ ... END $$` pattern (same as `add_password_attempts_column.sql`)
3. **Backward compatibility**: `encryption_method` must be nullable — non-encrypted files have NULL, Python response schemas must handle `Optional[str]`

## Dependencies

- No new Go or Python packages needed
- Phase 7 complete — all detection functions exist and are tested
- Existing infrastructure (PostgreSQL, Redis, RabbitMQ) sufficient

## Validation Architecture

### DET-06 Validation
- Unit tests: Each detection function returns correct encryption method string
- Integration: Upload encrypted ZIP (ZipCrypto), ZIP (AES-256), 7z, RAR4, RAR5 → verify `encryption_method` field in response and DB

### STM-03 Validation
- Unit test: `cleanup_stuck_jobs()` with mocked DB returns count of failed jobs
- Integration: Create a `password_required` job with `updated_at` backdated >24h → run cleanup → verify status is `failed` with correct error message

---
*Phase: 08-encryption-reporting-operational-hardening*
*Researched: 2026-03-30*
