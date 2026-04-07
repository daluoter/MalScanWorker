# Password-Protected Archive Handling Design

Date: 2026-04-01
Owner: MalScanWorker team
Status: Approved for planning

## 1. Problem Statement

Current behavior cannot complete recursive analysis for password-protected archives.
When archive extraction needs a password, the system does not complete a user-guided password flow end-to-end, so files inside encrypted archives are not analyzed.

Business goal (single purpose): enable analysis of password-protected archives by prompting users for password input during job processing, and if password attempts fail repeatedly, show extraction failure in the final report.

## 2. Locked Product Decisions

Decisions confirmed with user:

1. Max password attempts: **3**.
2. After 3 failed attempts: job status becomes **done** (not failed), and final report must be available.
3. Password input location: **Job Status page** (`/jobs/:jobId`).

## 3. Goals and Non-Goals

### Goals

1. Detect when archive extraction requires password and transition to `password_required` state.
2. Allow user to submit archive password from job status page and resume analysis.
3. Correctly handle wrong password retries with a hard limit of 3 attempts.
4. Persist final report with explicit extraction failure details when attempts are exhausted.
5. Keep existing non-password archive and non-archive flows unchanged.

### Non-Goals

1. Cracking or brute-force password guessing.
2. Persisting archive passwords in database.
3. Building a separate password management subsystem.
4. Redesigning all report UI; only targeted additions for extraction failure clarity.

## 4. Current Gaps in Codebase

1. Worker archive stage (`worker/src/malscan_worker/stages/archive_extract.py`) has no user password input/resume path implemented.
2. Worker pipeline stage wrapper (`worker/src/malscan_worker/pipeline.py`) catches generic exceptions and can swallow password-specific control flow unless explicitly rethrown.
3. Backend has no password submission endpoint in `backend/src/malscan/api/`.
4. Backend `JobStatus` enum/model (`backend/src/malscan/models/job.py`) does not include `password_required`.
5. Frontend currently has status typing for `password_required` in some files but no working UI flow in `JobStatusPage` for password submission.

## 5. Proposed Design (Approach A)

### 5.1 Job State Model

Add and use explicit state:

- `queued`
- `scanning`
- `password_required` (new active waiting state)
- `done`
- `failed`

State transitions for encrypted archives:

1. `queued` -> `scanning`
2. `scanning` -> `password_required` (password needed, no password provided OR wrong password with attempts remaining)
3. `password_required` -> `queued` (user submits password)
4. `queued` -> `scanning` (worker consumes retry message)
5. If password correct: continue normal analysis -> `done`
6. If password wrong and attempts exhausted (3): write final report with extraction failure -> `done`

### 5.2 Data Model Changes

#### Backend DB / ORM

In `jobs` table and `Job` model:

1. Add `password_attempts` integer column, default `0`, non-null.
2. Extend `JobStatus` enum and API schema literals to include `password_required`.

`password_attempts` increment rule:

1. Increment only when a user-submitted password was used for extraction and extraction failed with wrong password.
2. Do not increment when password is required but not yet submitted.

Rationale:

- `password_attempts` tracks confirmed wrong attempts and supports deterministic retry limit.
- No password value is stored in DB.

#### Migration

Create Alembic revision under `backend/alembic/versions/` to:

1. Add `password_attempts` column.
2. Backfill existing rows with default `0`.

### 5.3 API Contract Changes

#### New endpoint

`POST /api/v1/jobs/{job_id}/password`

Request body:

```json
{
  "password": "string"
}
```

Success response:

```json
{
  "job_id": "...",
  "status": "queued",
  "message": "Password submitted. Retrying archive extraction.",
  "attempts_used": 1,
  "attempts_remaining": 2
}
```

Validation rules:

1. `job_id` exists.
2. Job status must be `password_required`.
3. `password` must be non-empty and within safe length limit.
4. If `password_attempts >= 3`, reject with `409`.

Error behavior:

1. `404` job not found.
2. `409` invalid job state or attempts exhausted.
3. `422` missing/invalid password payload.
4. `503` queue publish failure.

#### Existing endpoint updates

1. `GET /api/v1/jobs/{job_id}` and SSE stream include `password_required` status.
2. Job status response includes attempts metadata (required for UX clarity):
   - `password_attempts`
   - `password_attempts_remaining`

### 5.4 Queue Message Contract

Password is passed only through the retry message payload, not DB:

```json
{
  "job_id": "...",
  "file_id": "...",
  "storage_key": "...",
  "sha256": "...",
  "original_filename": "...",
  "archive_password": "..."
}
```

Security boundary:

1. Message payload contains plaintext password only for transient processing.
2. Password must never be logged.
3. Password must not be persisted to DB result/error fields.

### 5.5 Worker Exception Model

Introduce explicit archive password control-flow exceptions (worker domain):

1. `ArchivePasswordRequiredError`
2. `ArchiveWrongPasswordError`

`ArchiveExtractStage` behavior:

1. If archive is encrypted and no password provided: raise `ArchivePasswordRequiredError`.
2. If password provided but invalid: raise `ArchiveWrongPasswordError`.
3. If password valid: extract and continue current recursive submission behavior.

Support per-format encrypted detection and normalization:

1. ZIP (`zipfile` encrypted flag / bad password runtime errors)
2. 7z (`py7zr` password requirement/wrong password exceptions)
3. RAR (`rarfile` password errors)

Normalize library-specific exceptions into the two domain exceptions above.

### 5.6 Pipeline and Consumer Orchestration

#### Pipeline (`run_pipeline` and `_run_stage`)

1. `_run_stage` must rethrow password domain exceptions instead of converting them into generic failed `StageResult`.
2. `run_pipeline` preserves current behavior for all other failures.

#### Consumer (`process_message`)

Add dedicated branches:

1. Catch `ArchivePasswordRequiredError`:
   - Update job to `password_required`
   - Set user-facing `error_message` prompt
   - ACK message (do not requeue)
2. Catch `ArchiveWrongPasswordError`:
   - Atomically increment `password_attempts`
   - If attempts < 3: set `password_required` + retry prompt, ACK
   - If attempts == 3: build/store final report with extraction failure, set status `done`, ACK
3. Keep existing retry/DLQ logic for infrastructure failures.

### 5.7 Report Model and Frontend Display

When attempts exhausted, final report must contain explicit archive extraction failure information in `results.archive_extract`:

Required fields:

1. `archive_type`
2. `extracted_count = 0`
3. `sub_jobs_created = 0`
4. `total_extracted_bytes = 0`
5. `reason = "Archive extraction failed after 3 incorrect password attempts"`

Recommended additional field:

1. `extraction_failed = true`

Frontend behavior:

1. Job status page shows password form only for `password_required`.
2. Submit action calls password endpoint.
3. If SSE returns `password_required` again after submission, show wrong password feedback and attempts remaining.
4. Report page always renders extraction failure message clearly when `archive_extract.reason` indicates password retry exhaustion.

## 6. Edge Cases and Handling

1. **Concurrent password submissions**: enforce status check and attempt update atomically in DB.
2. **Submit while not `password_required`**: reject `409`.
3. **Worker restarts between submissions**: retry path remains durable via queue/job state.
4. **Encrypted format unsupported**: mark extraction failure reason as unsupported encryption method.
5. **Nested encrypted archives**: child jobs independently follow same password flow.
6. **SSE disconnect/reconnect**: status polling source of truth is DB; UI restores form on reconnect.
7. **Queue publish failure on password submit**: return `503`, preserve recoverable user state.
8. **Password length abuse**: enforce max length and reject too-long payloads.
9. **Sensitive data leakage**: never log password; scrub related log fields.
10. **Final report availability after exhaustion**: ensure result is written before setting `done`.

## 7. Security and Privacy Constraints

1. Archive password is transient operational data; do not store in DB.
2. Disallow password echo in logs, metrics labels, and error traces.
3. Keep attempts limit fixed at 3 server-side for this phase; ignore client-side counters.
4. Use server-side state transitions only; frontend state is advisory.

## 8. Testing Strategy

### Worker tests

1. Encrypted archive without password triggers `password_required` path.
2. Wrong password increments attempts and re-enters `password_required`.
3. Third wrong password writes final report and marks job `done`.
4. Correct password extracts files and creates sub-jobs.
5. `_run_stage` rethrows password exceptions and still wraps non-password exceptions.

### Backend tests

1. Password endpoint success for valid `password_required` job.
2. `409` for invalid status and exhausted attempts.
3. `404` for unknown job.
4. `422` for invalid payload.
5. Job/SSE status response includes `password_required` and attempts metadata.

### Frontend tests

1. Job status page renders password form for `password_required`.
2. Wrong password cycle is reflected after SSE update.
3. Attempts remaining text updates correctly.
4. Report page shows extraction failure message for exhausted attempts.

## 9. Observability

Add structured logs (without password values):

1. `archive_password_required`
2. `archive_password_wrong`
3. `archive_password_attempts_exhausted`
4. `archive_password_submitted`

Metrics (optional but recommended):

1. Counter: password-required events.
2. Counter: wrong-password attempts.
3. Counter: exhausted-attempts outcomes.

## 10. Acceptance Criteria

1. Upload encrypted archive -> system enters `password_required` and UI prompts for password.
2. Correct password within 3 attempts -> archive contents are extracted and analyzed.
3. Wrong password 3 times -> job ends in `done`, and report explicitly states extraction failed due to password attempts exhausted.
4. Non-encrypted uploads and existing analysis pipeline behavior remain unchanged.
5. No password value appears in DB or logs.

## 11. YAGNI Scope Guard

This phase intentionally excludes:

1. Password vault/integration.
2. Multi-password dictionaries.
3. Automatic retry scheduling without user input.
4. Report redesign beyond required failure visibility.
