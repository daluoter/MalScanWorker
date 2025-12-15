# Tasks for persist-worker-results

## Status: ✅ COMPLETED & ARCHIVED

## Prerequisites
- [x] Ensure Alembic is configured in backend
- [x] Ensure database connection works

## Task List

### 1. Unify Status Definitions (Backend)
- [x] Modify `backend/src/malscan/models/job.py`:
  - Change `PROCESSING = "processing"` → `SCANNING = "scanning"`
  - Change `COMPLETED = "completed"` → `DONE = "done"`
- [x] Search for hardcoded status strings and update them

### 2. Add Result Column (Backend)
- [x] Add `result` JSONB column to `Job` model (`nullable=True`)
- [x] Generate Alembic migration
- [x] Apply migration to database

### 3. Implement update_job_result (Worker)
- [x] Add `update_job_result()` function in `db.py`

### 4. Store Results in Pipeline (Worker)
- [x] Add `_build_analysis_result()` function
- [x] Call `update_job_result()` before setting status to `done`

### 5. Implement Real get_report API (Backend)
- [x] Modify `get_report()` to query database
- [x] Return `job.result` if status is `done`
- [x] Return 404/400 for invalid states

### 6. Verification
- [x] Run linter (ruff) - all fixed
- [x] End-to-end test - completed
- [x] Verify status transitions: queued → scanning → done
