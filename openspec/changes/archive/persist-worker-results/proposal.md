# Persist Worker Analysis Results

## Summary
Implement full persistence of worker analysis results to the database and unify status definitions across Backend and Worker.

## Motivation
- **Problem 1:** Worker analysis results are not stored in the database; `get_report` API returns only mock data.
- **Problem 2:** Status definitions are inconsistent: Backend uses `processing/completed` while Worker uses `scanning/done`.

## Scope
- **Backend:** Modify `JobStatus` enum, add `result` JSONB column to `Job` model, update `get_report` API.
- **Worker:** Add `update_job_result()` function, store analysis results before marking job as `done`.
- **Database:** Alembic migration to add `result` column.

## Status Flow (Unified)
```
queued → scanning → done
              ↘ failed
```

## Related Specs
- `analysis-pipeline` (if exists)
- `job-status` (new capability)

## Approval Required
- [ ] User approval to proceed with implementation
