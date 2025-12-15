# Design: Worker Analysis Result Persistence

## Overview
This design document describes the architectural changes needed to persist worker analysis results and unify status definitions.

## Current State

### Backend JobStatus Enum
```python
class JobStatus(str, Enum):
    QUEUED = "queued"
    PROCESSING = "processing"   # ← Inconsistent
    COMPLETED = "completed"     # ← Inconsistent
    FAILED = "failed"
```

### Worker Status Usage
```python
# pipeline.py line 200
await update_job_status(job_id, "done", ...)  # Uses "done"
```

### API get_report
- Returns mock data, does not query database.

## Proposed State

### Unified Status Flow
```
┌─────────┐    ┌──────────┐    ┌──────┐
│ queued  │ ─→ │ scanning │ ─→ │ done │
└─────────┘    └────┬─────┘    └──────┘
                    │
                    ↓
               ┌────────┐
               │ failed │
               └────────┘
```

### Backend JobStatus Enum (Modified)
```python
class JobStatus(str, Enum):
    QUEUED = "queued"
    SCANNING = "scanning"   # ← Changed from PROCESSING
    DONE = "done"           # ← Changed from COMPLETED
    FAILED = "failed"
```

### Job Model (Modified)
```python
class Job(Base):
    ...
    result: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
```

### Worker db.py (New Function)
```python
async def update_job_result(job_id: str, result: dict[str, Any]) -> None:
    """Store analysis result in job record."""
    ...
    stmt = text("""
        UPDATE jobs
        SET result = :result, updated_at = :updated_at
        WHERE id = :job_id
    """)
    ...
```

### Pipeline Flow (Modified)
```python
# Before setting status to done:
await update_job_result(job_id, {
    "stages": [...],
    "verdict": "...",
    "score": ...,
    ...
})
await update_job_status(job_id, "done", ...)
```

### API get_report (Modified)
```python
@router.get("/reports/{job_id}")
async def get_report(job_id: str, db: AsyncSession) -> dict:
    job = await get_job_by_id(db, job_id)
    if job is None:
        raise HTTPException(404, "Job not found")
    if job.status != JobStatus.DONE.value:
        raise HTTPException(400, "Job not completed")
    if job.result is None:
        raise HTTPException(404, "Report not available")
    return job.result
```

## Migration Strategy
1. Add `result` column as NULLABLE (backwards compatible)
2. Deploy new worker that writes results
3. Existing jobs without results will return 404 on get_report (acceptable)

## Risks and Mitigations
| Risk | Mitigation |
|------|------------|
| Large JSON in result column | Limit result size, consider separate table for v2 |
| Status enum change breaks existing jobs | Use string comparison, not enum (already implemented) |
