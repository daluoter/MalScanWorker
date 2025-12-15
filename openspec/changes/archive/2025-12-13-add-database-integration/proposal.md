# Database Integration

## Impact
- **Backend**: Adds PostgreSQL connection, SQLAlchemy models, and updates API routes to use the database.
- **Frontend**: No direct changes, but `GET /jobs/{status}` will now return real data.
- **Infrastructure**: utilizing existing Supabase credentials.

## Description
This change implements the persistence layer for MalScanWorker. currently, the backend returns mock data and does not store upload records. By integrating PostgreSQL, we ensure that:
1. File uploads are recorded (deduplicated by hash).
2. Jobs are tracked through their lifecycle.
3. The Worker (in future changes) can update job status and results.

## Key Decisions
- **Async SQLAlchemy**: Matching the `async/await` pattern of FastAPI.
- **Table Structure**:
    - `files`: id, sha256, size, filename, created_at.
    - `jobs`: id, file_id, status (queued, processing, completed, failed), created_at, updated_at.
- **Transaction**: Upload steps (MinIO + DB) should ideally be consistent, but MVP will do best-effort (MinIO first, then DB).
