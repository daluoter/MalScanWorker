# Tasks

- [x] Add Database Configuration
    - Create `backend/src/malscan/db/engine.py` with `AsyncEngine` setup.
    - Create `backend/src/malscan/db/session.py` for session dependency.
- [x] Create Data Models
    - Create `backend/src/malscan/models/base.py` (DeclarativeBase).
    - Create `backend/src/malscan/models/file.py`.
    - Create `backend/src/malscan/models/job.py`.
- [x] Update API Routes
    - Modify `backend/src/malscan/api/routes.py`:
        - Inject database session into `upload_file`.
        - Implement DB insert logic in `upload_file`.
        - Inject database session into `get_job_status`.
        - Implement DB select logic in `get_job_status`.
- [x] Verification
    - Verify application startup matches `DATABASE_URL`.
    - Verify `POST /files` inserts rows in `files` and `jobs`.
    - Verify `GET /jobs/{job_id}` returns data from DB.
