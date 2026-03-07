# Implementation Tasks: Shorten MinIO file retention time

- [ ] **Task 1: Update MinIO retention policy in the backend storage config**
  - **File**: `backend/src/malscan/storage.py`
  - **Action**: Locate `init_buckets()`. Update `Expiration(days=7)` to `days=1`. Adjust the corresponding `rule_id` and `log.info` lines.
- [ ] **Task 2: Restart the API container**
  - **Action**: Run `docker compose restart api` or `docker compose up -d --build api` to apply the changed singleton configuration during startup.
- [ ] **Task 3: Verify the new 1-day retention policy**
  - **Action**: Log into MinIO Console (http://localhost:9001) > Administrator > Buckets > `malscan.uploads` > Lifecycle, and visually verify the rule duration is set to 1 day.
