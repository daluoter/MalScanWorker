# Technical Design: Shorten MinIO file retention time

## Context

The backend file upload route (`backend/src/malscan/api/routes.py`) accepts files up to 100MB (`MAX_REQUEST_BODY_SIZE = 150 * 1024 * 1024` in `backend/src/malscan/main.py`), temporarily storing them in MinIO (`backend/src/malscan/storage.py`) until picked up by a worker. Currently, `storage.py` sets a Bucket Lifecycle Policy with `Expiration(days=7)` during initialization (`init_buckets`), keeping the uploaded blobs locally for a week. The expected physical disk backing MinIO has 50GB space.

## Architecture Change

Instead of reducing the file limit, only the Bucket Lifecycle Expiration parameter needs adjustment. Changing retention to 1 day guarantees an artificial ceiling of ~50GB / 100MB = 512 maximum size files stored. A throughput of >500 files per day is an acceptable baseline before exhaustion.

## Code Adjustments

### backend/src/malscan/storage.py
In `init_buckets`:
```python
        # Set lifecycle rule (1 days expiry)
        lifecycle_config = LifecycleConfig(
            [
                Rule(
                    status="Enabled",
                    rule_id="1-day-expiry", # Update rule_id to accurately reflect intention
                    expiration=Expiration(days=1), # Change from 7 to 1
                    rule_filter=Filter(prefix=""),
                )
            ]
        )
        client.set_bucket_lifecycle(bucket, lifecycle_config)
        log.info("bucket_lifecycle_configured", bucket=bucket, days=1) # Update log message
```

## Rollback Plan

If 1 day retention turns out to be too short (e.g., workers queue backing up for more than 24 hours), we can revert `days=1` back to `days=7` (or slightly higher like `days=3`) in `storage.py` and restart the API containers.
