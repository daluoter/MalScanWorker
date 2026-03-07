# Proposal: Shorten MinIO file retention time

## Problem Statement

The system allows file uploads up to 100MB per file, but the storage backend is currently constrained to ~50GB of disk space. Under the current retention policy of 7 days, if users max out the file size limit, the storage space can quickly reach capacity (approx 512 max-size files), causing the backend to fail for new uploads or worker processing. Since a 100MB capacity is crucial for scanning certain malicious file types (like ISOs or full installation payloads), reverting the upload limit is undesirable.

## Proposed Solution

Modify the MinIO object lifecycle policy so that uploaded files expire and are automatically deleted after 1 day (`days=1`) instead of 7 days. This change guarantees the system can comfortably handle around 500 maximum-size files on any given day without hitting the 50GB storage ceiling, preserving the system's ability to scan large files while mitigating disk space exhaustion risks.

## Expected Impact

*   **Positive**: The 100MB file upload capability is maintained. The risk of sudden system outages due to disk space exhaustion is significantly reduced.
*   **Negative**: Stale files (>24 hours old) can no longer be retrieved for manual re-analysis or delayed deeper sandboxing without requiring the user to upload them again. However, the analysis report and status generated right after upload will remain in the database indefinitely.
