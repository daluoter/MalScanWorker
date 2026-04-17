# Dynamic Sandbox Integration Design

**Date:** 2026-04-17
**Status:** Implementing
**Approach:** Dedicated sandbox queue and worker pool with additive report schema

## Problem

`worker/src/malscan_worker/stages/sandbox.py` is still mock-only. The pipeline already reserves a sandbox stage, and backend/reporting/scoring already understand `results.sandbox`, but there is no real provider abstraction, no CAPEv2 integration, and no way to run long detonation jobs without blocking the static worker pool.

## Goals

1. Add a `SandboxProvider` abstraction and registry with `mock` and `capev2` providers.
2. Support CAPEv2 file and URL submission, task polling, normalized report fetch, and artifact metadata references.
3. Keep the existing `results.sandbox.behaviors`, `results.sandbox.network_connections`, and `results.sandbox.is_mock` compatibility path intact.
4. Normalize sandbox output into one additive `results.sandbox` block with these fields:
   - `executed`, `provider`, `task_id`, `is_mock`, `verdict_hint`
   - `processes`, `files`, `registry`, `mutexes`, `dns`, `http`, `tcp_udp`
   - `dropped_files`, `screenshots`, `pcap`, `memory_dump`, `iocs`, `errors`, `raw_report_ref`
5. Prevent long-running detonation from blocking the original static worker.
6. Add retry, timeout, circuit breaker, and provider-unavailable fallback.
7. Add unit and integration coverage for registry resolution, provider normalization, deferred execution, and backward-compatible report shaping.

## Non-Goals

1. No database migration unless absolutely necessary.
2. No deep CAPE artifact mirroring into MinIO in this phase. We keep remote metadata and download references.
3. No change to top-level report endpoint shape beyond additive fields.
4. No new backend endpoint just for sandbox.

## Approaches Compared

### A. Synchronous sandbox wait inside the existing worker

The current worker would submit to CAPE and block until detonation finished.

Pros:

1. Smallest code path.
2. No new queue or worker role.

Cons:

1. Long detonation holds the same worker slot that currently runs static analysis.
2. Queue latency for all samples becomes coupled to CAPE latency.
3. Retry and timeout behavior for static work and dynamic work are forced into one failure domain.
4. CAPE brownouts can starve the primary worker fleet.

### B. Dedicated sandbox queue and worker pool with report backfill

The static worker stores a partial report after static stages, publishes a sandbox follow-up message to a dedicated queue, and leaves the job in `scanning/current_stage=sandbox_pending`. A dedicated sandbox worker performs detonation, normalizes the result, rewrites `results.sandbox`, recomputes direct risk, and then marks the job `done`.

Pros:

1. Long detonation no longer blocks static throughput.
2. CAPE failures and retries are isolated to the sandbox worker pool.
3. Existing job/result schema is still usable because the same job record is finalized later.
4. A `mock` fallback can still finalize the report when CAPE is unavailable.

Cons:

1. Slightly more orchestration code.
2. Requires a second worker service and queue declaration.

## Recommendation

Use **Approach B**.

It is the smallest architecture that preserves static throughput and still fits the existing system: RabbitMQ already exists, job progress already exists, backend already waits for `job.status == done`, and the report schema is already additive. We can implement this without a migration by reusing the current `jobs.result`, `jobs.current_stage`, and `jobs.status` fields.

## Architecture

### 1. Worker roles

1. The existing worker keeps consuming `malscan.jobs`.
2. A new sandbox worker consumes `malscan.jobs.sandbox`.
3. Both use the same image; the sandbox worker starts a dedicated entrypoint that reuses the existing RabbitMQ consumer plumbing with a sandbox-specific message handler.

### 2. Static pipeline flow

1. Run existing static stages as today.
2. `SandboxStage` in the static worker does not detonate. It either:
   - publishes a sandbox follow-up message and returns a deferred placeholder, or
   - falls back to inline `mock` findings if sandbox dispatch itself fails.
3. If sandbox work was deferred, `run_pipeline(...)` stores a partial report, recomputes risk without dynamic evidence, updates artifact risk, and leaves the job in:
   - `status = scanning`
   - `current_stage = sandbox_pending`
   - `stages_done = stages_total - 1`
4. The static worker acknowledges the message and becomes free immediately.

### 3. Sandbox worker flow

1. Consume the deferred sandbox message.
2. Download the same sample from MinIO.
3. Resolve provider from the registry using `SANDBOX_PROVIDER`.
4. Execute provider calls with retry and timeout.
5. If the provider is unavailable or the circuit is open, fall back to `mock`.
6. Load the partial report from `jobs.result`, replace `results.sandbox`, replace the sandbox timing entry, recompute direct risk, update artifact risk, and mark the job `done`.

### 4. Provider abstraction

The provider contract exposes:

1. `submit_file(...)`
2. `submit_url(...)`
3. `poll_task(...)`
4. `fetch_report(...)`
5. `fetch_artifact_metadata(...)`
6. `analyze_*()` convenience helpers that return one normalized result object

The default registry contains:

1. `mock`
2. `capev2`

### 5. CAPEv2 integration

Supported endpoints:

1. `POST /apiv2/tasks/create/file/`
2. `POST /apiv2/tasks/create/url/`
3. `GET /apiv2/tasks/view/<task_id>/`
4. `GET /apiv2/tasks/report/<task_id>/?format=json`
5. `GET /apiv2/tasks/screenshots/<task_id>/`
6. `GET /apiv2/pcap/get/<task_id>/`

Authentication uses `Authorization: Token <SANDBOX_API_TOKEN>` when provided.

### 6. Normalization rules

`results.sandbox` remains backward compatible by preserving:

1. `behaviors`
2. `network_connections`
3. `is_mock`

New additive fields are mapped like this:

1. `processes`: process tree summary from `behavior.processes`
2. `files`: summary from `behavior.summary.files` and dropped file metadata
3. `registry`: summary from `behavior.summary.registry` and signature details
4. `mutexes`: summary from `behavior.summary.mutexes`
5. `dns`, `http`, `tcp_udp`: normalized from `network.*`
6. `dropped_files`: file metadata plus download refs from the report endpoint
7. `screenshots`: screenshot refs from CAPE screenshot endpoint
8. `pcap`: metadata plus download ref to the PCAP endpoint when available
9. `memory_dump`: best-effort metadata from report/procmemory when present
10. `iocs`: additive IOC rollup derived from DNS, HTTP, TCP/UDP, and dropped files
11. `errors`: provider and fallback diagnostics
12. `raw_report_ref`: URL to the raw CAPE JSON report endpoint

`verdict_hint` is derived from high-confidence CAPE signatures and used as a human-facing summary only. Scoring remains evidence-driven through the legacy-compatible `behaviors` field so existing backend risk logic continues to work.

### 7. Reliability controls

1. HTTP calls use bounded retries.
2. Polling is bounded by `SANDBOX_TIMEOUT_SECONDS`.
3. A per-process circuit breaker opens after repeated provider failures.
4. When the configured provider cannot be used, the registry falls back to `mock` and records the reason in `results.sandbox.errors`.

## Data Flow

1. Upload API creates a normal job in `jobs`.
2. Static worker consumes `malscan.jobs` and stores a partial report.
3. Static worker publishes the same job context to `malscan.jobs.sandbox`.
4. Sandbox worker consumes `malscan.jobs.sandbox`.
5. Sandbox worker rewrites `jobs.result.results.sandbox` and final risk fields.
6. Backend serves the same report contract after `job.status == done`.

## Files To Change

### Worker

1. `worker/src/malscan_worker/stages/sandbox.py`
2. `worker/src/malscan_worker/pipeline.py`
3. `worker/src/malscan_worker/config.py`
4. `worker/src/malscan_worker/consumer.py`
5. `worker/src/malscan_worker/main.py`
6. `worker/src/malscan_worker/reporting.py`
7. `worker/src/malscan_worker/storage.py` if small helper reuse is needed
8. New `worker/src/malscan_worker/sandbox/*.py`
9. New `worker/src/malscan_worker/sandbox_main.py`
10. Worker tests covering provider normalization and deferred execution

### Backend

1. `backend/src/malscan/schemas/requests.py`
2. `backend/src/malscan/scoring/adapters.py`
3. `backend/src/malscan/api/routes.py`
4. Backend tests covering additive schema and scoring compatibility

### Frontend / Ops / Docs

1. `frontend/src/api/types.ts`
2. `frontend/src/pages/ReportPage.tsx`
3. `frontend/src/pages/JobStatusPage.tsx`
4. `frontend/src/components/report/reportText.ts`
5. `docker-compose.yml`
6. `README.md`
7. `worker/README.md`

## Migration Impact

1. **Database migration:** none required.
2. **Queue topology:** one additive queue, `malscan.jobs.sandbox`.
3. **Deployment:** one additive worker service, `sandbox-worker`.
4. **Environment:** add the requested sandbox provider env vars and one queue name env var for the dedicated sandbox queue.

## Compatibility Risks

1. Existing clients that only read `behaviors`, `network_connections`, and `is_mock` continue to work.
2. Existing backend scoring continues to work because normalized results preserve the legacy-compatible sandbox shape.
3. Job progress percentages change because `stages_total` is corrected to include the true pipeline stage count.
4. During deferred sandbox execution the job remains `scanning`, so clients that assumed every worker ack implies `done` would be wrong. The current frontend already polls job status and is compatible with this model after adding a `sandbox_pending` label.

## Testing Strategy

1. Unit-test provider registry resolution and fallback.
2. Unit-test `mock` normalization.
3. Unit-test CAPEv2 normalization from representative JSON payloads.
4. Integration-test static pipeline deferral and sandbox worker finalization.
5. Regression-test backend schema compatibility and scoring on normalized sandbox results.
