# Dynamic Sandbox Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add provider-backed dynamic sandbox analysis with a dedicated sandbox queue/worker, CAPEv2 normalization, and additive backward-compatible report/schema updates without blocking the static worker.

**Architecture:** Keep the existing static worker focused on static/recursive analysis. Let `SandboxStage` defer detonation work to a dedicated queue, then have a sandbox worker finalize the same job by normalizing provider output back into `results.sandbox`, recomputing direct risk, and marking the job `done`. Preserve legacy sandbox compatibility fields while adding the richer normalized schema.

**Tech Stack:** Python 3.11, aio-pika, aiohttp, FastAPI, SQLAlchemy, existing scoring/report pipeline, React/TypeScript frontend, Docker Compose

**Spec:** `docs/superpowers/specs/2026-04-17-dynamic-sandbox-integration-design.md`

---

## File Structure

### New files

1. `worker/src/malscan_worker/sandbox/__init__.py` — sandbox package exports
2. `worker/src/malscan_worker/sandbox/providers.py` — provider models, registry, mock and CAPEv2 providers, circuit breaker
3. `worker/src/malscan_worker/sandbox/publisher.py` — cached RabbitMQ publisher for deferred sandbox jobs
4. `worker/src/malscan_worker/sandbox_main.py` — sandbox worker entrypoint
5. `worker/tests/test_sandbox_stage.py` — stage/registry/provider normalization tests

### Modified files

1. `worker/src/malscan_worker/stages/sandbox.py` — defer-or-fallback orchestration and final sandbox execution helpers
2. `worker/src/malscan_worker/pipeline.py` — partial report storage, sandbox finalization, stage count correction
3. `worker/src/malscan_worker/config.py` — sandbox env vars and queue defaults
4. `worker/src/malscan_worker/consumer.py` — pluggable message handler and sandbox consumer path
5. `worker/src/malscan_worker/main.py` — initialize shared publishers
6. `worker/src/malscan_worker/reporting.py` — richer empty sandbox defaults
7. `backend/src/malscan/schemas/requests.py` — additive sandbox models
8. `backend/src/malscan/scoring/adapters.py` — scoring compatibility with normalized sandbox payloads
9. `backend/src/malscan/config.py` — correct `stages_total`
10. `backend/tests/test_scoring_adapters.py` — normalized sandbox evidence tests
11. `backend/tests/test_api.py` — sandbox schema compatibility tests
12. `frontend/src/api/types.ts` — additive sandbox contract typing
13. `frontend/src/pages/JobStatusPage.tsx` — `sandbox_pending` label
14. `frontend/src/pages/ReportPage.tsx` — updated mock notice behavior
15. `frontend/src/components/report/reportText.ts` — localized sandbox labels
16. `docker-compose.yml` — dedicated sandbox worker service and env wiring
17. `README.md` — architecture, env, queue, fallback, and deployment notes
18. `worker/README.md` — worker role split and sandbox provider notes

---

### Task 1: Add failing tests for sandbox provider normalization and deferred execution

**Files:**
- Create: `worker/tests/test_sandbox_stage.py`
- Modify: `worker/tests/test_pipeline.py`
- Modify: `backend/tests/test_scoring_adapters.py`
- Modify: `backend/tests/test_api.py`

- [ ] Write tests that assert registry resolution, mock normalization, CAPEv2 normalization, deferred static pipeline behavior, sandbox finalization, and backend schema compatibility.
- [ ] Run the focused tests and confirm they fail for the expected reasons.

### Task 2: Implement provider abstraction, CAPEv2 support, retries, circuit breaker, and fallback

**Files:**
- Create: `worker/src/malscan_worker/sandbox/__init__.py`
- Create: `worker/src/malscan_worker/sandbox/providers.py`
- Modify: `worker/src/malscan_worker/config.py`
- Modify: `worker/src/malscan_worker/stages/sandbox.py`

- [ ] Add normalized sandbox result helpers and empty/default payload builders.
- [ ] Add `SandboxProvider` abstraction, registry, `mock`, and `capev2` providers.
- [ ] Add CAPEv2 file/url submission, polling, report fetch, screenshot/pcap metadata fetch, and best-effort memory dump metadata.
- [ ] Add retry, timeout, circuit breaker, and mock fallback.
- [ ] Re-run the focused provider tests until green.

### Task 3: Implement dedicated queue / worker finalization path

**Files:**
- Create: `worker/src/malscan_worker/sandbox/publisher.py`
- Create: `worker/src/malscan_worker/sandbox_main.py`
- Modify: `worker/src/malscan_worker/pipeline.py`
- Modify: `worker/src/malscan_worker/consumer.py`
- Modify: `worker/src/malscan_worker/main.py`
- Modify: `worker/src/malscan_worker/reporting.py`

- [ ] Publish deferred sandbox messages to the dedicated queue.
- [ ] Store partial reports and leave jobs in `scanning/current_stage=sandbox_pending`.
- [ ] Add sandbox worker consumption and finalization that patches `results.sandbox`, timings, risk, and artifact risk.
- [ ] Re-run worker pipeline/consumer tests until green.

### Task 4: Update backend and frontend compatibility layers

**Files:**
- Modify: `backend/src/malscan/schemas/requests.py`
- Modify: `backend/src/malscan/scoring/adapters.py`
- Modify: `backend/src/malscan/config.py`
- Modify: `frontend/src/api/types.ts`
- Modify: `frontend/src/pages/JobStatusPage.tsx`
- Modify: `frontend/src/pages/ReportPage.tsx`
- Modify: `frontend/src/components/report/reportText.ts`

- [ ] Extend backend schema models with additive sandbox fields while preserving legacy ones.
- [ ] Keep scoring compatible with both old and new sandbox payloads.
- [ ] Add `sandbox_pending` stage labels and richer sandbox typing in the frontend.
- [ ] Re-run backend compatibility tests until green.

### Task 5: Update deployment docs, compose, and verify end-to-end

**Files:**
- Modify: `docker-compose.yml`
- Modify: `README.md`
- Modify: `worker/README.md`

- [ ] Add a `sandbox-worker` service with its own queue.
- [ ] Document `SANDBOX_PROVIDER`, `SANDBOX_BASE_URL`, `SANDBOX_API_TOKEN`, `SANDBOX_TIMEOUT_SECONDS`, `SANDBOX_POLL_INTERVAL_SECONDS`, `SANDBOX_ENABLE_URL_SUBMISSION`, and the dedicated queue behavior.
- [ ] Run focused verification commands for worker tests and backend tests.
- [ ] Run code review, then commit, push, create PR, and merge.
