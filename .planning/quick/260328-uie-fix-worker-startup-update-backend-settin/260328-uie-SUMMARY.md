---
phase: quick
plan: 260328-uie
subsystem: backend-config, documentation
tags: [bugfix, settings, worker, readme]
dependency_graph:
  requires: []
  provides: [worker-starts-cleanly, correct-readme-commands]
  affects: [backend/src/malscan/config.py, README.md, README.en.md]
tech_stack:
  added: []
  patterns: [explicit-optional-fields-over-extra-ignore]
key_files:
  created: []
  modified:
    - backend/src/malscan/config.py
    - README.md
    - README.en.md
decisions:
  - Used explicit fields with defaults instead of ConfigDict(extra="ignore") to catch env var typos
metrics:
  duration: 59s
  completed: "2026-03-28T14:02:47Z"
  tasks_completed: 2
  tasks_total: 2
---

# Quick Task 260328-uie: Fix Worker Startup & Update Backend Settings Summary

**One-liner:** Added clamav_host/clamav_port/sandbox_mock fields to shared Settings model so worker doesn't crash on startup; fixed README ingest command from cmd/server to cmd/ingest.

## What Changed

### Task 1: Add clamav/sandbox fields to backend Settings model
- **Commit:** b91ab69
- **Files:** `backend/src/malscan/config.py`
- Added `clamav_host: str = "localhost"`, `clamav_port: int = 3310`, `sandbox_mock: bool = False` to the `Settings` class
- These fields accept the worker-specific env vars (CLAMAV_HOST, CLAMAV_PORT, SANDBOX_MOCK) that were previously rejected as "extra inputs not permitted" by pydantic-settings
- Fields use safe defaults since the backend itself doesn't use them

### Task 2: Fix ingest startup command in READMEs
- **Commit:** 008ff52
- **Files:** `README.md`, `README.en.md`
- Changed `go run ./cmd/server` to `go run ./cmd/ingest` in both READMEs
- The actual Go entrypoint is `ingest/cmd/ingest/main.go`; `cmd/server` never existed

## Verification Results

1. `get_settings()` loads successfully with clamav env vars, prints "OK localhost"
2. `grep -r "cmd/server" README.md README.en.md` returns no matches (exit 1)
3. `grep "cmd/ingest" README.md README.en.md` returns matches in both files at line 331

## Deviations from Plan

None - plan executed exactly as written.

## Known Stubs

None.

## Self-Check: PASSED

- [x] `backend/src/malscan/config.py` — FOUND, contains `clamav_host`
- [x] `README.md` — FOUND, contains `cmd/ingest`
- [x] `README.en.md` — FOUND, contains `cmd/ingest`
- [x] Commit b91ab69 — verified
- [x] Commit 008ff52 — verified
