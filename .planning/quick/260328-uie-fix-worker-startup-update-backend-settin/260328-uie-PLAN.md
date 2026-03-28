---
phase: quick
plan: 260328-uie
type: execute
wave: 1
depends_on: []
files_modified:
  - backend/src/malscan/config.py
  - README.md
  - README.en.md
autonomous: true
requirements: []
must_haves:
  truths:
    - "Worker starts without Settings validation errors when CLAMAV_HOST, CLAMAV_PORT, SANDBOX_MOCK env vars are present"
    - "README ingest startup command works: `cd ingest && go run ./cmd/ingest`"
  artifacts:
    - path: "backend/src/malscan/config.py"
      provides: "Settings model with clamav/sandbox fields"
      contains: "clamav_host"
    - path: "README.md"
      provides: "Correct ingest startup command"
      contains: "cmd/ingest"
    - path: "README.en.md"
      provides: "Correct ingest startup command (English)"
      contains: "cmd/ingest"
  key_links:
    - from: "worker/.env"
      to: "backend/src/malscan/config.py"
      via: "pydantic-settings env var loading"
      pattern: "clamav_host.*clamav_port.*sandbox_mock"
---

<objective>
Fix two worker/ingest startup failures found during local testing.

Purpose: The worker cannot start because the backend's shared `Settings` model rejects clamav/sandbox env vars as "extra inputs not permitted." The ingest README command points to a non-existent `cmd/server` directory instead of the actual `cmd/ingest`.

Output: Worker starts cleanly with clamav env vars; README commands are correct.
</objective>

<execution_context>
@$HOME/.config/opencode/get-shit-done/workflows/execute-plan.md
@$HOME/.config/opencode/get-shit-done/templates/summary.md
</execution_context>

<context>
@backend/src/malscan/config.py
@worker/.env
@ingest/cmd/ingest/main.go
@README.md (lines 328-332)
@README.en.md (lines 328-332)
</context>

<tasks>

<task type="auto">
  <name>Task 1: Add clamav/sandbox fields to backend Settings model</name>
  <files>backend/src/malscan/config.py</files>
  <action>
Add three fields to the `Settings` class in `backend/src/malscan/config.py` to accept the worker-specific environment variables that are present in `worker/.env` and the root `.env`:

```python
# ClamAV (worker-specific, optional for backend)
clamav_host: str = "localhost"
clamav_port: int = 3310

# Sandbox (worker-specific, optional for backend)
sandbox_mock: bool = False
```

Add these fields AFTER the existing `stages_total` field and BEFORE the `class Config` block. These are optional with sensible defaults because the backend itself doesn't use them — they exist so the shared `Settings` model doesn't reject env vars that the worker needs.

Do NOT use `model_config = ConfigDict(extra="ignore")` — that would silently swallow typos in env var names. Explicit fields are safer.
  </action>
  <verify>
    <automated>cd /home/daluoter/projects/MalScanWorker/worker && poetry run python -c "from malscan.config import Settings; s = Settings(); print(f'clamav_host={s.clamav_host} clamav_port={s.clamav_port} sandbox_mock={s.sandbox_mock}')"</automated>
  </verify>
  <done>Settings() loads without "extra inputs not permitted" errors when CLAMAV_HOST, CLAMAV_PORT, SANDBOX_MOCK env vars are present. Worker can import malscan.config and malscan.storage without crashing.</done>
</task>

<task type="auto">
  <name>Task 2: Fix ingest startup command in READMEs</name>
  <files>README.md, README.en.md</files>
  <action>
In both `README.md` and `README.en.md`, fix the incorrect ingest startup command.

Change `go run ./cmd/server` to `go run ./cmd/ingest` in the "啟動 Ingest 服務" / "Start the Ingest Service" section (line 331 in both files).

The actual Go entrypoint is `ingest/cmd/ingest/main.go`, not `cmd/server` which does not exist.
  </action>
  <verify>
    <automated>grep -n "cmd/server" README.md README.en.md; echo "EXIT:$?"; grep -n "cmd/ingest" README.md README.en.md</automated>
  </verify>
  <done>`cmd/server` no longer appears in either README. Both show `go run ./cmd/ingest` as the ingest startup command.</done>
</task>

</tasks>

<verification>
1. `cd worker && poetry run python -c "from malscan.config import get_settings; s = get_settings(); print('OK', s.clamav_host)"` — prints "OK localhost" (or configured value)
2. `grep -r "cmd/server" README.md README.en.md` — returns no matches
3. `grep "cmd/ingest" README.md README.en.md` — returns matches in both files
</verification>

<success_criteria>
- Worker startup no longer fails on Settings validation for clamav/sandbox env vars
- Both READMEs reference the correct `go run ./cmd/ingest` command
- No regressions in backend startup (Settings still validates required fields)
</success_criteria>

<output>
After completion, create `.planning/quick/260328-uie-fix-worker-startup-update-backend-settin/260328-uie-SUMMARY.md`
</output>
