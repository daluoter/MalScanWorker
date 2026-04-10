---
status: investigating
trigger: "Password input prompt never appears for password-protected archives on the job status page"
created: 2026-03-31T00:00:00Z
updated: 2026-03-31T00:00:00Z
---

## Current Focus

hypothesis: WrongPasswordError is swallowed by _run_stage's catch-all Exception handler in pipeline.py, so it never propagates to consumer.py which handles it with password_required transition. The pipeline completes with "done" status instead.
test: Trace the exception propagation path from archive_extract -> _run_stage -> run_pipeline -> consumer
expecting: _run_stage catches WrongPasswordError as a generic Exception and converts it to a StageResult, preventing the consumer from ever transitioning to password_required
next_action: Confirm by reading exact code path

## Symptoms

expected: When a password-protected archive is uploaded, backend detects it needs a password, sets job status to password_required, SSE emits password_required, and frontend shows PasswordForm component
actual: The analysis completes without ever showing the password entry UI — the job goes straight to done
errors: None visible — the job silently completes
reproduction: Upload a password-protected archive
started: Unknown — may have always been broken for the initial password detection flow

## Eliminated

## Evidence

- timestamp: 2026-03-31T00:01:00Z
  checked: Frontend JobStatusPage.tsx render logic (line 177)
  found: Correctly checks `job.status === 'password_required' && !passwordAccepted` to render PasswordForm
  implication: Frontend rendering logic is correct — bug must be in status never reaching password_required

- timestamp: 2026-03-31T00:01:30Z
  checked: Frontend types.ts (line 1)
  found: JobStatusValue type includes 'password_required' — type definitions are correct
  implication: No type-level issue

- timestamp: 2026-03-31T00:02:00Z
  checked: Frontend SSE handler (lines 36-64)
  found: SSE handler correctly parses data, checks `data.status === 'password_required'` (line 41), and updates state
  implication: SSE handler is correct — if backend sent password_required, frontend would show the form

- timestamp: 2026-03-31T00:02:30Z
  checked: Backend SSE stream endpoint (routes.py lines 338-421)
  found: Polls DB every 1s, emits job status. Terminates only on 'done' or 'failed'. Would correctly stream 'password_required' if DB had that status.
  implication: SSE streaming is correct

- timestamp: 2026-03-31T00:03:00Z
  checked: Worker consumer.py (lines 119-134)
  found: consumer calls `run_pipeline(body)` and catches `WrongPasswordError` to transition to password_required. BUT the pipeline's _run_stage() function catches ALL exceptions including WrongPasswordError.
  implication: CRITICAL — WrongPasswordError raised in archive_extract stage is caught by _run_stage's catch-all handler (pipeline.py:190), converted to a StageResult with status="failed", and the pipeline continues to completion with "done" status

- timestamp: 2026-03-31T00:03:30Z
  checked: Pipeline _run_stage function (pipeline.py lines 146-202)
  found: `except Exception as e:` on line 190 catches ALL exceptions from stages, including WrongPasswordError, and returns a StageResult. The exception NEVER propagates to consumer.py.
  implication: This is the ROOT CAUSE. The consumer's `except WrongPasswordError:` handler (consumer.py:127) is dead code — it can never be reached because _run_stage swallows the exception.

- timestamp: 2026-03-31T00:04:00Z
  checked: Pipeline run_pipeline function (pipeline.py lines 278-283)
  found: Sequential stages (including ArchiveExtractStage) are run via _run_stage, which catches exceptions. After all stages complete, pipeline unconditionally sets status to "done" (line 309-314).
  implication: Confirms that password_required status is never set — the job goes queued -> scanning -> done, skipping password_required entirely

## Resolution

root_cause: In `worker/src/malscan_worker/pipeline.py`, the `_run_stage()` function (line 190) has a catch-all `except Exception as e:` that catches `WrongPasswordError` from the archive extraction stage. This converts the error into a `StageResult(status="failed")` and returns it, preventing the exception from propagating up to `consumer.py`'s `except WrongPasswordError:` handler (line 127). Since the pipeline continues to completion and sets the job status to "done", the job NEVER transitions to `password_required`, and the frontend SSE stream never receives that status, so the PasswordForm is never rendered.
fix:
verification:
files_changed: []
