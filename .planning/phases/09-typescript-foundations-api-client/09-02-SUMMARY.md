---
phase: 09-typescript-foundations-api-client
plan: 02
subsystem: api-client
tags: [api-client, password, security, eslint, no-console, error-handling, PWI-06, SEC-01, SEC-03]

# Dependency graph
requires:
  - phase: 09-typescript-foundations-api-client
    plan: 01
    provides: "types.ts with JobStatusValue, client.ts with re-exports"
provides:
  - "apiClient.submitPassword(jobId, password) method sending POST /api/v1/jobs/{id}/password"
  - "PasswordSubmitResponse interface with attempts_used and attempts_remaining"
  - "ApiRequestError class extending Error with code, statusCode, details"
  - "ESLint no-console rule blocking console.log/debug/info"
affects: [frontend-api, security, error-handling]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "ApiRequestError class for structured error handling with error codes from backend"
    - "ESLint no-console as compile-time security gate against password leakage"
    - "Password only in POST JSON body, never in URL parameters"

key-files:
  modified:
    - frontend/src/api/types.ts
    - frontend/src/api/client.ts
    - frontend/.eslintrc.cjs

key-decisions:
  - "ApiRequestError extends Error for instanceof checking — only used in new submitPassword method, not retrofitted to existing methods"
  - "Network errors (fetch throws) get code 'NETWORK_ERROR' with statusCode 0"
  - "ESLint allow list: console.warn and console.error permitted, console.log/debug/info blocked"
  - "encodeURIComponent(jobId) in URL for safety, though jobId is always a UUID"

patterns-established:
  - "ApiRequestError for structured error propagation from API client to UI components"
  - "Error code extraction from FastAPI error shape: errorData?.detail?.error || errorData?.error"

requirements-completed: [PWI-06, SEC-01, SEC-03]

# Metrics
duration: ~10min
completed: 2026-03-31
---

# Phase 09 Plan 02: API Client Method & Security Summary

**Added submitPassword() API method with typed PasswordSubmitResponse and ApiRequestError for structured error handling. ESLint no-console rule blocks console.log/debug/info as compile-time security gate (SEC-01). Password value only in POST body, never in URLs (SEC-03).**

## What Was Done

### Task 1: Add PasswordSubmitResponse type and ApiRequestError class

Added to `frontend/src/api/types.ts`:

- **PasswordSubmitResponse** interface: `job_id`, `status`, `message`, `attempts_used`, `attempts_remaining` — matches backend `POST /api/v1/jobs/{id}/password` 200 response shape
- **ApiRequestError** class extending `Error`:
  - `readonly code: string` — backend error code (e.g., `EMPTY_PASSWORD`, `MAX_ATTEMPTS_EXCEEDED`)
  - `readonly statusCode: number` — HTTP status (400/404/409/429, or 0 for network errors)
  - `readonly details: Record<string, unknown>` — optional structured error details
  - `name` set to `'ApiRequestError'` for error identification
  - instanceof-checkable: `err instanceof ApiRequestError` returns true

Both are re-exported from `client.ts` via the existing `export * from './types'`.

### Task 2: Add submitPassword() method to ApiClient

Added `submitPassword(jobId: string, password: string): Promise<PasswordSubmitResponse>` to the `ApiClient` class in `client.ts`:

- **Request**: POST to `/api/v1/jobs/{encodeURIComponent(jobId)}/password` with `Content-Type: application/json` and body `{"password": "..."}` — password is ONLY in the JSON body, never in URL
- **Success (200)**: Returns typed `PasswordSubmitResponse` with attempt counts
- **HTTP errors (400/404/409/429)**: Throws `ApiRequestError` with `code` extracted from backend error response (`errorData?.detail?.error` or `errorData?.error`)
- **Network errors**: Throws `ApiRequestError` with code `'NETWORK_ERROR'` and statusCode `0`
- **Non-JSON error responses**: Falls back to default message `'密碼提交失敗'` and code `'UNKNOWN_ERROR'`
- **Security**: No console logging anywhere in the method, password never in URL

Updated import at top of client.ts: added `PasswordSubmitResponse` to type import, added separate value import for `ApiRequestError` class.

### Task 3: Add ESLint no-console rule for security

Added to `frontend/.eslintrc.cjs` rules:

```javascript
'no-console': ['error', { allow: ['warn', 'error'] }],
```

- **Blocked**: `console.log()`, `console.debug()`, `console.info()` — all trigger ESLint error
- **Allowed**: `console.warn()`, `console.error()` — needed for legitimate error logging
- **Existing code**: `console.error('Failed to copy')` in `ReportPage.tsx:35` passes (in allow list)

## Deviations from Plan

None.

## Verification Results

| Check | Result |
|-------|--------|
| `npx tsc --noEmit` | Compiles without errors |
| `npx eslint src/ --max-warnings 0` | Passes with no-console rule active |
| `console.log/debug/info` in src/ | Zero matches |
| `submitPassword` in client.ts | Method exists at line 93 |
| `ApiRequestError` in types.ts | Class defined at line 127 |
| `PasswordSubmitResponse` in types.ts | Interface defined at line 118 |
| `console` in api/ directory | Zero matches (no console usage) |
| `password` in client.ts | Only in method signature, URL path segment `/password`, and JSON body |

## Known Stubs

None — submitPassword() is fully implemented and ready for Phase 10 UI integration.

## Self-Check: PASSED

- All 3 key files: FOUND
- PasswordSubmitResponse interface: DEFINED
- ApiRequestError class: DEFINED with code, statusCode, details
- submitPassword method: IMPLEMENTED with POST body, error handling
- ESLint no-console rule: ACTIVE, existing code passes
- Password never in URL: VERIFIED
- TypeScript + ESLint clean: YES
