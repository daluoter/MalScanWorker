# Phase 4: API Contract & Production Readiness - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-03-27
**Phase:** 04-api-contract-production-readiness
**Areas discussed:** Response format compliance, CORS middleware setup, Graceful shutdown behavior, Error response audit

---

## Response format compliance

### Timestamp format

| Option | Description | Selected |
|--------|-------------|----------|
| Match Python exactly | Use time.RFC3339Nano for microsecond precision + offset like '2026-03-27T13:54:44.123456+00:00' | |
| RFC3339 is close enough | Keep time.RFC3339 ('2026-03-27T13:54:44Z') — both valid ISO 8601 | |
| You decide | Let the agent figure out the best approach | ✓ |

**User's choice:** You decide
**Notes:** Agent discretion on timestamp format — match Python output as closely as reasonable

### Response field set

| Option | Description | Selected |
|--------|-------------|----------|
| Current fields are correct | Go response has exactly the 5 fields Python UploadResponse defines — no changes needed | ✓ |
| Add data envelope | Wrap in a data envelope like {'data': {...}} for consistency | |

**User's choice:** Current fields are correct
**Notes:** None

### Response struct type

| Option | Description | Selected |
|--------|-------------|----------|
| Typed response struct | Define UploadResponse struct with json tags for compile-time safety | ✓ |
| Keep map[string]any | Keep current map[string]any approach — simpler, fewer lines | |

**User's choice:** Typed response struct
**Notes:** Replace map[string]any with typed struct for compiler-checked field names

---

## CORS middleware setup

### CORS scope

| Option | Description | Selected |
|--------|-------------|----------|
| Mirror Python exactly | go-chi/cors with same settings: origins from env, credentials=false, all methods, all headers, 600s max-age | ✓ |
| Restrict to used methods | Only allow GET, POST, OPTIONS — the ingest service only serves health + upload | |
| You decide | Let the agent match Python's behavior | |

**User's choice:** Mirror Python exactly
**Notes:** Even though Go only serves GET and POST, mirror Python's broad CORS for consistency

### CORS library

| Option | Description | Selected |
|--------|-------------|----------|
| go-chi/cors | Same ecosystem as router, well-maintained, trivial integration | ✓ |
| rs/cors | Standalone, more popular, works with any mux | |
| You decide | Let the agent pick | |

**User's choice:** go-chi/cors
**Notes:** None

---

## Graceful shutdown behavior

### Shutdown timeout

| Option | Description | Selected |
|--------|-------------|----------|
| Configurable via env | SHUTDOWN_TIMEOUT env var with default 30s — K8s terminationGracePeriodSeconds can match | ✓ |
| Hardcoded 30s | Simpler, one fewer config option | |
| You decide | Let the agent decide | |

**User's choice:** Configurable via env
**Notes:** None

### In-flight upload handling

| Option | Description | Selected |
|--------|-------------|----------|
| Let http.Server.Shutdown drain | srv.Shutdown() stops listener, waits for active requests within timeout, then defers close backends | ✓ |
| WaitGroup tracking | Explicit tracking of in-flight upload goroutines for more control | |
| You decide | Let the agent decide | |

**User's choice:** Let http.Server.Shutdown drain
**Notes:** Go's built-in Shutdown() is sufficient — no need for explicit WaitGroup

### Backend cleanup order

| Option | Description | Selected |
|--------|-------------|----------|
| Keep defer-based cleanup | Current defer order works correctly after srv.Shutdown() blocks | ✓ |
| Explicit ordered cleanup | Explicitly close in order with logging for each step | |
| You decide | Let the agent decide | |

**User's choice:** Keep defer-based cleanup
**Notes:** None

---

## Error response audit

### Error code alignment

| Option | Description | Selected |
|--------|-------------|----------|
| Match Python codes exactly | Read Python code to find exact error codes and align | ✓ |
| Current codes are fine | Frontend checks message text, not error codes | |
| You decide | Let the agent audit and fix | |

**User's choice:** Match Python codes exactly
**Notes:** None

### MaxBytesReader error handling

| Option | Description | Selected |
|--------|-------------|----------|
| Clean JSON for oversized | Catch MaxBytesError and return clean JSON 400 with FILE_TOO_LARGE code | ✓ |
| Raw error is fine | Let raw Go error propagate — edge case | |
| You decide | Let the agent handle it | |

**User's choice:** Clean JSON for oversized
**Notes:** None

---

## Agent's Discretion

- Exact timestamp format (RFC3339Nano vs custom)
- Error code string value alignment (agent will audit Python source)
- CORS middleware placement in chain
- Shutdown logging for backend close steps

## Deferred Ideas

None — discussion stayed within phase scope
