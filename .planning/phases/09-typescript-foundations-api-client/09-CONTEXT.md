# Phase 9: TypeScript Foundations & API Client - Context

**Gathered:** 2026-03-31
**Status:** Ready for planning

<domain>
## Phase Boundary

TypeScript type system recognizes `password_required` as a first-class job status, the API client can submit passwords, and security invariants are established at the transport layer. This is a foundation phase — no UI changes, no SSE handler changes, no component rendering. Types, maps, API method, error class, and lint rules only.

**Requirements:** SDT-03, PWI-06, SEC-01, SEC-03

**Success criteria:**
1. `password_required` appears in the `JobStatus` type union with a distinct label and color in status display maps — TypeScript compiler catches any unhandled branches
2. Calling `apiClient.submitPassword(jobId, password)` sends a POST to `/api/v1/jobs/{id}/password` and returns a typed response with attempt count and error details
3. Password value never appears in `console.log`, URL parameters, query strings, or browser history — verified by grep across all new code
4. API error responses (400, 404, 409, 429) are parsed into typed error objects usable by downstream UI components

</domain>

<decisions>
## Implementation Decisions

### Type system pattern (SDT-03)
- **D-01:** Extract a **named type alias** `JobStatusValue = 'queued' | 'scanning' | 'done' | 'failed' | 'password_required'` instead of keeping the union inline. This enables typed `Record<JobStatusValue, string>` keys for exhaustiveness checking at compile time.
- **D-02:** All types move to a **separate `src/api/types.ts`** file. `client.ts` imports from `types.ts` and only contains the `ApiClient` class + singleton export. This keeps types importable independently of the client instance.
- **D-03:** Status display maps (labels, colors) move to a **shared `src/constants/status.ts`** file that both `JobStatusPage.tsx` and `ReportPage.tsx` import. Eliminates the current duplication of inline `Record<string, string>` maps. Map keys are typed as `Record<JobStatusValue, string>` for exhaustiveness.

### Status display values (SDT-03)
- **D-04:** `password_required` label: **`需要密碼`** (Traditional Chinese, matches existing pattern: 排隊中, 分析中, 完成, 失敗).
- **D-05:** `password_required` color: **`text-caution-yellow`** (amber/gold, `#eab308`). Already exists in `tailwind.config.js` as `caution-yellow`. Distinct from scanning (cyan), done (green), failed (red), queued (slate). Signals "action needed" without implying error.

### API client design (PWI-06)
- **D-07:** Add `submitPassword(jobId: string, password: string): Promise<PasswordSubmitResponse>` to `ApiClient`. Uses `POST /api/v1/jobs/{id}/password` with JSON body `{"password": "..."}`. Returns typed `PasswordSubmitResponse` on success (2xx).
- **D-08:** On HTTP errors (400, 404, 409, 429), throw an **`ApiRequestError` class** extending `Error`. This class carries `code: string` (e.g., `"MAX_ATTEMPTS_EXCEEDED"`), `statusCode: number`, and `details: Record<string, unknown>`. Callers can `instanceof ApiRequestError` for structured data while still catching generic errors.
- **D-09:** `ApiRequestError` is a **new class** used only in `submitPassword()` for Phase 9. Existing methods (`uploadFile`, `getJobStatus`, `getReport`) continue using `throw new Error(string)`. Refactoring existing methods is **out of scope** — consistency can be improved in a future pass.
- **D-10:** Response type `PasswordSubmitResponse` includes: `job_id: string`, `status: string`, `message: string`, `attempts_used: number`, `attempts_remaining: number`. Matches the backend response at `backend/src/malscan/api/password.py:174-180`.

### Security enforcement (SEC-01, SEC-03)
- **D-11:** Add ESLint `no-console` rule with `"error"` level in `.eslintrc.cjs`, but allow `console.warn` and `console.error` (there's an existing `console.error` in `ReportPage.tsx:35` for clipboard fallback). Config: `'no-console': ['error', { allow: ['warn', 'error'] }]`. This blocks `console.log`, `console.debug`, `console.info` — the channels most likely to leak sensitive data — while preserving legitimate error reporting.
- **D-12:** SEC-03 (no password in URL/query/history) is **inherently satisfied** by using `POST` with a JSON body. The `submitPassword()` method uses `fetch()` with `method: 'POST'` and `body: JSON.stringify(...)` — password never touches the URL. No additional enforcement needed beyond not implementing it wrong.
- **D-13:** No `console.log` statements will be added in any new code. The ESLint rule catches any accidental additions at lint time.

### Scope boundaries
- **D-14:** Phase 9 does **NOT** change the SSE handler in `JobStatusPage.tsx`. The SSE `onmessage` callback currently ignores `password_required` (it falls through without closing). Phase 10 will add the password prompt UI there.
- **D-15:** Phase 9 does **NOT** create any new React components. The `components/` directory stays empty until Phase 10.
- **D-16:** Phase 9 does **NOT** refactor existing API methods to use `ApiRequestError`. Only `submitPassword()` uses it.
- **D-17:** `stageLabels` map (duplicated between JobStatusPage and ReportPage) should also be centralized in `src/constants/status.ts` while we're consolidating status maps. This avoids a half-migration where some maps are shared and some aren't.

### the agent's Discretion
- Exact file organization within `src/api/types.ts` (interface ordering, export grouping)
- Whether `ApiRequestError` lives in `types.ts` or a separate `errors.ts` file
- Whether to add a `verdictLabels`/`verdictColors`/`verdictIcons` map to the shared constants file (ReportPage-only maps, not duplicated)
- TypeScript `satisfies` keyword usage for type-safe Record construction
- Whether to re-export types from `client.ts` for backward compatibility or update all imports

</decisions>

<specifics>
## Specific Ideas

- The types-first approach means Phase 10 can focus purely on UI without any type plumbing
- `ApiRequestError` with `code` field enables Phase 11 to pattern-match on specific error codes like `MAX_ATTEMPTS_EXCEEDED`, `WRONG_PASSWORD`, `INVALID_JOB_STATUS` without parsing strings
- The `no-console` ESLint rule is a broader security improvement that benefits the whole codebase, not just password handling
- Centralizing status maps eliminates the risk of adding `password_required` to one page but forgetting the other

</specifics>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Requirements & architecture
- `.planning/REQUIREMENTS.md` — All 22 v1.2 requirements with categories (SDT, PWI, ERR, SEC, REF)
- `.planning/PROJECT.md` — v1.2 milestone definition, constraints, key decisions
- `.planning/ROADMAP.md` — Phase 9 scope, success criteria, requirement mapping

### Codebase architecture
- `.planning/codebase/ARCHITECTURE.md` — System component diagram, data flow, service boundaries
- `.planning/codebase/CONVENTIONS.md` — Coding patterns, error handling, logging conventions

### Key source files (integration points)
- `frontend/src/api/client.ts` — API client class + all type definitions (203 lines). **Phase 9 primary target.**
- `frontend/src/pages/JobStatusPage.tsx` — SSE handler + inline status maps (213 lines). Status maps extracted, SSE handler untouched.
- `frontend/src/pages/ReportPage.tsx` — Report display + duplicate status/verdict maps (378 lines). Status maps extracted.
- `frontend/.eslintrc.cjs` — ESLint config. Adding `no-console` rule.
- `frontend/tailwind.config.js` — Cyberpunk theme config. May need `neon-yellow` color.

### Backend API contract (password endpoint)
- `backend/src/malscan/api/password.py` — `POST /jobs/{job_id}/password` implementation
  - Request: `{"password": "string"}`
  - Success (200): `{"job_id": "...", "status": "queued", "message": "...", "attempts_used": N, "attempts_remaining": M}`
  - Errors: 400 (`EMPTY_PASSWORD`, `INVALID_JOB_ID`), 404 (`JOB_NOT_FOUND`), 409 (`INVALID_JOB_STATUS`), 429 (`MAX_ATTEMPTS_EXCEEDED`)
  - Error format: `{"detail": {"error": {"code": "...", "message": "..."}}}`

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- **`ApiClient` class** (`client.ts:117`): Class-based singleton with `baseUrl` constructor. New `submitPassword()` method fits naturally as an additional method.
- **`ApiError` interface** (`client.ts:105`): Already defined but never used. Phase 9's `ApiRequestError` class replaces its purpose — the interface can be removed or kept for reference.
- **Error extraction pattern** (`client.ts:148-156`): All methods use the same nested error message extraction (`errorData?.detail?.error?.message || ...`). `submitPassword()` will use a variant that preserves the `code` field.

### Established Patterns
- **Inline Traditional Chinese**: All user-facing strings are hardcoded Chinese. New status label follows: `需要密碼`.
- **Cyberpunk Tailwind classes**: `text-neon-cyan`, `text-matrix-green`, `text-alert-red`, `text-slate-400`. New color: `text-caution-yellow` (already in theme as `caution-yellow: '#eab308'`).
- **`Record<string, string>` maps**: Currently untyped. Phase 9 changes to `Record<JobStatusValue, string>` for compile-time exhaustiveness.
- **Default exports for pages**: `export default function PageName()`. Not relevant to Phase 9 (no new pages/components).
- **Native fetch + EventSource**: No HTTP libraries. `submitPassword()` uses native `fetch`.

### Integration Points
- **`JobStatusPage.tsx` → status maps**: Currently inline `statusLabels`, `statusColors`, `stageLabels`. Phase 9 extracts to shared constants; page imports them.
- **`ReportPage.tsx` → status maps**: Currently inline `stageLabels` (duplicate). Phase 9 extracts; page imports.
- **`client.ts` → types**: All types currently co-located. Phase 9 moves to `types.ts`; `client.ts` imports.
- **`.eslintrc.cjs` → rules**: Adding `no-console: "error"` may flag existing `console.log` calls. Need to check if any exist.

</code_context>

<deferred>
## Deferred Ideas

- **Refactor existing API methods** to use `ApiRequestError` — future consistency improvement
- **Add `encryption_method` to `JobStatus` type** — deferred per REQUIREMENTS.md ("Encryption method display" is future)
- **Add `parent_job_id`, `total_sub`, `completed_sub`, `malicious_sub`** to `JobStatus` — backend sends these but frontend doesn't need them yet
- **Verdict maps centralization** — `verdictLabels`/`verdictColors`/`verdictIcons` in ReportPage aren't duplicated, so centralization is optional
- **i18n framework** — explicitly out of scope per REQUIREMENTS.md

</deferred>

---

*Phase: 09-typescript-foundations-api-client*
*Context gathered: 2026-03-31*
