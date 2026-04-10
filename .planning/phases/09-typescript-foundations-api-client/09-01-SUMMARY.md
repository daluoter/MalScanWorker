---
phase: 09-typescript-foundations-api-client
plan: 01
subsystem: frontend-types
tags: [typescript, types, status-maps, password-required, centralization, SDT-03]

# Dependency graph
requires:
  - phase: 08-encryption-reporting-operational-hardening
    provides: "Backend password_required status and encryption_method in API responses"
provides:
  - "JobStatusValue type alias including 'password_required' in frontend/src/api/types.ts"
  - "All API types extracted to dedicated types.ts with re-export from client.ts"
  - "Centralized statusLabels, statusColors, stageLabels in frontend/src/constants/status.ts"
  - "password_required mapped to label '需要密碼' and color 'text-caution-yellow'"
  - "Record<JobStatusValue, string> typed maps for compile-time exhaustiveness"
affects: [frontend-pages, api-client, status-display]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Type-safe Record<JobStatusValue, string> maps enforce exhaustive status handling at compile time"
    - "Re-export pattern (export * from './types') preserves backward compatibility for existing imports"

key-files:
  created:
    - frontend/src/api/types.ts
    - frontend/src/constants/status.ts
  modified:
    - frontend/src/api/client.ts
    - frontend/src/pages/JobStatusPage.tsx
    - frontend/src/pages/ReportPage.tsx

key-decisions:
  - "Named type alias JobStatusValue (not inline union) for reuse across typed Record keys"
  - "Separate src/api/types.ts for all types, extracted from client.ts"
  - "Centralized src/constants/status.ts eliminates duplication between JobStatusPage and ReportPage"
  - "stageLabels includes all stage keys from both pages (including archive-extract from ReportPage)"
  - "stageLabels typed as Record<string, string> since stages are not a closed union"

patterns-established:
  - "Type extraction: all API interfaces in types.ts, re-exported from client.ts"
  - "Shared constants: display maps in constants/ directory, imported by pages"

requirements-completed: [SDT-03]

# Metrics
duration: ~20min
completed: 2026-03-31
---

# Phase 09 Plan 01: Type Extraction & Centralized Status Maps Summary

**All API types extracted to dedicated types.ts with JobStatusValue union including password_required. Status display maps centralized in constants/status.ts with typed Record<JobStatusValue, string> keys for compile-time exhaustiveness. Both pages import shared maps instead of defining inline duplicates.**

## What Was Done

### Task 1: Create types.ts with all API types and JobStatusValue alias

Extracted all 12 interface/type definitions from `client.ts` to new `frontend/src/api/types.ts`:

- **JobStatusValue** type alias: `'queued' | 'scanning' | 'done' | 'failed' | 'password_required'`
- **JobStatus.status** field changed from inline `string` to `JobStatusValue` type
- All interfaces exported: UploadResponse, JobProgress, JobStatus, FileMetadata, AvResult, YaraHit, Iocs, StageTiming, Report, ApiError, HealthResponse
- `client.ts` updated: removed all type definitions, added `import type` from `./types`, added `export * from './types'` for backward compatibility
- Existing page imports (`from '../api/client'`) continue working via re-export

### Task 2: Create centralized status constants and update pages

Created `frontend/src/constants/status.ts` with three shared maps:

- **statusLabels**: `Record<JobStatusValue, string>` — maps status values to Traditional Chinese labels. Added `password_required: '需要密碼'`
- **statusColors**: `Record<JobStatusValue, string>` — maps status values to Tailwind classes. Added `password_required: 'text-caution-yellow'`
- **stageLabels**: `Record<string, string>` — merged superset from both pages, includes `archive-extract: 'ARCHIVE_EXTRACT'` from ReportPage

Updated pages:
- **JobStatusPage.tsx**: Removed 3 inline map definitions (statusLabels, statusColors, stageLabels), added import from `../constants/status`
- **ReportPage.tsx**: Removed 1 inline map definition (stageLabels), added import from `../constants/status`. Kept verdict maps inline (page-specific, not duplicated)

## Deviations from Plan

None.

## Verification Results

| Check | Result |
|-------|--------|
| `npx tsc --noEmit` | Compiles without errors |
| `password_required` in frontend/src/ | Found in types.ts (union) and status.ts (both maps) |
| `需要密碼` in frontend/src/ | Found in status.ts |
| `statusLabels` in pages/ | Only import statements, no inline definitions |
| `stageLabels` in pages/ | Only import statements, no inline definitions |
| `Record<string, string>` in constants/ | Only stageLabels (status maps use Record<JobStatusValue, string>) |

## Known Stubs

None — all type extraction and map centralization is complete.

## Self-Check: PASSED

- All 5 key files: FOUND
- types.ts contains JobStatusValue with password_required: YES
- status.ts contains 需要密碼 and text-caution-yellow: YES
- Pages import from constants, no inline duplicates: YES
- TypeScript compiles clean: YES
