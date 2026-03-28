---
phase: quick
plan: 260328-uu7
subsystem: ingest/config
tags: [config, dotenv, bugfix, go]
dependency_graph:
  requires: []
  provides: [dotenv-loading, env-key-fix]
  affects: [ingest-startup]
tech_stack:
  added: [joho/godotenv v1.5.1]
  patterns: [silent-dotenv-load, os-env-precedence]
key_files:
  created: []
  modified:
    - ingest/internal/config/config.go
    - ingest/internal/config/config_test.go
    - ingest/go.mod
    - ingest/go.sum
    - ingest/.gitignore
decisions:
  - "Use _ = godotenv.Load() pattern to silently ignore missing .env (safe for prod/Docker)"
  - "Add .env to .gitignore to prevent credential leaks"
metrics:
  duration: 136s
  completed: "2026-03-28"
  tasks_completed: 2
  tasks_total: 2
---

# Quick Task 260328-uu7: Fix Ingest Startup — Add .env Auto-Loading

**One-liner:** Added godotenv .env auto-loading before env.Parse() and fixed AMQP_URL → RABBITMQ_URL key mismatch so the ingest service starts cleanly in local dev.

## What Changed

### Task 1: Add godotenv .env loading and fix .env key (bf17fc6)

- Added `joho/godotenv` dependency to `go.mod`
- Added `godotenv.Load()` call at the top of `config.Load()`, before `env.Parse()` — silently ignored when .env is missing (production)
- Renamed `AMQP_URL` to `RABBITMQ_URL` in `.env` to match the Config struct's `env:"RABBITMQ_URL"` tag
- Added `.env` to `.gitignore` to prevent accidental credential commits

### Task 2: Add tests for .env loading behavior (f6e2034)

- `TestLoadFromDotEnvFile`: Creates temp .env, changes CWD, verifies `Load()` succeeds reading vars from .env file
- `TestOsEnvOverridesDotEnv`: Sets OS env var + .env with different value, confirms OS wins (godotenv's documented non-override behavior)
- All 10 config tests pass (8 existing + 2 new)

## Verification

```
go build ./cmd/ingest       ✓ (no errors)
go vet ./...                ✓ (no warnings)
go test ./... -count=1      ✓ (all packages pass)
```

## Deviations from Plan

None — plan executed exactly as written.

## Known Stubs

None.

## Commits

| # | Hash | Message |
|---|------|---------|
| 1 | bf17fc6 | fix(260328-uu7): add godotenv .env auto-loading and fix AMQP_URL key mismatch |
| 2 | f6e2034 | test(260328-uu7): add tests for .env file loading and OS env override behavior |
