---
phase: 1
slug: foundation-infrastructure-wiring
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-03-27
---

# Phase 1 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Go stdlib `testing` (Go 1.22) |
| **Config file** | None — Go test runner is built in |
| **Quick run command** | `cd ingest && go test ./...` |
| **Full suite command** | `cd ingest && go test -v -race ./...` |
| **Estimated runtime** | ~5 seconds |

---

## Sampling Rate

- **After every task commit:** Run `cd ingest && go build ./... && go test ./...`
- **After every plan wave:** Run `cd ingest && go test -v -race ./... && go vet ./...`
- **Before `/gsd-verify-work`:** Full suite must be green + Docker Compose smoke test
- **Max feedback latency:** 10 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| config-parse | 01 | 1 | OPS-03 | unit | `go test ./internal/config/ -run TestConfigParse -v` | ❌ | pending |
| db-url-transform | 01 | 1 | DB-07 | unit | `go test ./internal/config/ -run TestDatabaseURLTransform -v` | ❌ | pending |
| pool-config | 01 | 1 | DB-06 | unit | `go test ./internal/config/ -run TestPoolConfig -v` | ❌ | pending |
| logger-json | 01 | 1 | OPS-02 | unit | `go test ./cmd/ingest/ -run TestLoggerOutput -v` | ❌ | pending |
| health-ok | 02 | 2 | OPS-01 | unit (mock) | `go test ./internal/health/ -run TestHealthy -v` | ❌ | pending |
| health-fail | 02 | 2 | OPS-01 | unit (mock) | `go test ./internal/health/ -run TestUnhealthy -v` | ❌ | pending |
| dockerfile-build | 03 | 3 | OPS-05 | smoke | `docker build -t test-ingest ./ingest` | ❌ | pending |
| compose-start | 03 | 3 | OPS-06 | integration | `docker compose up -d ingest && curl http://localhost:8080/health` | ❌ | pending |
| minio-bucket | 03 | 3 | STORE-02 | integration | `docker compose up -d ingest && mc ls myminio/uploads` | ❌ | pending |

---

## Wave 0 Gaps

- [ ] `ingest/internal/config/config_test.go` — covers OPS-03, DB-07, DB-06
- [ ] `ingest/internal/health/health_test.go` — covers OPS-01 (mock backends)
- [ ] Go module initialization: `go mod init` in `ingest/`
