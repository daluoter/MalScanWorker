---
phase: 05-integration-deployment
plan: 02
subsystem: infra
tags: [kubernetes, k8s, deployment, service, clusterip, security-context]

# Dependency graph
requires:
  - phase: 04-api-contract-production-readiness
    provides: Production-ready Go binary with health endpoints, CORS, graceful shutdown
  - phase: 01-foundation
    provides: Dockerfile, health endpoint at /healthz, config env vars
provides:
  - Kubernetes Deployment for malscan-ingest with probes, security context, resource limits
  - ClusterIP Service for internal-only access at port 8080
affects: [production-deployment, k8s-ingress-setup]

# Tech tracking
tech-stack:
  added: []
  patterns: [k8s deployment mirroring api pattern, ClusterIP for proxy-only access]

key-files:
  created: [k8s/ingest/deployment.yaml]
  modified: []

key-decisions:
  - "ClusterIP (not NodePort) — ingest only reachable through proxy"
  - "All three probes (startup/liveness/readiness) hit /healthz on port 8080"
  - "Ingest-specific env vars as inline env entries alongside shared envFrom"
  - "Resource limits match api: 100m/256Mi requests, 500m/512Mi limits"

patterns-established:
  - "K8s ingest deployment mirrors api deployment pattern exactly"
  - "ClusterIP for internal services behind proxy, NodePort for direct-access services"

requirements-completed: [DEPLOY-02]

# Metrics
duration: 1min
completed: 2026-03-28
---

# Phase 5 Plan 02: Kubernetes Manifests Summary

**Kubernetes Deployment + ClusterIP Service for ingest with liveness/readiness/startup probes, security context (runAsNonRoot, readOnlyRootFilesystem), and shared config/secrets**

## Performance

- **Duration:** 1 min
- **Started:** 2026-03-28T07:26:40Z
- **Completed:** 2026-03-28T07:27:20Z
- **Tasks:** 1
- **Files modified:** 1

## Accomplishments
- Created k8s/ingest/deployment.yaml with Deployment (1 replica) and ClusterIP Service
- Security context: runAsNonRoot, runAsUser 1000, readOnlyRootFilesystem with emptyDir /tmp
- Three-probe chain: startupProbe -> livenessProbe -> readinessProbe all on /healthz:8080
- Shared envFrom (malscan-config + malscan-secrets) with ingest-specific inline env vars

## Task Commits

Each task was committed atomically:

1. **Task 1: Create k8s/ingest/deployment.yaml with Deployment and ClusterIP Service** - `e6df6eb` (feat)

## Files Created/Modified
- `k8s/ingest/deployment.yaml` - Deployment + ClusterIP Service mirroring api pattern with ingest-specific config

## Decisions Made
- ClusterIP service type (not NodePort) — ingest is internal-only, accessed via proxy
- Probes use /healthz (not /health or /ready) matching Go ingest health endpoint
- Port 8080 throughout (container, probes, service) matching Go config default
- Prometheus scrape annotations included for monitoring parity with api/worker

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered
None

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- K8s manifests ready for deployment alongside existing api/worker/infra manifests
- May need Nginx K8s deployment or Ingress controller for production proxy routing (out of scope for this phase)

---
*Phase: 05-integration-deployment*
*Completed: 2026-03-28*
