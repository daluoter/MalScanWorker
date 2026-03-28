# Phase 5: Integration & Deployment - Context

**Gathered:** 2026-03-28
**Status:** Ready for planning

<domain>
## Phase Boundary

Go ingest service runs alongside the existing FastAPI backend in production with transparent proxy routing and Kubernetes deployment manifests. Nginx reverse proxy routes `POST /api/v1/files` to Go ingest, all other paths to FastAPI. Kubernetes manifests in `k8s/ingest/` define Deployment and Service. This phase covers requirements DEPLOY-01 and DEPLOY-02.

</domain>

<decisions>
## Implementation Decisions

### Proxy routing strategy
- **D-01:** Nginx reverse proxy for traffic splitting — standard, well-understood, matches PROJECT.md decision
- **D-02:** Nginx added to BOTH Docker Compose (local dev) and Kubernetes (production) — identical routing path in both environments
- **D-03:** Proxy takes over port 8000 in Docker Compose — the `api` service loses its host port mapping, frontend keeps hitting `localhost:8000` which is now Nginx. Zero frontend config change required
- **D-04:** Method + path matching — only `POST /api/v1/files` routes to Go ingest (port 8080), all other requests (including GET/OPTIONS on the same path) route to FastAPI
- **D-05:** CORS headers handled by backend services (Go ingest and FastAPI), not by Nginx — services control their own CORS. Nginx just proxies transparently

### Kubernetes manifest design
- **D-06:** Mirror existing `k8s/api/` structure — single `deployment.yaml` containing both Deployment and Service resources in `k8s/ingest/deployment.yaml`
- **D-07:** ClusterIP service type (internal only) — ingest is only reachable through the Nginx proxy, no direct external access. Differs from api's NodePort since proxy handles routing
- **D-08:** 1 replica for initial deployment — matches api Deployment pattern, sufficient for launch

### Ingest-specific k8s config
- **D-09:** Reuse existing `malscan-config` ConfigMap and `malscan-secrets` Secret via `envFrom` — same pattern as api/worker. Add ingest-specific values (PORT=8080, MAX_FILE_SIZE, SHUTDOWN_TIMEOUT, CORS_ORIGINS) as inline `env` entries in the Deployment spec
- **D-10:** `readOnlyRootFilesystem: true` with emptyDir volume mounted at `/tmp` — same pattern as api Deployment. Required for upload temp file streaming (Phase 2 decision)
- **D-11:** Resource requests/limits match api: requests 100m CPU / 256Mi memory, limits 500m CPU / 512Mi memory. Go binary is lightweight; adjust after production profiling

### Local dev integration
- **D-12:** Nginx service added to docker-compose.yml — mounted config from `nginx/nginx.conf` at project root
- **D-13:** `nginx/` directory at project root for config file — shareable between Docker Compose (volume mount) and Kubernetes (ConfigMap source)
- **D-14:** Nginx depends on both `api` and `ingest` services in compose — ensures backends are available before proxy starts

### Agent's Discretion
- Exact Nginx config syntax and tuning (worker_processes, proxy_pass directives, timeouts, buffer sizes)
- K8s probe configuration (intervals, thresholds, startup probe parameters) — follow api pattern as baseline
- Whether to add Prometheus scrape annotations on ingest pods (api/worker already have them)
- Nginx k8s deployment details (image version, resource limits, ConfigMap mount)
- Client max body size in Nginx (should be >= 150MB to match Go's MaxBytesReader)

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Existing k8s manifests (patterns to follow)
- `k8s/api/deployment.yaml` — Reference Deployment + Service: probes, securityContext, envFrom, NodePort, emptyDir /tmp pattern
- `k8s/worker/deployment.yaml` — Worker Deployment: 2 replicas, volume mounts, resource profile
- `k8s/configmap.yaml` — Shared ConfigMap with MINIO_ENDPOINT, RABBITMQ, LOG_LEVEL etc.
- `k8s/secrets.yaml.example` — Secret template: DATABASE_URL, MINIO keys, RABBITMQ_URL
- `k8s/namespace.yaml` — Namespace `malscan`

### Docker Compose (existing setup to extend)
- `docker-compose.yml` — Current service definitions including `ingest` service on port 8080, `api` on port 8000

### Ingest service (what's being deployed)
- `ingest/Dockerfile` — Multi-stage Go build, alpine runtime, runs as uid 1000, exposes 8080
- `ingest/internal/config/config.go` — Config struct with PORT, SHUTDOWN_TIMEOUT, CORS_ORIGINS, MAX_FILE_SIZE
- `ingest/internal/server/server.go` — Router setup with health endpoint at `/healthz`

### Python API (co-deployed backend)
- `backend/src/malscan/main.py` — FastAPI app entry point, serves on port 8000
- `backend/Dockerfile` — Python backend container build

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `k8s/api/deployment.yaml`: Complete template for Deployment + Service with probes, security context, envFrom, resource limits — copy and adapt for ingest
- `k8s/configmap.yaml`: Shared config already covers MINIO, RABBITMQ, LOG_LEVEL — ingest can reuse via envFrom
- `k8s/secrets.yaml.example`: Secret already covers DATABASE_URL, MINIO keys, RABBITMQ_URL — no new secrets needed
- `docker-compose.yml`: Ingest service already defined with correct environment variables and health-check dependencies
- `ingest/Dockerfile`: Production-ready multi-stage build, runs as non-root uid 1000, alpine base

### Established Patterns
- K8s deployments use `envFrom` referencing both configMapRef and secretRef
- Pod security: `runAsNonRoot: true`, `runAsUser: 1000`, `readOnlyRootFilesystem: true` with emptyDir for /tmp
- Prometheus annotations on pod templates (`prometheus.io/scrape`, `prometheus.io/port`, `prometheus.io/path`)
- startupProbe → livenessProbe → readinessProbe chain with httpGet health endpoints
- Container images from `ghcr.io/daluoter/malscan-{service}:latest`

### Integration Points
- No existing proxy/Nginx config — must be created from scratch in `nginx/` directory
- `docker-compose.yml` needs: new `nginx` service, removal of `api` port mapping (proxy takes over :8000)
- `k8s/` needs: new `k8s/ingest/` directory with deployment.yaml
- Nginx k8s deployment may need its own manifest (or be added to an existing ingress pattern)

</code_context>

<specifics>
## Specific Ideas

No specific requirements — standard Nginx reverse proxy pattern with method-based routing. Follow existing k8s manifest conventions exactly.

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope

</deferred>

---

*Phase: 05-integration-deployment*
*Context gathered: 2026-03-28*
