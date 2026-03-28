# Phase 5: Integration & Deployment - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-03-28
**Phase:** 05-integration-deployment
**Areas discussed:** Proxy routing strategy, Kubernetes manifest design, Ingest-specific k8s config, Local dev integration

---

## Proxy Routing Strategy

### Q1: How should traffic be split between Go ingest and FastAPI?

| Option | Description | Selected |
|--------|-------------|----------|
| Nginx reverse proxy | Dedicated Nginx config with location + method matching. Standard, well-understood. Matches PROJECT.md decision. | ✓ |
| Traefik with path/method rules | Traefik IngressRoute or middleware. More k8s-native but adds new dependency. | |
| Kubernetes Ingress only | Only k8s Ingress, no Docker Compose proxy. Local dev keeps direct port access. | |

**User's choice:** Nginx reverse proxy (Recommended)
**Notes:** Aligns with existing PROJECT.md key decision for proxy routing via Nginx.

### Q2: Should Nginx proxy be in Docker Compose and k8s, or k8s only?

| Option | Description | Selected |
|--------|-------------|----------|
| Both Docker Compose and k8s | Nginx in both envs. Frontend always hits proxy. Identical routing path locally and in production. | ✓ |
| k8s only | Only add Nginx for k8s. Docker Compose keeps direct port access. Simpler but routing differs between envs. | |

**User's choice:** Both Docker Compose and k8s (Recommended)
**Notes:** Ensures consistent routing behavior across environments.

### Q3: Which port should Nginx proxy listen on in Docker Compose?

| Option | Description | Selected |
|--------|-------------|----------|
| Proxy takes over :8000 | Proxy takes api's port mapping. Frontend keeps hitting :8000. Zero frontend config change. | ✓ |
| Proxy on new port (e.g. :80) | Proxy on different port. Requires frontend config change. | |

**User's choice:** Proxy takes over :8000 (Recommended)
**Notes:** Zero-disruption for frontend — same port, transparently proxied.

### Q4: Method+path vs path-only routing?

| Option | Description | Selected |
|--------|-------------|----------|
| Method + path match | Only POST /api/v1/files → Go. All other methods/paths → FastAPI. Simple, precise. | ✓ |
| Path-only match | All methods on /api/v1/files → Go. Simpler config but Go must handle non-POST methods. | |

**User's choice:** Method + path match (Recommended)
**Notes:** Precise routing — only the upload POST goes to Go.

---

## Kubernetes Manifest Design

### Q5: Should k8s/ingest/ follow k8s/api/ structure?

| Option | Description | Selected |
|--------|-------------|----------|
| Mirror api/ structure | Deployment + Service in single deployment.yaml. Same convention as existing api/. | ✓ |
| Separate deployment + service files | Separate files. More granular but diverges from convention. | |

**User's choice:** Mirror api/ structure (Recommended)
**Notes:** Consistency with existing k8s manifest patterns.

### Q6: Service type for ingest in k8s?

| Option | Description | Selected |
|--------|-------------|----------|
| ClusterIP (internal only) | Only reachable within cluster via Nginx proxy. No direct external access. | ✓ |
| NodePort (direct access) | Accessible via nodePort like api (30080). Allows direct debug access. | |

**User's choice:** ClusterIP (internal only) (Recommended)
**Notes:** Cleaner architecture — all external access through Nginx proxy.

### Q7: Replica count for ingest Deployment?

| Option | Description | Selected |
|--------|-------------|----------|
| 1 replica | Single replica. Matches api. Sufficient for initial deployment. | ✓ |
| 2 replicas | Basic redundancy during rolling updates. Matches worker. | |

**User's choice:** 1 replica (Recommended)
**Notes:** Start simple, scale after production observation.

---

## Ingest-Specific K8s Config

### Q8: Reuse shared ConfigMap/Secrets or create ingest-specific ones?

| Option | Description | Selected |
|--------|-------------|----------|
| Shared configmap + inline extras | Reuse malscan-config + malscan-secrets via envFrom. Add ingest-specific values as inline env. | ✓ |
| Separate ingest configmap | Create separate k8s/ingest/configmap.yaml. More organized but adds another resource. | |

**User's choice:** Shared configmap + inline extras (Recommended)
**Notes:** Avoids resource proliferation. Ingest-specific vars as inline env entries.

### Q9: Filesystem and /tmp volume strategy?

| Option | Description | Selected |
|--------|-------------|----------|
| readOnly + emptyDir /tmp | readOnlyRootFilesystem: true with emptyDir volume at /tmp. Same as api pattern. | ✓ |
| Writable root filesystem | readOnlyRootFilesystem: false. Simpler but less secure. | |

**User's choice:** readOnly + emptyDir /tmp (Recommended)
**Notes:** Secure approach matching api Deployment. Required for temp file streaming.

### Q10: Resource requests/limits?

| Option | Description | Selected |
|--------|-------------|----------|
| Match api resources | 100m/256Mi requests, 500m/512Mi limits. Go binary is lightweight. | ✓ |
| Higher than api | 200m/256Mi requests, 1000m/1Gi limits. More room for concurrent uploads. | |

**User's choice:** Match api resources (Recommended)
**Notes:** Start with api-equivalent resources, adjust after production profiling.

---

## Local Dev Integration

### Q11: How to add Nginx to Docker Compose?

| Option | Description | Selected |
|--------|-------------|----------|
| Nginx service in compose | Nginx service with mounted nginx.conf. Takes over port 8000. | ✓ |
| Nginx on separate port | Keep api on :8000, add nginx on different port. Less disruptive but routing differs. | |

**User's choice:** Nginx service in compose (Recommended)
**Notes:** Consistent with decision D-03 (proxy takes over :8000).

### Q12: Where should Nginx config file live?

| Option | Description | Selected |
|--------|-------------|----------|
| nginx/ directory at project root | Single nginx.conf shareable between Docker Compose and k8s. | ✓ |
| Separate configs per environment | Different configs for compose vs k8s. | |

**User's choice:** nginx/ directory at project root (Recommended)
**Notes:** Single source of truth, mountable in both environments.

### Q13: CORS handling with Nginx proxy?

| Option | Description | Selected |
|--------|-------------|----------|
| CORS on backend services | Services control their own CORS. Nginx just proxies. | ✓ |
| CORS on Nginx proxy | Nginx handles CORS centrally. | |

**User's choice:** CORS on backend services (Recommended)
**Notes:** Keep existing Phase 4 CORS implementation. Nginx passes through transparently.

---

## Agent's Discretion

- Exact Nginx config syntax and tuning parameters
- K8s probe configuration details (intervals, thresholds)
- Whether to add Prometheus scrape annotations on ingest pods
- Nginx k8s deployment specifics
- Client max body size in Nginx config

## Deferred Ideas

None — discussion stayed within phase scope
