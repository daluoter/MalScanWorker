# External Integrations

**Analysis Date:** 2025-01-13

## APIs & External Services

**Malware Analysis Engines:**
- ClamAV - Antivirus scanning
  - Client: pyclamd 0.4.0 (network socket)
  - Connection: TCP host/port (default: localhost:3310)
  - Usage: `worker/src/malscan_worker/stages/clamav.py`
  - Authentication: None (local daemon)

- YARA - Pattern-based malware detection
  - SDK/Client: yara-python 4.5.4
  - Connection: File-based rule loading
  - Rules location: `/etc/yara/rules/` (configurable via `YARA_RULES_PATH`)
  - Usage: `worker/src/malscan_worker/stages/yara_scan.py`
  - Authentication: None

**Archive Processing:**
- 7z extraction via py7zr 0.22.0
  - Usage: `worker/src/malscan_worker/stages/archive_extract.py`
  - Authentication: None

- RAR extraction via rarfile 4.2
  - Usage: `worker/src/malscan_worker/stages/archive_extract.py`
  - Authentication: None

## Data Storage

**Databases:**
- PostgreSQL 13+ (primary data store)
  - Connection string: `DATABASE_URL` env var
  - Format: `postgresql+asyncpg://user:pass@host:port/db`
  - Client: SQLAlchemy 2.0.0 with asyncpg 0.29.0 driver
  - Async pool: 10 base connections + 20 overflow
  - Usage: `backend/src/malscan/db/engine.py`
  - Tables auto-created on startup via SQLAlchemy ORM
  - Optional migration tool: Alembic (configured but not actively used)

**File Storage:**
- MinIO (S3-compatible object storage)
  - SDK/Client: minio 7.2.0 (Python SDK)
  - Connection: HTTP to MinIO endpoint
  - Credentials: `MINIO_ACCESS_KEY`, `MINIO_SECRET_KEY` env vars
  - Endpoint: `MINIO_ENDPOINT` env var (default: localhost:9000)
  - Secure: `MINIO_SECURE` env var (default: false)
  - Buckets:
    - `uploads` - User-uploaded malware samples
    - `artifacts` - Analysis artifacts and reports
  - Lifecycle policy: 1-day expiry on uploads bucket
  - Usage: `backend/src/malscan/storage.py`, `worker/src/malscan_worker/storage.py`
  - Threading: Sync operations wrapped in asyncio executor (ThreadPoolExecutor, max 4 workers)

**Caching:**
- None (application uses in-memory caches for YARA rules and configuration)
- Redis/Memcached not integrated

## Message Queuing

**RabbitMQ:**
- Broker URL: `RABBITMQ_URL` env var
- Format: `amqp://user:pass@host:port/`
- Client: aio-pika 9.3.0 (async AMQP)
- Queue: `malscan.jobs` (configurable via `RABBITMQ_QUEUE`)
- Queue configuration:
  - Durable: Yes (persisted across restarts)
  - Dead-letter exchange: "" (default exchange)
  - Dead-letter routing key: "malscan-dlq"
- Message format: JSON
- Message delivery mode: PERSISTENT
- Publisher: `backend/src/malscan/queue.py`
- Consumer: `worker/src/malscan_worker/consumer.py`
- Retry strategy:
  - Publisher: 5 attempts, exponential backoff (1s → 16s)
  - Consumer: 3 retries before dead-letter queue
  - Backoff: x-death headers tracked by RabbitMQ

## Authentication & Identity

**Auth Provider:**
- Custom/None - No centralized auth provider
- API is publicly accessible (no authentication required)
- CORS origins configurable via `CORS_ORIGINS` env var
- Frontend sends requests directly to API

## Monitoring & Observability

**Error Tracking:**
- None (no Sentry, Rollbar, or similar)

**Logs:**
- Structured JSON logging via structlog 23.2.0
- Log level: Configurable via `LOG_LEVEL` env var (default: INFO)
- Output format: JSON
- Processors configured in `backend/src/malscan/main.py`:
  - Log level annotation
  - ISO timestamp
  - JSON rendering

**Metrics:**
- Backend: Prometheus metrics via prometheus-fastapi-instrumentator 6.1.0
  - Endpoint: `/metrics`
  - Tracks: Request latency, status codes, request count
  - Usage: `backend/src/malscan/main.py`

- Worker: Prometheus metrics via prometheus-client 0.19.0
  - Metrics server: aiohttp-based on port 9090
  - Endpoint: `/metrics`
  - Metrics exposed:
    - `malscan_job_total` - Job count by status
    - `malscan_stage_latency_seconds` - Stage execution time
    - `malscan_queue_depth` - Pending jobs
    - `malscan_worker_active_jobs` - Currently processing jobs
  - Usage: `worker/src/malscan_worker/metrics.py`

**Health Checks:**
- Backend health endpoint: `GET /health` - Returns `{"status": "ok"}`
- Backend readiness endpoint: `GET /ready` - Returns `{"status": "ready"}` (TODO: check deps)
- Worker health endpoint: `GET /health` (via metrics server)
- Worker readiness endpoint: `GET /ready` (via metrics server)
- Usage: Kubernetes liveness/readiness probes

## CI/CD & Deployment

**Hosting:**
- Kubernetes (k3s) on Linux VMs
- GitHub Pages for static frontend
- Docker containers for backend and worker services

**CI Pipeline:**
- GitHub Actions
- Triggers: Push to main branch
- Builds Docker images and pushes to GHCR (GitHub Container Registry)
  - `ghcr.io/{OWNER}/malscan-api:latest`
  - `ghcr.io/{OWNER}/malscan-worker:latest`
- Deploys frontend to GitHub Pages

**Deployment:**
- Kubernetes manifests: `k8s/` directory
  - Namespace: `malscan`
  - Services: API, Worker, MinIO, RabbitMQ, PostgreSQL
  - ConfigMaps and Secrets for configuration
  - PersistentVolumes and PersistentVolumeClaims for storage
- Docker Compose for local development: `docker-compose.yml`

## Frontend-Backend Communication

**Protocol:**
- REST API with HTTP/HTTPS
- Base URL configurable via `VITE_API_BASE_URL` env var (defaults to http://localhost:8000)

**Endpoints:**
- `POST /api/v1/files` - Upload file for analysis
- `GET /api/v1/jobs/{job_id}` - Query job status
- `GET /api/v1/jobs/{job_id}/stream` - Server-Sent Events stream for progress
- `GET /api/v1/reports/{job_id}` - Get analysis report
- `GET /health` - Health check
- `GET /ready` - Readiness check
- `GET /metrics` - Prometheus metrics

**CORS Configuration:**
- Configurable via `CORS_ORIGINS` env var (comma-separated list)
- Default: "*" (all origins allowed)
- Methods allowed: GET, POST, PUT, DELETE, OPTIONS, PATCH
- Preflight cache: 10 minutes

**Frontend Client:**
- Fetch API (native browser)
- No external HTTP library (no Axios, no React Query)
- Usage: `frontend/src/api/client.ts`
- TypeScript client class with error handling

## Webhooks & Callbacks

**Incoming:**
- None (no external webhooks received)

**Outgoing:**
- None (no webhooks sent to external systems)

**Real-time Updates:**
- Server-Sent Events (SSE) for job progress streaming
  - Endpoint: `GET /api/v1/jobs/{job_id}/stream`
  - Library: sse-starlette 1.1.5
  - Usage: `backend/src/malscan/api/routes.py`
  - Frontend listens with EventSource API

## External File Storage

**Primary:**
- MinIO S3-compatible object storage (internally deployed)
  - Not a third-party service (self-hosted)
  - Buckets: `uploads`, `artifacts`

**Secondary:**
- None (no Dropbox, AWS S3, Google Cloud Storage integration)

## Sandbox/Execution Environment

**Execution Model:**
- Mock sandbox (for development)
- Configuration: `SANDBOX_ENABLED` and `SANDBOX_MOCK` env vars
- Used in: `worker/src/malscan_worker/stages/sandbox.py`
- Actual sandbox integration: Not yet implemented
- Mock returns fabricated behavior data for testing

## Environment Variables Summary

**Critical (no defaults):**
- `DATABASE_URL` - PostgreSQL connection
- `MINIO_ENDPOINT` - MinIO server address
- `MINIO_ACCESS_KEY` - MinIO credentials
- `MINIO_SECRET_KEY` - MinIO credentials
- `RABBITMQ_URL` - RabbitMQ broker connection

**Optional with defaults:**
- `MINIO_BUCKET_UPLOADS` (default: "uploads")
- `MINIO_BUCKET_ARTIFACTS` (default: "artifacts")
- `MINIO_SECURE` (default: false)
- `RABBITMQ_QUEUE` (default: "malscan.jobs")
- `CORS_ORIGINS` (default: "*")
- `LOG_LEVEL` (default: "INFO")
- `LOG_FORMAT` (default: "json")
- `MAX_FILE_SIZE` (default: 104857600)
- `STAGES_TOTAL` (default: 5)
- `STAGE_TIMEOUT_SECONDS` (default: 300)
- `YARA_RULES_PATH` (default: "/etc/yara/rules")
- `CLAMAV_HOST` (default: "clamav")
- `CLAMAV_PORT` (default: 3310)
- `SANDBOX_ENABLED` (default: true)
- `SANDBOX_MOCK` (default: true)
- `METRICS_PORT` (default: 9090)

---

*Integration audit: 2025-01-13*
