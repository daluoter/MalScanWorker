# Technology Stack

**Analysis Date:** 2025-01-13

## Languages

**Primary:**
- Python 3.11 - Backend API server and worker pipeline
- TypeScript 5.2 - Frontend application
- JavaScript (Node.js) - Build tooling and frontend dev

**Secondary:**
- YAML - Kubernetes manifests, Docker Compose, configuration
- SQL - PostgreSQL database schemas (managed via SQLAlchemy ORM)

## Runtime

**Environment:**
- Python 3.11-slim (Docker image base)
- Node.js via npm (frontend build)

**Package Manager:**
- Poetry 1.8+ (Python dependency management)
  - Lockfile: `backend/poetry.lock` and `worker/poetry.lock`
  - Main config: `backend/pyproject.toml`, `worker/pyproject.toml`
- npm (JavaScript)
  - Lockfile: `frontend/package-lock.json`
  - Main config: `frontend/package.json`

## Frameworks

**Core:**
- FastAPI 0.104.0 - REST API framework for backend (`backend/src/malscan/main.py`)
- uvicorn 0.24.0 - ASGI server for FastAPI
- SQLAlchemy 2.0.0 (asyncio) - ORM for database operations (`backend/src/malscan/db/engine.py`)
- React 18.2.0 - Frontend UI framework
- Vite 5.0.0 - Frontend build tool and dev server

**Testing:**
- pytest 7.4.0 - Python test runner
- pytest-asyncio 0.21.0 - Async test support
- pytest-cov 4.1.0 - Coverage reporting
- pytest-mock 3.12.0 - Mocking utilities

**Build/Dev:**
- TypeScript 5.2.2 - Type checking for frontend
- Tailwind CSS 3.4.0 - Utility-first CSS framework
- PostCSS 8.4.32 - CSS transformation
- ESLint 8.53.0 - JavaScript/TypeScript linting
- Vite TypeScript plugin (@vitejs/plugin-react 4.2.0) - JSX support
- black 23.11.0 - Python code formatter
- ruff 0.1.0 - Python linter
- mypy 1.7.0 - Python type checker
- isort 5.12.0 - Python import sorter

**Code Quality:**
- structlog 23.2.0 - Structured logging for Python (JSON output)
- prometheus-fastapi-instrumentator 6.1.0 - Metrics collection for FastAPI
- prometheus-client 0.19.0 - Prometheus metrics for worker

## Key Dependencies

**Critical:**

- aio-pika 9.3.0 - RabbitMQ async client for message queuing
  - Used in: `backend/src/malscan/queue.py`, `worker/src/malscan_worker/consumer.py`
  - Purpose: Publisher-subscriber pattern for job distribution

- minio 7.2.0 - S3-compatible object storage client
  - Used in: `backend/src/malscan/storage.py`, `worker/src/malscan_worker/storage.py`
  - Purpose: File upload/download for malware samples and artifacts

- asyncpg 0.29.0 - PostgreSQL async driver
  - Used in: `backend/src/malscan/db/engine.py`
  - Purpose: Efficient async database connections

- pydantic 2.5.0 + pydantic-settings 2.1.0 - Data validation and settings management
  - Used in: `backend/src/malscan/config.py`, `worker/src/malscan_worker/config.py`
  - Purpose: Environment variable parsing and validation

- tenacity 8.2.0 - Retry library with exponential backoff
  - Used in: `backend/src/malscan/queue.py`, `worker/src/malscan_worker/consumer.py`
  - Purpose: Resilient RabbitMQ publishing and message processing

**Infrastructure:**

- python-magic 0.4.27 - File type detection
  - Used in: `worker/src/malscan_worker/stages/filetype.py`
  - Purpose: Determine MIME type and file classification

- yara-python 4.5.4 - YARA malware rule engine binding
  - Used in: `worker/src/malscan_worker/stages/yara_scan.py`
  - Purpose: Pattern-based malware detection

- pyclamd 0.4.0 - ClamAV network socket client
  - Used in: `worker/src/malscan_worker/stages/clamav.py`
  - Purpose: Connect to ClamAV daemon for AV scanning

- py7zr 0.22.0 - 7z archive extraction
  - Used in: `worker/src/malscan_worker/stages/archive_extract.py`
  - Purpose: Extract 7z archives for nested malware analysis

- rarfile 4.2 - RAR archive handling
  - Used in: `worker/src/malscan_worker/stages/archive_extract.py`
  - Purpose: Extract RAR archives for nested malware analysis

- aiohttp 3.9.0 - HTTP client for async operations
  - Used in: `worker/src/malscan_worker/metrics.py`
  - Purpose: Run aiohttp web server for Prometheus metrics endpoint

- sse-starlette 1.1.5 - Server-Sent Events for Starlette/FastAPI
  - Used in: `backend/src/malscan/api/routes.py`
  - Purpose: Real-time job progress streaming to frontend

- alembic 1.13.0 - Database migration tool
  - Config: `backend/alembic.ini`
  - Purpose: Manage schema versioning (optional, currently using auto-create)

- python-multipart 0.0.7 - Multipart form parsing for file uploads
  - Used in: FastAPI file upload endpoint
  - Purpose: Handle streaming file uploads

## Configuration

**Environment:**
- Configuration loaded from `.env` files using Pydantic Settings
- Backend config: `backend/src/malscan/config.py`
- Worker config: `worker/src/malscan_worker/config.py`
- Example: `.env.example` at repository root

**Required Environment Variables:**
- `DATABASE_URL` - PostgreSQL connection string (asyncpg driver)
- `MINIO_ENDPOINT` - MinIO server address
- `MINIO_ACCESS_KEY` - MinIO authentication
- `MINIO_SECRET_KEY` - MinIO authentication
- `RABBITMQ_URL` - RabbitMQ broker URL (AMQP protocol)

**Optional Environment Variables:**
- `CORS_ORIGINS` - CORS-allowed origins (default: "*")
- `LOG_LEVEL` - Logging level (default: "INFO")
- `LOG_FORMAT` - Log format, "json" for structured logging (default: "json")
- `MAX_FILE_SIZE` - Max upload size in bytes (default: 104857600 = 100MB)
- `STAGES_TOTAL` - Number of pipeline stages (default: 5)
- `CLAMAV_HOST` - ClamAV daemon host (default: "clamav")
- `CLAMAV_PORT` - ClamAV daemon port (default: 3310)
- `SANDBOX_ENABLED` - Enable sandbox analysis (default: true)
- `SANDBOX_MOCK` - Use mock sandbox (default: true)
- `METRICS_PORT` - Prometheus metrics port (default: 9090)
- `YARA_RULES_PATH` - Directory containing YARA rule files (default: "/etc/yara/rules")

**Build:**
- Frontend: `frontend/vite.config.ts` - Vite configuration
- Frontend: `frontend/tsconfig.json` - TypeScript configuration
- Frontend: `frontend/.eslintrc.cjs` - ESLint configuration
- Backend: `backend/pyproject.toml` - Poetry configuration with tool settings
- Backend: `backend/poetry.lock` - Dependency lock file

**Build Artifacts:**
- Frontend dist: `frontend/dist/` (static HTML/JS/CSS)
- Backend container: Dockerfile in `backend/`
- Worker container: Dockerfile in `worker/`

## Platform Requirements

**Development:**
- Python 3.11+
- Node.js 16+
- Docker & Docker Compose (for local infrastructure)
- Poetry (Python dependency manager)
- npm (Node package manager)

**Production:**
- Docker container runtime
- Kubernetes 1.25+ (via k3s)
- PostgreSQL 13+ database
- RabbitMQ 3.x message broker
- MinIO S3-compatible object storage
- ClamAV virus scanner daemon
- YARA malware detection engine
- Linux kernel (tested on Ubuntu 22.04)

**Infrastructure (docker-compose):**
- postgres:15
- minio/minio:latest
- rabbitmq:3-management
- clamav/clamav:latest
- Python 3.11-slim container images

## Container Images

**Generated by CI/CD:**
- Backend: `ghcr.io/{OWNER}/malscan-api:latest`
- Worker: `ghcr.io/{OWNER}/malscan-worker:latest`
- Frontend: Deployed to GitHub Pages (static)

**Image Registries:**
- GitHub Container Registry (GHCR) for Python services
- GitHub Pages for static frontend

---

*Stack analysis: 2025-01-13*
