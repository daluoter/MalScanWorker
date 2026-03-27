# Codebase Structure

**Analysis Date:** 2025-03-27

## Directory Layout

```
MalScanWorker/
├── backend/                    # FastAPI backend service
│   ├── src/malscan/           # Main package
│   │   ├── api/               # Route handlers
│   │   ├── db/                # Database session and engine
│   │   ├── models/            # SQLAlchemy ORM models
│   │   ├── schemas/           # Pydantic request/response schemas
│   │   ├── main.py            # FastAPI app entry point
│   │   ├── config.py          # Settings from environment
│   │   ├── storage.py         # MinIO client and file operations
│   │   └── queue.py           # RabbitMQ publisher
│   ├── tests/                 # Pytest test suite
│   ├── alembic/               # Database migration configs
│   ├── pyproject.toml         # Poetry dependencies
│   ├── Dockerfile             # Container image definition
│   └── .env                   # Environment variables (not in git)
│
├── worker/                     # Job processing worker service
│   ├── src/malscan_worker/    # Main package
│   │   ├── stages/            # Analysis stages (plugins)
│   │   ├── utils/             # Helper utilities
│   │   ├── main.py            # Worker entry point
│   │   ├── config.py          # Settings from environment
│   │   ├── consumer.py        # RabbitMQ consumer with retry logic
│   │   ├── pipeline.py        # Pipeline orchestrator
│   │   ├── db.py              # Database helpers for worker
│   │   ├── storage.py         # MinIO file download
│   │   └── metrics.py         # Prometheus metrics
│   ├── rules/                 # YARA rule files
│   ├── tests/                 # Pytest test suite
│   ├── pyproject.toml         # Poetry dependencies
│   ├── Dockerfile             # Container image definition
│   └── .env                   # Environment variables (not in git)
│
├── frontend/                   # React/Vite web UI
│   ├── src/                   # TypeScript/TSX source
│   │   ├── pages/             # React page components
│   │   ├── api/               # API client
│   │   ├── styles/            # Tailwind CSS
│   │   ├── App.tsx            # Root app component
│   │   └── main.tsx           # React entry point
│   ├── public/                # Static assets
│   ├── index.html             # HTML template
│   ├── tsconfig.json          # TypeScript configuration
│   ├── vite.config.ts         # Vite build config
│   ├── package.json           # NPM dependencies
│   └── .env                   # Environment variables
│
├── k8s/                        # Kubernetes manifests
│   ├── api/                   # Backend deployment and service
│   ├── worker/                # Worker deployment
│   ├── minio/                 # MinIO PV/PVC and deployment
│   ├── rabbitmq/              # RabbitMQ PV/PVC and deployment
│   ├── yara-rules/            # ConfigMap for YARA rules
│   ├── namespace.yaml         # malscan namespace
│   └── configmap.yaml         # Shared configuration
│
├── docker-compose.yml         # Local development orchestration
├── README.md                  # Project documentation
└── openspec/                  # Design specifications and proposals
```

## Directory Purposes

**backend/src/malscan/:**
- Purpose: FastAPI REST API service for file upload and job management
- Contains: Route handlers, models, schemas, config, storage/queue clients
- Key files: `main.py` (entry point), `routes.py` (HTTP endpoints), `models/` (database schemas)

**backend/src/malscan/api/:**
- Purpose: HTTP route definitions
- Contains: `routes.py` with three main endpoints (upload, job status, reports)
- Pattern: Single router module included in main app

**backend/src/malscan/models/:**
- Purpose: SQLAlchemy ORM models defining database schema
- Contains: `base.py` (Base declarative), `file.py` (File model), `job.py` (Job model with sub-jobs)
- Pattern: Mapped relationships support hierarchical job tracking

**backend/src/malscan/schemas/:**
- Purpose: Pydantic models for request/response validation
- Contains: `requests.py` with response schemas (UploadResponse, JobStatusResponse, ReportResponse)
- Pattern: Single source of truth for API contracts

**backend/src/malscan/db/:**
- Purpose: Database connectivity and session management
- Contains: `engine.py` (AsyncEngine), `session.py` (SessionLocal factory), `__init__.py` (get_db dependency)
- Pattern: SQLAlchemy async with asyncpg driver

**backend/src/malscan/storage.py:**
- Purpose: MinIO file storage operations
- Contains: Singleton Minio client, bucket initialization, file upload/download wrappers
- Pattern: Thread pool executor for sync operations wrapped in async

**backend/src/malscan/queue.py:**
- Purpose: RabbitMQ job publication
- Contains: Singleton connection, channel, queue declaration, publish_job coroutine
- Pattern: aio_pika robust connection for automatic reconnection

**worker/src/malscan_worker/:**
- Purpose: Job consumer and analysis orchestrator
- Contains: Consumer, pipeline, stages, metrics, database helpers
- Key files: `main.py` (entry point), `consumer.py` (RabbitMQ consumer), `pipeline.py` (stage orchestrator)

**worker/src/malscan_worker/stages/:**
- Purpose: Modular analysis logic encapsulated as pluggable stages
- Contains: 7 stage implementations (FileType, ClamAV, YARA, IOC, Archive, Sandbox, + Base abstract)
- Pattern: Each stage is a class extending Stage with name property and async execute method

**worker/src/malscan_worker/stages/base.py:**
- Purpose: Stage interface and context/result dataclasses
- Contains: Stage ABC, StageContext, StageResult definitions
- Pattern: Used by all stages to define contract

**worker/src/malscan_worker/utils/:**
- Purpose: Helper utilities for pipeline execution
- Contains: `submission.py` (InternalJobSubmitter for sub-job creation)
- Pattern: Singleton connection pool for internal job publication

**worker/src/malscan_worker/consumer.py:**
- Purpose: RabbitMQ consumer with error handling and retry logic
- Contains: Message processing loop, retry count extraction, DLQ routing
- Pattern: Tenacity retry decorator for connection initialization

**worker/src/malscan_worker/pipeline.py:**
- Purpose: Orchestrate stages and build final analysis report
- Contains: PARALLEL_STAGES and SEQUENTIAL_STAGES lists, _run_stage(), run_pipeline()
- Pattern: Parallel execution via asyncio.gather(), sequential with for loop

**frontend/src/:**
- Purpose: React single-page application for user interaction
- Contains: Pages, API client, styles
- Pattern: React Router for client-side routing with GitHub Pages basename support

**frontend/src/pages/:**
- Purpose: Page-level components
- Contains: `UploadPage.tsx` (file input), `JobStatusPage.tsx` (polling/SSE), `ReportPage.tsx` (results display)
- Pattern: Each page is a separate component with state management via hooks

**frontend/src/api/client.ts:**
- Purpose: Centralized HTTP client with typed interfaces
- Contains: Fetch wrapper for all backend endpoints, error handling
- Pattern: Singleton instance with TypeScript interfaces for all API types

**k8s/:**
- Purpose: Kubernetes deployment manifests
- Contains: Namespaces, PVs/PVCs, Deployments for API/worker/MinIO/RabbitMQ, Services
- Pattern: Separated by component (api/, worker/, minio/, rabbitmq/)

**worker/rules/:**
- Purpose: YARA rule files for malware detection
- Contains: `.yar` or `.yara` rule files for pattern matching
- Pattern: Mounted as ConfigMap or volume in Kubernetes

## Key File Locations

**Entry Points:**
- `frontend/src/main.tsx`: React app mounting point
- `backend/src/malscan/main.py`: FastAPI application factory
- `worker/src/malscan_worker/main.py`: Worker startup with signal handling

**Configuration:**
- `backend/src/malscan/config.py`: Settings schema (DATABASE_URL, MINIO_*, RABBITMQ_URL, etc.)
- `worker/src/malscan_worker/config.py`: Worker-specific settings
- `.env` files: Environment variable storage (not committed)

**Core Logic:**
- `backend/src/malscan/api/routes.py`: HTTP endpoints (/files, /jobs/{id}, /reports/{id})
- `worker/src/malscan_worker/pipeline.py`: Pipeline orchestration (stage execution, result building)
- `worker/src/malscan_worker/consumer.py`: RabbitMQ message loop with retry handling

**Data Models:**
- `backend/src/malscan/models/job.py`: Job ORM with parent-child relationships
- `backend/src/malscan/models/file.py`: File ORM (SHA256-indexed deduplication)
- `frontend/src/api/client.ts`: TypeScript interfaces (UploadResponse, Report, etc.)

**Testing:**
- `backend/tests/`: Pytest fixtures and test modules
- `worker/tests/`: Pytest fixtures and test modules
- Pattern: pytest.ini or pyproject.toml defines test discovery

## Naming Conventions

**Files:**
- Python modules: `snake_case.py` (e.g., `archive_extract.py`, `job.py`)
- React components: `PascalCase.tsx` for pages, `camelCase.ts` for utilities (e.g., `UploadPage.tsx`, `client.ts`)
- YARA rules: `*.yar` or `*.yara` extension
- Database migrations: Alembic standard (`versions/XXXX_description.py`)

**Directories:**
- Python packages: `snake_case/` (e.g., `malscan_worker/`, `stages/`)
- React: lowercase (e.g., `pages/`, `api/`, `styles/`)
- Kubernetes: lowercase with hyphens (e.g., `api/`, `minio/`)

**Functions/Methods:**
- Python: `snake_case` (e.g., `upload_file()`, `get_job_status()`, `_sanitize_filename()`)
- TypeScript: `camelCase` (e.g., `getJobStatus()`, `uploadFile()`)
- Prefix private/internal functions with `_` (e.g., `_run_stage()`, `_cleanup_temp_dir()`)

**Classes:**
- Python: `PascalCase` (e.g., `Stage`, `ArchiveExtractStage`, `StageContext`)
- TypeScript: `PascalCase` (e.g., `ApiClient`, `JobStatusResponse`)

**Database:**
- Tables: plural lowercase (e.g., `jobs`, `files`)
- Columns: snake_case (e.g., `created_at`, `parent_job_id`, `stages_done`)
- Foreign keys: resource_id pattern (e.g., `file_id`, `parent_job_id`)

**Environment Variables:**
- UPPERCASE_WITH_UNDERSCORES (e.g., `DATABASE_URL`, `MINIO_ACCESS_KEY`, `RABBITMQ_URL`)

## Where to Add New Code

**New Feature - Analysis Stage:**
- Implementation: `worker/src/malscan_worker/stages/new_stage_name.py`
- Pattern: Create class extending `Stage`, implement `name` property and `async execute()` method
- Integration: Add instance to PARALLEL_STAGES or SEQUENTIAL_STAGES list in `worker/src/malscan_worker/pipeline.py`
- Testing: Create `worker/tests/test_new_stage_name.py` with pytest fixtures

**New Frontend Page:**
- Implementation: `frontend/src/pages/NewPage.tsx` as React functional component
- Styling: Add Tailwind classes to component or `frontend/src/styles/index.css`
- Routing: Add route in `frontend/src/App.tsx` Routes block
- API: Add client method to `frontend/src/api/client.ts` if needed

**New API Endpoint:**
- Implementation: Add route handler function in `backend/src/malscan/api/routes.py`
- Schema: Add Pydantic model in `backend/src/malscan/schemas/requests.py`
- Database: Add ORM model in `backend/src/malscan/models/` if new entity
- Testing: Create `backend/tests/test_endpoint_name.py`

**New Database Table:**
- ORM Model: Create class in `backend/src/malscan/models/entity_name.py` or add to existing model file
- Migration: Create Alembic migration via `alembic revision --autogenerate -m "description"`
- Relationships: Update related models' relationship definitions
- Indexes: Add to SQLAlchemy via `mapped_column(..., index=True)` for frequently queried fields

**Utility Function:**
- Shared helpers: `worker/src/malscan_worker/utils/function_name.py` (worker utilities)
- Storage ops: Extend `backend/src/malscan/storage.py` or `worker/src/malscan_worker/storage.py`
- Validation: Extend sanitization functions or config validators

**Configuration:**
- Backend: Add field to `Settings` class in `backend/src/malscan/config.py`
- Worker: Add field to Settings in `worker/src/malscan_worker/config.py`
- Environment: Document in `.env.example` and README.md deployment section

## Special Directories

**backend/tests/:**
- Purpose: Pytest test suite for backend
- Generated: No (committed fixtures and test modules)
- Committed: Yes
- Pattern: Test files named `test_*.py` or `*_test.py`

**worker/tests/:**
- Purpose: Pytest test suite for worker
- Generated: No (committed fixtures and test modules)
- Committed: Yes
- Pattern: Test files named `test_*.py` or `*_test.py`

**backend/.pytest_cache/**
- Purpose: Pytest cache artifacts
- Generated: Yes
- Committed: No (in .gitignore)

**worker/.pytest_cache/**
- Purpose: Pytest cache artifacts
- Generated: Yes
- Committed: No (in .gitignore)

**backend/alembic/versions/:**
- Purpose: Database migration files
- Generated: Yes (via `alembic revision --autogenerate`)
- Committed: Yes (migrations are source code)
- Pattern: Timestamp-prefixed SQL/Python migration scripts

**backend/.mypy_cache/, backend/.ruff_cache/**
- Purpose: Type checker and linter cache
- Generated: Yes
- Committed: No (in .gitignore)

**worker/.mypy_cache/, worker/.ruff_cache/**
- Purpose: Type checker and linter cache
- Generated: Yes
- Committed: No (in .gitignore)

**frontend/dist/:**
- Purpose: Built static assets (Vite output)
- Generated: Yes (via `npm run build`)
- Committed: No (in .gitignore)
- Deploy: GitHub Pages pulls from this directory

**frontend/node_modules/:**
- Purpose: NPM dependencies
- Generated: Yes (via `npm install`)
- Committed: No (in .gitignore)

**worker/rules/:**
- Purpose: YARA rule files
- Generated: No (manually maintained or updated)
- Committed: Yes
- Pattern: Organized by rule author/category with `.yar` extension

**k8s/**
- Purpose: Kubernetes manifests for production deployment
- Generated: No (manually maintained)
- Committed: Yes
- Pattern: Declarative YAML with separate files per resource type

---

*Structure analysis: 2025-03-27*
