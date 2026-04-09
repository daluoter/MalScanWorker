English | [繁體中文](README.md)

# MalScanWorker

Malware Attachment Analysis Pipeline

## Architecture

```
User → GitHub Pages (React) → Nginx Reverse Proxy
                                    │
                         ┌──────────┴──────────┐
                         │                      │
                   POST /api/v1/files    GET /api/v1/**
                         │                      │
                         ▼                      ▼
                Go Ingest Service         FastAPI (Backend)
              (chi + pgx + minio-go        (SQLAlchemy + asyncpg)
               + amqp091-go)                    │
                    │                           │
          ┌─────────┼─────────┐                 │
          ▼         ▼         ▼                 │
       MinIO   PostgreSQL  RabbitMQ             │
      (files)   (metadata)    │                 │
                              ▼                 │
                         Worker(s) ◄────────────┘
                      clamscan / yara CLI
                              │
                              ▼
                     Supabase PostgreSQL
                         (reports)
```

**Data Flow:**
1. Users upload files through the frontend → Nginx routes requests based on path
2. **Go Ingest Service** handles file uploads: stores files in MinIO, writes job metadata to PostgreSQL, and publishes tasks to RabbitMQ
3. **Worker(s)** consume tasks from RabbitMQ, run ClamAV / YARA / format-analysis / deobfuscation and related stages, compute direct/local artifact risk, and write reports back to the database
4. **FastAPI Backend** provides job status queries and report retrieval APIs, and applies descendant tree-aware risk rollup when `/reports/{job_id}` is read

## Quick Start

### Prerequisites

- VirtualBox + Ubuntu Server VM (for k3s)
- A [Supabase](https://supabase.com/) project (free tier works fine)
- GitHub account (for GHCR and GitHub Pages)

> ⚠️ **VirtualBox Network Configuration**
>
> VirtualBox defaults to NAT mode, which prevents external access to the VM (including `http://VM_IP:30080`).
>
> **Solution:** Switch the VirtualBox network adapter to **Bridged Adapter**
>
> Steps: VM Settings → Network → Adapter 1 → Attached to: select "Bridged Adapter"

---

## Full Deployment Steps

### 1. Fork/Clone the Project

```bash
git clone https://github.com/YOUR_USERNAME/MalScanWorker.git
cd MalScanWorker
```

### 2. Configure GitHub Repository

#### 2.1 Enable GitHub Pages
1. Go to repo **Settings** → **Pages**
2. Set **Source** to **GitHub Actions**

#### 2.2 Set Repository Variables
Go to **Settings** → **Secrets and variables** → **Actions** → **Variables**

Add the following variable:
| Variable Name | Example Value |
|---------------|---------------|
| `API_BASE_URL` | `http://YOUR_VM_IP:30080` |

### 3. Set Up k3s Environment (Inside VM)

```bash
# Install k3s
curl -sfL https://get.k3s.io | sh -

# Verify installation
sudo kubectl get nodes
```

### 4. Build Docker Images

The project includes GitHub Actions workflows that automatically build and push to GHCR.
Just make sure CI/CD passes — images will be created at:
- `ghcr.io/YOUR_USERNAME/malscan-api:latest`
- `ghcr.io/YOUR_USERNAME/malscan-worker:latest`
- `ghcr.io/YOUR_USERNAME/malscan-ingest:latest`

#### Manual Build (Optional)
```bash
# Backend API
cd backend
docker build -t ghcr.io/YOUR_USERNAME/malscan-api:latest .
docker push ghcr.io/YOUR_USERNAME/malscan-api:latest

# Worker
cd ../worker
docker build -t ghcr.io/YOUR_USERNAME/malscan-worker:latest .
docker push ghcr.io/YOUR_USERNAME/malscan-worker:latest

# Ingest (Go)
cd ../ingest
docker build -t ghcr.io/YOUR_USERNAME/malscan-ingest:latest .
docker push ghcr.io/YOUR_USERNAME/malscan-ingest:latest
```

### 5. Deploy to k3s

#### 5.1 Create Namespace
```bash
sudo kubectl apply -f k8s/namespace.yaml
```

#### 5.2 Create Secrets
```bash
sudo kubectl create secret generic malscan-secrets \
  --namespace=malscan \
  --from-literal=DATABASE_URL="postgresql://postgres:YOUR_PASSWORD@YOUR_SUPABASE_HOST:5432/postgres" \
  --from-literal=MINIO_ACCESS_KEY="minioadmin" \
  --from-literal=MINIO_SECRET_KEY="YOUR_MINIO_SECRET" \
  --from-literal=RABBITMQ_URL="amqp://guest:guest@rabbitmq:5672/"
```

#### 5.3 Create Data Directories (On k3s Node)
```bash
# MinIO and RabbitMQ require persistent storage
sudo mkdir -p /data/malscan/minio
sudo mkdir -p /data/malscan/rabbitmq
sudo chmod 777 /data/malscan/minio /data/malscan/rabbitmq
```

#### 5.4 Update k8s Manifests (Replace OWNER)
Edit the following files and replace `OWNER` with your GitHub username:
- `k8s/api/deployment.yaml`
- `k8s/worker/deployment.yaml`
- `k8s/ingest/deployment.yaml`

```bash
# Batch replace using sed
sed -i 's/OWNER/YOUR_USERNAME/g' k8s/api/deployment.yaml
sed -i 's/OWNER/YOUR_USERNAME/g' k8s/worker/deployment.yaml
sed -i 's/OWNER/YOUR_USERNAME/g' k8s/ingest/deployment.yaml
```

#### 5.5 Deploy All Resources
```bash
# 1. Create namespace and configmap
sudo kubectl apply -f k8s/namespace.yaml
sudo kubectl apply -f k8s/configmap.yaml

# 2. Create PersistentVolumes (must be created before namespace resources)
sudo kubectl apply -f k8s/minio/pv.yaml
sudo kubectl apply -f k8s/rabbitmq/pv.yaml

# 3. Deploy infrastructure services
sudo kubectl apply -f k8s/minio/pvc.yaml
sudo kubectl apply -f k8s/minio/deployment.yaml
sudo kubectl apply -f k8s/rabbitmq/pvc.yaml
sudo kubectl apply -f k8s/rabbitmq/deployment.yaml

# 4. Deploy application services
sudo kubectl apply -f k8s/yara-rules/
sudo kubectl apply -f k8s/ingest/
sudo kubectl apply -f k8s/api/
sudo kubectl apply -f k8s/worker/
sudo kubectl apply -f k8s/nginx/
```

#### 5.6 Verify Deployment
```bash
sudo kubectl get pods -n malscan
sudo kubectl get svc -n malscan
```

### 6. Access Services

| Service | URL |
|---------|-----|
| Frontend | https://YOUR_USERNAME.github.io/MalScanWorker/ |
| API | http://VM_IP:30080 |
| MinIO Console | http://VM_IP:NodePort (check `kubectl get svc`) |
| RabbitMQ Management | http://VM_IP:NodePort |

### 7. Connect Frontend and Backend with Cloudflare Tunnel

> ⚠️ **Why is this needed?**
>
> GitHub Pages is served over HTTPS, and browser security policies (Mixed Content) block requests from HTTPS pages to HTTP APIs.
> Cloudflare Tunnel provides a free HTTPS endpoint for your VM API.

#### 7.1 Install cloudflared (Inside VM)

```bash
# Debian/Ubuntu
curl -L --output cloudflared.deb https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb
sudo dpkg -i cloudflared.deb

# Or via snap
sudo snap install cloudflared
```

#### 7.2 Start a Quick Tunnel

```bash
# Replace 30080 with your API NodePort
sudo cloudflared tunnel --url http://localhost:30080
```

On success, you'll see a public URL like:
```
Your quick Tunnel has been created! Visit it at:
https://random-words-here.trycloudflare.com
```

> 💡 **Note:** Quick Tunnel URLs change on every restart. For a permanent URL, see [Named Tunnels](https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/).

#### 7.3 Update GitHub Repository Variables

1. Go to repo **Settings** → **Secrets and variables** → **Actions** → **Variables**
2. Edit the `API_BASE_URL` variable and set it to the Cloudflare Tunnel HTTPS URL:
   ```
   https://random-words-here.trycloudflare.com
   ```
   > ⚠️ **Note:** Do **not** add a trailing slash `/` to the URL

#### 7.4 Redeploy the Frontend

Trigger a GitHub Pages redeployment (either method):
- Push any commit to the `main` branch
- Go to **Actions** → **Frontend Deploy** → **Run workflow**

#### 7.5 Verify Connectivity

1. Open https://YOUR_USERNAME.github.io/MalScanWorker/
2. Upload a test file
3. You should see a successful upload and be taken to the analysis progress page

> 🔍 **Debugging Tip:** If something goes wrong, open browser DevTools (F12) → Network tab and inspect the API request URLs and responses.

---

## Local Development

During development, you need two parts:
1. **Infrastructure:** PostgreSQL, MinIO, RabbitMQ, ClamAV
2. **Application:** Frontend, Ingest Service, Backend API, Worker

> ⚠️ **Avoid the "Ghost Consumer" Problem**
>
> If you plan to run the Worker locally with `poetry run` for development/debugging, **never** start all services with `docker compose up -d`!
> The `docker-compose.yml` includes a `worker` service — if both run simultaneously, RabbitMQ will have two consumers, and some tasks may be grabbed by the outdated Docker worker, leading to incorrect analysis results.
>
> **The right approach:** Only start infrastructure containers, then manually start the application services locally.

### 1. Start Infrastructure (PostgreSQL, MinIO, RabbitMQ, ClamAV)

From the project root, start only the required infrastructure — **do not** start the API, Ingest, or Worker:

```bash
docker compose up -d postgres minio rabbitmq clamav
```

### 2. Set Environment Variables (`.env`)

The backend and worker need to connect to the locally running infrastructure. Create the corresponding `.env` files:

#### Backend (`backend/.env`)
```bash
cd backend
cat <<EOF > .env
DATABASE_URL=postgresql+asyncpg://postgres:postgres@localhost:5432/malscan
MINIO_ENDPOINT=localhost:9000
MINIO_ACCESS_KEY=minioadmin
MINIO_SECRET_KEY=minioadmin
RABBITMQ_URL=amqp://guest:guest@localhost:5672/
EOF
```

#### Worker (`worker/.env`)
```bash
cd ../worker
cat <<EOF > .env
DATABASE_URL=postgresql+asyncpg://postgres:postgres@localhost:5432/malscan
MINIO_ENDPOINT=localhost:9000
MINIO_ACCESS_KEY=minioadmin
MINIO_SECRET_KEY=minioadmin
RABBITMQ_URL=amqp://guest:guest@localhost:5672/
CLAMAV_HOST=localhost
CLAMAV_PORT=3310
SANDBOX_MOCK=true
EOF
```

#### Ingest (`ingest/.env`)
```bash
cd ../ingest
cat <<EOF > .env
LISTEN_ADDR=:8080
DATABASE_URL=postgres://postgres:postgres@localhost:5432/malscan?sslmode=disable
MINIO_ENDPOINT=localhost:9000
MINIO_ACCESS_KEY=minioadmin
MINIO_SECRET_KEY=minioadmin
MINIO_USE_SSL=false
MINIO_BUCKET=uploads
RABBITMQ_URL=amqp://guest:guest@localhost:5672/
EOF
```

> 💡 Database tables are automatically created when the backend and worker start — no manual migrations needed.

### 3. Start the Frontend
```bash
cd frontend
npm install
npm run dev
```

### 4. Start the Ingest Service (Go)
```bash
cd ingest
go run ./cmd/ingest
```

### 5. Start the Backend
```bash
cd backend
poetry install
poetry run uvicorn malscan.main:app --reload
```

### 6. Start the Worker
```bash
cd worker
poetry install
poetry run python -m malscan_worker.main
```

### 📦 Test the Full Containerized Environment (Docker Compose)

If you've finished development and want to test the entire system in a **fully containerized** setup:

1. **Make sure to stop** all locally running `poetry run` and `go run` processes (API, Ingest, and Worker) to avoid connection or consumer conflicts.
2. Run the following command to force-rebuild any modified Worker, API, and Ingest images, ensuring containers use the latest code:

```bash
# From the project root
docker compose up -d --build
```

---

## Password-Protected and Recursive Archive Analysis

When an uploaded archive requires a password, the system enters a password flow first; after successful unlock, recursive extraction and descendant analysis begin.

### Supported Formats
- **Archive:** ZIP, 7z, RAR, TAR, GZIP, BZ2
- **ISO:** currently a stub (planned, not actively extracted yet)

### Supported Encryption Methods
- **ZIP:** ZipCrypto / AES-256 (WZ_AES)
- **7z:** AES-256
- **RAR:** AES-128 / AES-256

### Workflow
1. Upload a password-protected archive → system auto-detects and sets `password_required`
2. Submit password on the job status page → system retries extraction and resumes analysis
3. After successful unlock, the worker creates artifact lineage records and dispatches recursive sub-jobs
4. If dedup finds an existing DB file row but MinIO object has expired, the worker auto re-uploads to avoid sub-job `NoSuchKey`
5. Up to **3** password attempts are allowed
   - Correct password: extraction succeeds and inner files are analyzed
   - 3 wrong attempts: final report is generated with explicit extraction-failed notice

### Report and Navigation Behavior
- Parent report is shown only after the full descendant job tree reaches terminal states
  - If descendants are still running, `GET /api/v1/reports/{job_id}` returns `409`
  - Frontend displays a waiting state and polls until report is ready
  - The final `score`, `risk_level`, and `risk` block reflect the full artifact-tree rollup, not just the root file's local scan
- Successful extraction: report includes archive extraction info (file count, sub-jobs, total extracted size)
- Failed extraction: report shows a red extraction-failed banner
- If the password is wrong 3 times, the final report keeps `verdict = "unknown"` and returns a conservative zeroed `risk` block instead of mislabeling the file as `clean`
- Child Job/Report pages include a "back to parent analysis" entry

---

## Format-Specific Analyzer Architecture (Phase 1)

The worker now includes a dedicated `format-analysis` stage to add deep, format-specific visibility beyond generic static scanning (ClamAV/YARA/regex IOC).

### What `AnalyzerRegistry` is

`AnalyzerRegistry` is a first-match dispatch registry for pluggable analyzers:

- Uses MIME (from `file-type`) plus magic bytes
- Selects the first analyzer that can handle the file
- Provides deterministic ordering and incremental extensibility

Current default order:

1. `PEAnalyzer`
2. `OfficeAnalyzerAdapter`
3. `PDFAnalyzer`
4. `LNKAnalyzer`
5. `ScriptAnalyzer`

### Formats supported in this phase

- PE (EXE/DLL)
- Office (RTF/OLE/OOXML)
- PDF
- LNK
- Script (PowerShell / JavaScript / VBScript / Batch / HTA)

### How `DocumentAnalysisStage` is integrated

The existing `DocumentAnalysisStage` was intentionally not rewritten yet.
Instead, it is integrated through an adapter/shim (`OfficeAnalyzerAdapter`):

- Reuses current Office parsing and exploit detection internals
- Maps legacy findings into unified `AnalyzerResult`
- Lets Office participate in shared format-analysis scoring/reporting

### Behavior/config changes in this phase

- Pipeline order now includes `format-analysis` between parallel static stages and later sequential stages.
- Reports now include `results.format_analysis`.
- `results.document_analysis` remains for backward compatibility.
- Format analysis can submit extracted artifacts as sub-jobs.
- Recursive submission in this stage now enforces max-depth guardrails.

### Intentionally not included yet

- Full internal decomposition/rewrite of `DocumentAnalysisStage` as a native Office analyzer
- PDF JavaScript emulation/deobfuscation
- Full LNK extra-data ecosystem parsing
- Script AST/symbolic execution-level analysis
- Cross-format chain correlation (e.g., LNK -> script -> downloader)

### Limitations and follow-up work

- Some parser dependencies are optional and fall back gracefully when unavailable.
- Indicator logic is heuristic-oriented and designed for explainability; precision tuning continues.
- Deeper format semantics, cross-format correlation, and threat-intel enrichment are planned follow-ups.

---

## Multi-Signal Risk Scoring and Report Fields

The system now uses evidence-driven multi-signal risk scoring instead of the earlier thin `verdict/score` logic.

### Risk Calculation Flow

- The worker computes only direct/local risk for the current artifact when a job finishes
- The backend recomputes canonical tree-aware risk on `GET /api/v1/reports/{job_id}` after all descendants are complete
- This prevents parent reports from going stale when risky child artifacts finish later

### Main Signal Sources

- ClamAV signatures
- YARA metadata-based classification
- raw IOC extraction
- structured `format-analysis` indicators
- deobfuscation evidence
- sandbox behaviors
- descendant inheritance from the artifact tree

### Compatibility Fields

- Top-level `verdict` is retained as the legacy compatibility field
- Top-level `score` remains a legacy-compatible alias of final `risk_score`
- Compatibility mapping:
  - `clean -> clean`
  - `low / medium / high -> suspicious`
  - `malicious -> malicious`

### New Risk Fields

- Top-level `risk_level`: `clean | low | medium | high | malicious`
- Top-level `risk` block includes:
  - `policy_version`
  - `risk_score`
  - `risk_level`
  - `legacy_verdict`
  - `malicious_gate_open`
  - `high_gate_open`
  - `independent_source_count`
  - `breakdown`
  - `evidence`
  - `top_evidence`
  - `descendant_summary`

### Artifact Tree Risk Fields

- `artifact_tree` nodes now expose:
  - `verdict`
  - `score`
  - `risk_level`
  - `policy_version`
- The root `artifact_tree` node is kept consistent with the final top-level rolled-up report risk so clients do not see conflicting root-artifact severity in the same payload

---

## API Endpoints

| Method | Path | Service | Description |
|--------|------|---------|-------------|
| POST | `/api/v1/files` | Go Ingest Service | Upload a file for analysis |
| GET | `/api/v1/jobs/{job_id}` | FastAPI | Query analysis status |
| POST | `/api/v1/jobs/{job_id}/password` | FastAPI | Submit archive password (max 3 attempts) |
| GET | `/api/v1/reports/{job_id}` | FastAPI | Retrieve the final tree-aware analysis report, including `risk`, `risk_level`, and the artifact tree |

---

## Tech Stack

- **Frontend:** React 18 + TypeScript + Vite
- **Ingest:** Go 1.25 + chi + pgx + minio-go + amqp091-go (file ingestion layer)
- **Backend:** FastAPI + SQLAlchemy + asyncpg
- **Worker:** Python + clamscan CLI + yara CLI + pyzipper (AES ZIP) + py7zr + rarfile
- **Reverse Proxy:** Nginx (routes requests to Ingest / Backend)
- **Queue:** RabbitMQ
- **Storage:** MinIO + Supabase PostgreSQL
- **Container Orchestration:** k3s + GHCR
- **CI/CD:** GitHub Actions

---

## License

MIT
