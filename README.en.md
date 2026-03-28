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
3. **Worker(s)** consume tasks from RabbitMQ, run ClamAV / YARA scans, and write analysis reports back to the database
4. **FastAPI Backend** provides job status queries and report retrieval APIs

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

## API Endpoints

| Method | Path | Service | Description |
|--------|------|---------|-------------|
| POST | `/api/v1/files` | Go Ingest Service | Upload a file for analysis |
| GET | `/api/v1/jobs/{job_id}` | FastAPI | Query analysis status |
| GET | `/api/v1/reports/{job_id}` | FastAPI | Retrieve analysis report |

---

## Tech Stack

- **Frontend:** React 18 + TypeScript + Vite
- **Ingest:** Go 1.25 + chi + pgx + minio-go + amqp091-go (file ingestion layer)
- **Backend:** FastAPI + SQLAlchemy + asyncpg
- **Worker:** Python + clamscan CLI + yara CLI
- **Reverse Proxy:** Nginx (routes requests to Ingest / Backend)
- **Queue:** RabbitMQ
- **Storage:** MinIO + Supabase PostgreSQL
- **Container Orchestration:** k3s + GHCR
- **CI/CD:** GitHub Actions

---

## License

MIT
