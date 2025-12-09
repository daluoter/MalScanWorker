# MalScanWorker

惡意附件分析 Pipeline 系統

## 架構

```
User → GitHub Pages (React) → FastAPI → MinIO + Supabase + RabbitMQ
                                              ↓
                                         Worker(s) ← clamscan/yara CLI
                                              ↓
                                         Supabase (reports)
```

## 快速開始

### 前置需求

- VirtualBox + Ubuntu Server VM
- k3s
- Supabase 專案

### 本機開發

```bash
# 前端
cd frontend && npm install && npm run dev

# 後端 (需要 Poetry)
cd backend && poetry install && poetry run uvicorn malscan.main:app --reload

# Worker
cd worker && poetry install && poetry run python -m malscan_worker.main
```

### 部署

```bash
# 建立 namespace
kubectl apply -f k8s/namespace.yaml

# 建立 secrets (手動填入真實值)
kubectl create secret generic malscan-secrets \
  --namespace=malscan \
  --from-literal=DATABASE_URL="..." \
  --from-literal=MINIO_ACCESS_KEY="..." \
  --from-literal=MINIO_SECRET_KEY="..." \
  --from-literal=RABBITMQ_URL="..."

# 部署
kubectl apply -f k8s/
```

## API

- `POST /api/v1/files` - 上傳檔案
- `GET /api/v1/jobs/{job_id}` - 查詢狀態
- `GET /api/v1/reports/{job_id}` - 取得報告

## 技術棧

- **前端:** React 18 + TypeScript + Vite
- **後端:** FastAPI + SQLAlchemy + asyncpg
- **Worker:** Python + clamscan CLI + yara CLI
- **佇列:** RabbitMQ
- **儲存:** MinIO + Supabase PostgreSQL
- **部署:** k3s + GitHub Actions

## License

MIT
