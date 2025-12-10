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

- VirtualBox + Ubuntu Server VM（用於 k3s）
- [Supabase](https://supabase.com/) 專案（免費方案即可）
- GitHub 帳號（用於 GHCR 和 GitHub Pages）

---

## 完整部署步驟

### 1. Fork/Clone 專案

```bash
git clone https://github.com/YOUR_USERNAME/MalScanWorker.git
cd MalScanWorker
```

### 2. 設定 GitHub Repository

#### 2.1 啟用 GitHub Pages
1. 前往 repo **Settings** → **Pages**
2. **Source** 選擇 **GitHub Actions**

#### 2.2 設定 Repository Variables
前往 **Settings** → **Secrets and variables** → **Actions** → **Variables**

新增以下變數：
| 變數名稱 | 值範例 |
|----------|--------|
| `API_BASE_URL` | `http://YOUR_VM_IP:30080` |

### 3. 設定 k3s 環境（VM 內）

```bash
# 安裝 k3s
curl -sfL https://get.k3s.io | sh -

# 驗證安裝
sudo kubectl get nodes
```

### 4. 建立 Docker Images

專案已配置 GitHub Actions 自動建構並推送到 GHCR。
你只需要確保 CI/CD 通過，images 會自動建立在：
- `ghcr.io/YOUR_USERNAME/malscan-api:latest`
- `ghcr.io/YOUR_USERNAME/malscan-worker:latest`

#### 手動建構（可選）
```bash
# Backend API
cd backend
docker build -t ghcr.io/YOUR_USERNAME/malscan-api:latest .
docker push ghcr.io/YOUR_USERNAME/malscan-api:latest

# Worker
cd ../worker
docker build -t ghcr.io/YOUR_USERNAME/malscan-worker:latest .
docker push ghcr.io/YOUR_USERNAME/malscan-worker:latest
```

### 5. 部署到 k3s

#### 5.1 建立 Namespace
```bash
sudo kubectl apply -f k8s/namespace.yaml
```

#### 5.2 建立 Secrets
```bash
sudo kubectl create secret generic malscan-secrets \
  --namespace=malscan \
  --from-literal=DATABASE_URL="postgresql://postgres:YOUR_PASSWORD@YOUR_SUPABASE_HOST:5432/postgres" \
  --from-literal=MINIO_ACCESS_KEY="minioadmin" \
  --from-literal=MINIO_SECRET_KEY="YOUR_MINIO_SECRET" \
  --from-literal=RABBITMQ_URL="amqp://guest:guest@rabbitmq:5672/"
```

#### 5.3 修改 k8s manifests（替換 OWNER）
編輯以下檔案，將 `OWNER` 替換為你的 GitHub 帳號：
- `k8s/api/deployment.yaml`
- `k8s/worker/deployment.yaml`

```bash
# 使用 sed 批次替換
sed -i 's/OWNER/YOUR_USERNAME/g' k8s/api/deployment.yaml
sed -i 's/OWNER/YOUR_USERNAME/g' k8s/worker/deployment.yaml
```

#### 5.4 部署所有資源
```bash
sudo kubectl apply -f k8s/configmap.yaml
sudo kubectl apply -f k8s/minio/
sudo kubectl apply -f k8s/rabbitmq/
sudo kubectl apply -f k8s/yara-rules/
sudo kubectl apply -f k8s/api/
sudo kubectl apply -f k8s/worker/
```

#### 5.5 驗證部署
```bash
sudo kubectl get pods -n malscan
sudo kubectl get svc -n malscan
```

### 6. 存取服務

| 服務 | URL |
|------|-----|
| 前端 | https://YOUR_USERNAME.github.io/MalScanWorker/ |
| API | http://VM_IP:30080 |
| MinIO Console | http://VM_IP:NodePort (查 `kubectl get svc`) |
| RabbitMQ Management | http://VM_IP:NodePort |

---

## 本機開發

### 前端
```bash
cd frontend
npm install
npm run dev
```

### 後端
```bash
cd backend
poetry install
poetry run uvicorn malscan.main:app --reload
```

### Worker
```bash
cd worker
poetry install
poetry run python -m malscan_worker.main
```

### Docker Compose（本機環境）
```bash
docker-compose up -d
```

---

## API 端點

| 方法 | 路徑 | 說明 |
|------|------|------|
| POST | `/api/v1/files` | 上傳檔案進行分析 |
| GET | `/api/v1/jobs/{job_id}` | 查詢分析狀態 |
| GET | `/api/v1/reports/{job_id}` | 取得分析報告 |

---

## 技術棧

- **前端:** React 18 + TypeScript + Vite
- **後端:** FastAPI + SQLAlchemy + asyncpg
- **Worker:** Python + clamscan CLI + yara CLI
- **佇列:** RabbitMQ
- **儲存:** MinIO + Supabase PostgreSQL
- **容器:** k3s + GHCR
- **CI/CD:** GitHub Actions

---

## License

MIT
