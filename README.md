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

> ⚠️ **VirtualBox 網路設定注意事項**
>
> VirtualBox 預設使用 NAT 模式，這會導致外部無法連線到 VM（包括 `http://VM_IP:30080`）。
>
> **解決方法：** 將 VirtualBox 網路介面卡改為「**Bridged Adapter（橋接介面卡）**」
>
> 設定步驟：VM 設定 → 網路 → 介面卡 1 → 附加到：選擇「Bridged Adapter」

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

#### 5.3 建立資料目錄（在 k3s 節點上）
```bash
# MinIO 和 RabbitMQ 需要持久化儲存
sudo mkdir -p /data/malscan/minio
sudo mkdir -p /data/malscan/rabbitmq
sudo chmod 777 /data/malscan/minio /data/malscan/rabbitmq
```

#### 5.4 修改 k8s manifests（替換 OWNER）
編輯以下檔案，將 `OWNER` 替換為你的 GitHub 帳號：
- `k8s/api/deployment.yaml`
- `k8s/worker/deployment.yaml`

```bash
# 使用 sed 批次替換
sed -i 's/OWNER/YOUR_USERNAME/g' k8s/api/deployment.yaml
sed -i 's/OWNER/YOUR_USERNAME/g' k8s/worker/deployment.yaml
```

#### 5.5 部署所有資源
```bash
# 1. 建立 namespace 和 configmap
sudo kubectl apply -f k8s/namespace.yaml
sudo kubectl apply -f k8s/configmap.yaml

# 2. 建立 PersistentVolume（需要在 namespace 建立前）
sudo kubectl apply -f k8s/minio/pv.yaml
sudo kubectl apply -f k8s/rabbitmq/pv.yaml

# 3. 部署基礎服務
sudo kubectl apply -f k8s/minio/pvc.yaml
sudo kubectl apply -f k8s/minio/deployment.yaml
sudo kubectl apply -f k8s/rabbitmq/pvc.yaml
sudo kubectl apply -f k8s/rabbitmq/deployment.yaml

# 4. 部署應用服務
sudo kubectl apply -f k8s/yara-rules/
sudo kubectl apply -f k8s/api/
sudo kubectl apply -f k8s/worker/
```

#### 5.6 驗證部署
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

### 7. 使用 Cloudflare Tunnel 連通前後端

> ⚠️ **為什麼需要這個？**
>
> GitHub Pages 使用 HTTPS，而瀏覽器的安全策略（Mixed Content）會阻止從 HTTPS 頁面向 HTTP API 發送請求。
> 使用 Cloudflare Tunnel 可以免費為你的 VM API 提供 HTTPS 端點。

#### 7.1 安裝 cloudflared（在 VM 內）

```bash
# Debian/Ubuntu
curl -L --output cloudflared.deb https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb
sudo dpkg -i cloudflared.deb

# 或使用 snap
sudo snap install cloudflared
```

#### 7.2 啟動 Quick Tunnel

```bash
# 將 30080 替換為你的 API NodePort
sudo cloudflared tunnel --url http://localhost:30080
```

成功後會顯示類似以下的公開 URL：
```
Your quick Tunnel has been created! Visit it at:
https://random-words-here.trycloudflare.com
```

> 💡 **注意：** Quick Tunnel 每次重啟 URL 都會改變。如果需要固定 URL，請參考 [Named Tunnels](https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/)。

#### 7.3 更新 GitHub Repository Variables

1. 前往 repo **Settings** → **Secrets and variables** → **Actions** → **Variables**
2. 編輯 `API_BASE_URL` 變數，將值改為 Cloudflare Tunnel 提供的 HTTPS URL：
   ```
   https://random-words-here.trycloudflare.com
   ```
   > ⚠️ **注意：** URL 末尾**不要**加斜杠 `/`

#### 7.4 重新部署前端

觸發 GitHub Pages 重新部署（以下任一方式）：
- 推送任何 commit 到 `main` 分支
- 前往 **Actions** → **Frontend Deploy** → **Run workflow**

#### 7.5 驗證連通

1. 打開 https://YOUR_USERNAME.github.io/MalScanWorker/
2. 上傳一個測試檔案
3. 應該看到上傳成功並進入分析進度頁面

> 🔍 **除錯提示：** 如果遇到問題，打開瀏覽器 DevTools (F12) → Network 標籤，檢查 API 請求的 URL 和響應。

---

## 本機開發

### 本地資料庫設定

後端需要 PostgreSQL 資料庫。本地開發可使用 Docker 快速啟動：

```bash
# 1. 啟動本地 PostgreSQL
docker run -d \
  --name malscan-postgres \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=malscan \
  -p 5432:5432 \
  postgres:15

# 2. 建立 .env 檔案（在 backend 目錄）
cd backend
echo 'DATABASE_URL=postgresql+asyncpg://postgres:postgres@localhost:5432/malscan' > .env
```

> 💡 資料庫表格會在後端啟動時自動建立，無需手動執行 migration。

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
