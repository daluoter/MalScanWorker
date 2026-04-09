[English](README.en.md) | 繁體中文

# MalScanWorker

惡意附件分析 Pipeline 系統

## 架構

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
      (檔案)    (metadata)    │                 │
                              ▼                 │
                         Worker(s) ◄────────────┘
                      clamscan / yara CLI
                              │
                              ▼
                     Supabase PostgreSQL
                         (reports)
```

**資料流：**
1. 使用者透過前端上傳檔案 → Nginx 依據路由分流
2. **Go Ingest Service** 處理檔案上傳：存入 MinIO、寫入 job metadata 至 PostgreSQL、發布任務至 RabbitMQ
3. **Worker(s)** 從 RabbitMQ 消費任務，執行 ClamAV / YARA / format-analysis / deobfuscation 等分析，計算目前 artifact 的 direct/local risk，並將報告寫回資料庫
4. **FastAPI Backend** 提供 job 狀態查詢與報告取得 API，並在讀取 `/reports/{job_id}` 時做 descendant tree-aware risk rollup

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
- `ghcr.io/YOUR_USERNAME/malscan-ingest:latest`

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

# Ingest (Go)
cd ../ingest
docker build -t ghcr.io/YOUR_USERNAME/malscan-ingest:latest .
docker push ghcr.io/YOUR_USERNAME/malscan-ingest:latest
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
- `k8s/ingest/deployment.yaml`

```bash
# 使用 sed 批次替換
sed -i 's/OWNER/YOUR_USERNAME/g' k8s/api/deployment.yaml
sed -i 's/OWNER/YOUR_USERNAME/g' k8s/worker/deployment.yaml
sed -i 's/OWNER/YOUR_USERNAME/g' k8s/ingest/deployment.yaml
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
sudo kubectl apply -f k8s/ingest/
sudo kubectl apply -f k8s/api/
sudo kubectl apply -f k8s/worker/
sudo kubectl apply -f k8s/nginx/
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

開發時，我們需要兩個部分：
1. **基礎設施（Infra）**：PostgreSQL, MinIO, RabbitMQ, ClamAV
2. **應用程式（App）**：前端、Ingest 服務、後端 API、Worker

> ⚠️ **避免「幽靈消費者」問題 (Ghost Consumer)**
>
> 如果你打算使用 `poetry run` 在本機啟動 Worker 進行開發除錯，**絕對不要**使用 `docker compose up -d` 啟動全部服務！
> 因為 `docker-compose.yml` 中也包含了一個 `worker` 服務，若同時啟動，會導致 RabbitMQ 上出現兩個 consumers，造成部分任務被 Docker 中的舊版 Worker 搶走，導致分析結果異常。
>
> **正確的做法**：只啟動基礎設施容器，然後在本機手動啟動應用程式。

### 1. 啟動基礎設施 (PostgreSQL, MinIO, RabbitMQ, ClamAV)

在專案根目錄執行，僅啟動所需的基礎設施，**不啟動** API、Ingest 和 Worker：

```bash
docker compose up -d postgres minio rabbitmq clamav
```

### 2. 設定環境變數 (`.env`)

後端與 Worker 需要連線至本機建立的基礎設施。請切換目錄建立對應的 `.env` 檔案：

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

> 💡 資料庫表格會在後端和 Worker 啟動時自動建立，無需手動執行 migration。

### 3. 啟動前端
```bash
cd frontend
npm install
npm run dev
```

### 4. 啟動 Ingest 服務 (Go)
```bash
cd ingest
go run ./cmd/ingest
```

### 5. 啟動後端
```bash
cd backend
poetry install
poetry run uvicorn malscan.main:app --reload
```

### 6. 啟動 Worker
```bash
cd worker
poetry install
poetry run python -m malscan_worker.main
```

### 📦 測試完整容器化環境（Docker Compose）

若你完成開發，想在本機以 **完整容器化** 的方式測試整個系統：

1. **請先確保關閉**所有本機正在運行的 `poetry run` 和 `go run`（API、Ingest 和 Worker），以避免潛在的連線或消費者衝突。
2. 執行以下指令，強制重新編譯修改過的 Worker、API 和 Ingest image，確保容器使用的是最新的程式碼：

```bash
# 在專案根目錄下
docker compose up -d --build
```

---

## 密碼保護與遞迴壓縮檔分析

當上傳的壓縮檔需要密碼時，系統會先進入密碼流程；密碼正確後，會啟動遞迴解壓與子檔案分析。

### 支援格式
- **Archive:** ZIP、7z、RAR、TAR、GZIP、BZ2
- **ISO:** 目前保留為 stub（尚未啟用實際解壓）

### 支援的加密方式
- **ZIP:** ZipCrypto / AES-256（WZ_AES）
- **7z:** AES-256
- **RAR:** AES-128 / AES-256

### 使用流程
1. 上傳有密碼的壓縮檔 → 系統自動偵測並進入 `password_required`
2. 在工作狀態頁輸入密碼 → 系統重新嘗試解壓並繼續分析
3. 密碼正確後，Worker 會為衍生檔建立 artifact 記錄並派送 sub-job（遞迴分析）
4. 若 dedup 命中舊檔但 MinIO 物件已被 lifecycle 清除，系統會自動補傳，避免子任務 `NoSuchKey`
5. 最多可重試 **3 次**
   - 密碼正確：正常解壓並分析內部檔案
   - 3 次皆錯誤：產生最終報告，明確標示「解壓縮失敗」

### 報告與導覽行為
- 主報告會等整個 descendant job tree 完成後才顯示
  - 若仍有子任務進行中，`GET /api/v1/reports/{job_id}` 會回傳 `409`
  - 前端會顯示等待中狀態並自動輪詢，不會提早顯示未完成報告
  - 回傳的最終 `score` / `risk_level` / `risk` 會反映整棵 artifact tree 的 rollup 結果，不只是一層 local scan
- 解壓成功：報告顯示解壓資訊（檔案數、子任務數、解壓總大小）
- 解壓失敗：報告顯示紅色橫幅提示
- 若密碼連續錯誤 3 次，最終報告會保留 `verdict = "unknown"`，並附帶保守的零分 `risk` 區塊，避免把未完成分析誤標為 `clean`
- 子檔案的 Job/Report 頁面提供「返回上一層分析」入口

---

## 格式專用分析器架構（Phase 1）

Worker 新增了 `format-analysis` 階段，提供格式專用（format-specific）分析能力，補足先前主要依賴 generic 掃描（ClamAV/YARA/regex IOC）的可見性缺口。

### AnalyzerRegistry 是什麼

`AnalyzerRegistry` 是一個「第一個匹配就採用」的分析器註冊與分派器：

- 使用 `file-type` 階段產生的 MIME 與檔案 magic bytes 判斷
- 依照固定順序選擇可處理該檔案的 analyzer
- 維持可插拔擴充模式，後續可持續新增格式分析器

目前預設順序：

1. `PEAnalyzer`
2. `OfficeAnalyzerAdapter`
3. `PDFAnalyzer`
4. `LNKAnalyzer`
5. `ScriptAnalyzer`

### 本階段已支援格式

- PE（EXE/DLL）
- Office（RTF/OLE/OOXML）
- PDF
- LNK
- Script（PowerShell / JavaScript / VBScript / Batch / HTA）

### DocumentAnalysisStage 的整合方式

既有 `DocumentAnalysisStage` 並未拆解重寫，而是透過 `OfficeAnalyzerAdapter`（adapter/shim）包裝進新架構：

- 保留既有 Office 深度分析邏輯
- 將舊 findings 轉換成統一 `AnalyzerResult`
- 讓 Office 能與 PE/PDF/LNK/Script 共用同一套格式分析輸出與評分流

### 行為與設定變更

- Pipeline 流程變更為：
  - 平行靜態階段（file-type/clamav/yara/ioc-extract）
  - `format-analysis`
  - 後續序列階段（archive-extract/sandbox）
- 報告新增 `results.format_analysis` 區塊
- `results.document_analysis` 暫時保留（向後相容）
- 格式分析階段可提交抽取 artifacts 並建立 sub-job
- 遞迴提交沿用 max depth 保護機制，避免無限擴張

### 本階段刻意不做

- 不重構 `DocumentAnalysisStage` 內部為原生 Office analyzer（僅 adapter）
- 不做 PDF JS 模擬/深度去混淆
- 不做完整 LNK ExtraData 生態解析
- 不做 Script AST/符號執行等進階語意分析
- 不做跨格式關聯偵測（例如 LNK -> Script -> Downloader 鏈）

### 限制與後續工作

- 部分第三方 parser 屬 optional dependency，缺失時採 graceful degradation
- 規則偏重可解釋性的 heuristic；後續可持續校準誤報/漏報
- 可進一步加入跨格式關聯與 threat-intel enrichment

---

## 多訊號風險評分與報告欄位

系統現在使用 evidence-driven 的多訊號風險評分，取代舊的單薄 `verdict/score` 判定。

### 風險計算流程

- Worker 在 job 完成時，只計算當前 artifact 的 direct/local risk
- Backend 在 `GET /api/v1/reports/{job_id}` 且所有 descendants 完成後，使用同一套 scoring policy 做 canonical tree-aware rollup
- 這樣可以避免 parent job 太早完成，導致 parent risk 沒有反映後續子檔案結果

### 主要訊號來源

- ClamAV signature
- YARA metadata-based classification
- raw IOC extraction
- `format-analysis` structured indicators
- deobfuscation evidence
- sandbox behaviors
- descendant inheritance（由 backend rollup）

### 報告相容欄位

- top-level `verdict` 仍保留為 legacy compatibility 欄位
- top-level `score` 仍保留為 legacy-compatible alias（對應最終 `risk_score`）
- compatibility mapping:
  - `clean -> clean`
  - `low / medium / high -> suspicious`
  - `malicious -> malicious`

### 新增風險欄位

- top-level `risk_level`: `clean | low | medium | high | malicious`
- top-level `risk` 區塊包含：
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

### Artifact Tree 風險欄位

- `artifact_tree` 節點現在會帶出：
  - `verdict`
  - `score`
  - `risk_level`
  - `policy_version`
- root `artifact_tree` node 會與頂層最終 report risk 保持一致，避免同一份報告內 root node 與 top-level verdict/risk 不一致

---

## API 端點

| 方法 | 路徑 | 處理服務 | 說明 |
|------|------|----------|------|
| POST | `/api/v1/files` | Go Ingest Service | 上傳檔案進行分析 |
| GET | `/api/v1/jobs/{job_id}` | FastAPI | 查詢分析狀態 |
| POST | `/api/v1/jobs/{job_id}/password` | FastAPI | 提交壓縮檔密碼（最多 3 次） |
| GET | `/api/v1/reports/{job_id}` | FastAPI | 取得最終 tree-aware 分析報告（含 `risk`、`risk_level`、artifact tree） |

---

## 技術棧

- **前端:** React 18 + TypeScript + Vite
- **Ingest:** Go 1.25 + chi + pgx + minio-go + amqp091-go（檔案接收層）
- **後端:** FastAPI + SQLAlchemy + asyncpg
- **Worker:** Python + clamscan CLI + yara CLI + pyzipper (AES ZIP) + py7zr + rarfile
- **反向代理:** Nginx（路由分流至 Ingest / Backend）
- **佇列:** RabbitMQ
- **儲存:** MinIO + Supabase PostgreSQL
- **容器:** k3s + GHCR
- **CI/CD:** GitHub Actions

---

## License

MIT
