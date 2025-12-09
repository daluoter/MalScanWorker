# Project Context

## Purpose
MalScanWorker 是一個惡意附件分析 Pipeline 系統，提供自動化的檔案威脅偵測服務。使用者透過 Web UI 上傳檔案，系統非同步執行多階段分析（檔案類型偵測、ClamAV 掃描、YARA 規則比對、IOC 擷取、沙箱行為分析），並產出結構化的威脅報告。

**核心價值：**
- 非同步處理：立即回傳 job_id，不阻塞使用者
- 多階段分析：模組化 stage 設計，易於擴充
- 可觀測性：完整的 metrics/logs/tracing 支援
- 企業級部署：k8s 原生，支援水平擴展

## Tech Stack

### 後端
- **語言/框架：** Python 3.11+ / FastAPI
- **非同步模型：** async/await
- **ORM/DB Client：** SQLAlchemy 2.0 (async) + asyncpg
- **外部 HTTP Client：** httpx（可選，僅用於外部 API adapter，如 VirusTotal）

### 前端
- **框架：** React 18 + TypeScript
- **路由：** React Router v6
- **HTTP Client：** fetch API (native)
- **樣式：** CSS Modules / Tailwind CSS

### 基礎設施
- **資料庫：** Supabase PostgreSQL (雲端)
- **物件儲存：** MinIO (k3s 內部署)
- **訊息隊列：** RabbitMQ (k3s 內部署)
- **容器編排：** k3s (單節點, VirtualBox Ubuntu VM)
- **CI/CD：** GitHub Actions
- **前端部署：** GitHub Pages
- **容器註冊：** GitHub Container Registry (GHCR)

### 分析引擎
- **AV 掃描：** ClamAV clamscan CLI（MVP：Worker 內執行；v2 考慮 clamd socket）
- **規則比對：** YARA CLI（MVP：rules 透過 ConfigMap/volume mount；v2 考慮 yara-python）
- **IOC 擷取：** 自建正規表達式引擎
- **沙箱：** Adapter 介面 + Mock 實作 (MVP)

### 觀測
- **API Metrics：** Prometheus + prometheus-fastapi-instrumentator（暴露 /metrics）
- **Worker Metrics：** prometheus_client + 內建 HTTP server（暴露 /metrics）
- **Logging：** structlog (JSON format)
- **Dashboard：** Grafana
- **Tracing：** OpenTelemetry (v2 擴充)

## Project Conventions

### Code Style

**Python (後端/Worker):**
- Formatter: Black (line-length=100)
- Linter: Ruff
- Type Checker: mypy (strict mode)
- Import Sorter: isort (Black-compatible)
- Docstring: Google style

**TypeScript (前端):**
- Formatter: Prettier
- Linter: ESLint (typescript-eslint)
- 禁用 `any` type

**命名規範：**
- Python: snake_case (variables/functions), PascalCase (classes)
- TypeScript: camelCase (variables/functions), PascalCase (components/types)
- API endpoints：固定採用需求指定路徑（/api/v1/...），不套用 kebab/snake 規範
- JSON 欄位 / DB 欄位: snake_case
- k8s resources: kebab-case

### Architecture Patterns

**後端架構：**
- Clean Architecture: Presentation → Application → Domain → Infrastructure
- 依賴注入: FastAPI Depends
- Repository Pattern: 資料存取抽象
- Adapter Pattern: 外部服務整合 (ClamAV, YARA, Sandbox)

**Worker 架構：**
- Stage Pipeline: 每個 stage 實作統一介面
- Fail-Fast: 任一 stage 失敗立即中止
- Stateless: Worker 不保留狀態，可水平擴展

**前端架構：**
- Feature-based 目錄結構
- Custom Hooks 封裝業務邏輯
- React Query 或手動 polling 處理狀態

### Testing Strategy

**後端：**
- Unit Tests: pytest + pytest-asyncio
- Integration Tests: testcontainers (PostgreSQL, RabbitMQ, MinIO)
- Coverage: 最低 80%

**前端：**
- Unit Tests: Vitest + React Testing Library
- E2E Tests: Playwright (v2 考慮)

**CI 必須通過：** lint + type check + unit tests

### Git Workflow

- **主分支：** `main` (protected)
- **開發分支：** `feature/<name>`, `fix/<name>`, `refactor/<name>`
- **Commit 格式：** Conventional Commits
  - `feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`
- **PR 必須：** 至少 1 approval + CI 通過
- **合併策略：** Squash and merge

## Domain Context

### 惡意軟體分析領域知識

**檔案分析流程：**
1. **File Type Detection:** 使用 magic bytes / MIME 類型判斷真實檔案格式（防止副檔名偽裝）
2. **Signature-Based Detection:** ClamAV / YARA 使用已知惡意特徵碼比對
3. **IOC Extraction:** 擷取可疑指標 (URLs, Domains, IPs, File Hashes)
4. **Behavioral Analysis:** 沙箱執行觀察檔案行為（MVP 為 mock）

**關鍵術語：**
- **IOC (Indicator of Compromise):** 入侵指標，用於識別惡意活動
- **YARA Rule:** 基於模式的惡意軟體分類規則
- **Verdict:** 最終判定結果 (clean/suspicious/malicious)
- **Score:** 威脅評分 (0-100)

**風險考量：**
- Zip Bomb: 壓縮炸彈可耗盡系統資源（MVP 不解壓）
- Evasion: 惡意軟體可能偵測分析環境並改變行為
- False Positive/Negative: 簽章比對可能誤判

## Important Constraints

### 部署環境限制（不可更動）
- 開發/操作端：Windows 11 宿主機
- 執行環境：VirtualBox 內一台 Ubuntu Server VM
- K8s：VM 內安裝 k3s 單節點叢集
- 資料庫：Supabase PostgreSQL（雲端）
- 前端：GitHub Pages（必須處理 project pages base path）
- 對外暴露：MVP 用 NodePort

### 技術限制
- 檔案大小上限：20MB
- 單一 Worker 處理流程：不做並行 stage（簡化狀態管理）
- Sandbox：MVP 僅 mock 實作

### 安全限制
- Secrets 不可 hardcode，僅允許 k8s Secret 注入
- CORS 僅允許 GitHub Pages 網域
- Worker 必須有 CPU/Memory 資源限制與 stage timeout

## External Dependencies

### Supabase PostgreSQL
- **用途：** 主資料庫 (files, jobs, reports 三表)
- **連線：** DATABASE_URL (含 password)
- **權限：** 需要 CRUD 權限

### MinIO (Self-hosted in k3s)
- **用途：** 檔案物件儲存
- **Buckets：** `uploads` (原始檔案), `artifacts` (分析產出)
- **連線：** MINIO_ENDPOINT, MINIO_ACCESS_KEY, MINIO_SECRET_KEY

### RabbitMQ (Self-hosted in k3s)
- **用途：** 任務隊列
- **Queue：** `malscan.jobs`
- **連線：** RABBITMQ_URL (amqp://...)

### ClamAV (Worker 內建)
- **用途：** 防毒掃描
- **MVP：** Worker image 內含 clamscan CLI，virus DB 以啟動更新（freshclam）處理
- **v2：** clamd sidecar 或獨立 clamd service（socket/TCP）

### GitHub Services
- **GHCR：** Container image 存放
- **GitHub Pages：** 前端靜態網站
- **GitHub Actions：** CI/CD pipeline
