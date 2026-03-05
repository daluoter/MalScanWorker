## Context

MalScanWorker 是一套離線環境惡意檔案分析管線，由 FastAPI 後端、Python async Worker、RabbitMQ、MinIO、PostgreSQL 組成。經過三輪效能優化後，系統在功能層面已趨完整，但在可靠性與安全性方面仍有四個 CRITICAL 等級的問題：

1. **RabbitMQ 連線洩漏**：每次 `publish_job()` 建立新 TCP+AMQP 連線，高併發時耗盡 file descriptor 和 RabbitMQ 連線上限。
2. **SSE Session 生命週期錯誤**：SSE 串流端點長時間複用 request-scoped DB session，連線池可能回收底層連線導致 `InterfaceError`。
3. **上傳檔名未清理**：`multipart/form-data` 的 filename 直接存入 DB，可能包含路徑穿越字元（`../../`）、null bytes、或超長字串。
4. **密碼硬編碼**：後端與 Worker 的 `config.py` 為 DB、MinIO、RabbitMQ 設定了明文預設密碼，生產環境漏設環境變數時靜默使用弱密碼。

## Goals / Non-Goals

**Goals:**
- 消除 RabbitMQ 每次 publish 的連線開銷，改為持久連線單例
- SSE 端點每次 DB 查詢使用獨立 session，避免長生命週期 session 問題
- 對上傳檔名做 sanitize（移除路徑分隔符、null bytes、限制長度）
- 移除 config 中的密碼預設值，強制從環境變數讀取

**Non-Goals:**
- 不重構 FastAPI lifespan（留待後續優化）
- 不實作 RabbitMQ retry 機制修復（consumer 端 requeue 問題留待後續）
- 不新增 NetworkPolicy 或 k8s 安全強化
- 不變更 docker-compose.yml 的預設值（開發環境需要方便啟動）

## Decisions

### D1: RabbitMQ 持久連線管理

**選擇**：在 `queue.py` 中建立模組級別 `_connection` / `_channel` 單例，搭配 `init_rabbitmq()` / `close_rabbitmq()` 生命週期函式，由 `main.py` 的 startup/shutdown 事件呼叫。

**替代方案**：
- FastAPI dependency injection：每個 request 從連線池取 channel → 過於複雜，publish 只在 upload 時用
- 使用 `aio_pika.connect_robust` 的自動重連 → 仍選用此方式，但包在 singleton 中避免每次重建

**理由**：與現有 MinIO singleton 模式一致，改動最小，且 `aio_pika.connect_robust` 已內建斷線重連。

### D2: SSE 端點 Session 隔離

**選擇**：在 SSE async generator 內部使用 `get_session_factory()` 建立每次迭代獨立的 session（`async with session_factory() as session`）。移除 `Depends(get_db)` 從 SSE 端點參數。

**替代方案**：
- 保留 `Depends(get_db)` 但每次迭代 `expire_all()` → 仍有長生命週期 session 風險
- 直接用 engine `create_async_session` → 不如用已有的 session factory

**理由**：`get_session_factory()` 已在 `db/__init__.py` 中匯出，每次迭代建立獨立 session 確保連線池正常管理。

### D3: 檔名 Sanitize 策略

**選擇**：在 `routes.py` 的 upload 端點中，取得 filename 後立即呼叫 `_sanitize_filename()` 工具函式：
1. 取 `os.path.basename()` 移除路徑前綴
2. 移除 null bytes (`\x00`)
3. 截斷至 255 字元
4. 若結果為空則使用 `"unnamed"`

**替代方案**：
- 使用 `werkzeug.utils.secure_filename` → 不想新增依賴
- 在前端做驗證 → 不可信，後端必須自行驗證

**理由**：零依賴、簡單、涵蓋主要攻擊向量。

### D4: 密碼預設值移除策略

**選擇**：移除 `config.py` 中 `database_url`、`minio_access_key`、`minio_secret_key`、`rabbitmq_url` 的預設值（不給 `= "..."`），改為 Pydantic required field。測試中透過 `monkeypatch` 或 fixture 設定環境變數。

**替代方案**：
- 只加 warning log 但保留預設值 → 不夠安全，生產環境仍可能遺漏
- 使用 `SecretStr` type → 可以做但本次只先移除預設值

**理由**：Pydantic `BaseSettings` 的 required field 在未設定時會在啟動時立即拋出 `ValidationError`，fail-fast 行為最安全。

## Risks / Trade-offs

- **[Breaking Change]** 移除密碼預設值後，本地開發需要 `.env` 檔案或環境變數 → 需更新 README 和 `.env.example`
- **[RabbitMQ Singleton]** 若 `startup_event` 中 RabbitMQ 尚未就緒，`init_rabbitmq()` 會失敗 → 使用 `connect_robust` 自帶重連機制，且 startup 中不 raise（與 MinIO 初始化策略一致）
- **[SSE Session]** 每次迭代建立新 session 有微量額外開銷 → 相比長 session 的風險，此開銷可忽略（每秒一次查詢）
- **[Filename]** `os.path.basename` 在 Linux 上不處理 Windows 路徑分隔符 `\` → 額外替換 `\` 為 `/` 再取 basename
