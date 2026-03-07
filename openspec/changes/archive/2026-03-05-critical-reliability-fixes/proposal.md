## Why

目前 MalScanWorker 存在四個 CRITICAL 等級的可靠性與安全性問題，會在生產環境中造成資源耗盡、連線洩漏、安全漏洞、以及資料正確性錯誤。這些問題在低負載時不明顯，但在多使用者並行操作或長時間運行時會逐步暴露。

## What Changes

- **RabbitMQ 連線單例化**：`queue.py` 中每次 `publish_job()` 都建立新的 TCP+AMQP 連線再關閉，改為啟動時建立持久連線並全程複用。
- **SSE 端點 DB Session 修復**：`/jobs/{job_id}/stream` 端點的 async generator 長時間複用同一個 request-scoped `AsyncSession`，改為每次迭代建立獨立 session。
- **上傳檔名清理**：上傳端點接受未經驗證的 `filename`，存入資料庫前未做任何 sanitize，可能包含路徑穿越字元或 null bytes。
- **密碼硬編碼移除**：後端與 Worker 的 `config.py` 將 DB、MinIO、RabbitMQ 密碼寫死為預設值，生產環境若未設定環境變數會靜默使用弱密碼。

## Capabilities

### New Capabilities
- `upload-sanitization`: 上傳檔名清理與驗證邏輯

### Modified Capabilities
- `error-resilience`: 新增 RabbitMQ 持久連線管理與 SSE session 隔離，強化系統韌性
- `backend-db`: SSE 端點的 DB session 生命週期修正

## Impact

- **Backend**：`queue.py`（RabbitMQ singleton）、`routes.py`（SSE session + 檔名 sanitize）、`main.py`（lifespan 中初始化/關閉 RabbitMQ 連線）、`config.py`（移除密碼預設值）
- **Worker**：`config.py`（移除密碼預設值）
- **Infra**：`docker-compose.yml`（明確標註 dev-only 預設值）、`k8s/secrets.yaml.example`（確認文件正確）
- **DB Session**：`db/session.py` 或 `db/__init__.py` 需暴露 session factory 供 SSE 使用
- **Tests**：需更新測試以配合 config 變更（必填欄位）
- **Breaking**：在未設定環境變數的情況下，後端和 Worker 將無法啟動（密碼欄位不再有預設值）——這是刻意的安全強化行為
