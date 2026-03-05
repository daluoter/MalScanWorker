## 1. RabbitMQ 持久連線單例

- [x] 1.1 重構 `backend/src/malscan/queue.py`：新增模組級 `_connection`/`_channel` 變數，實作 `init_rabbitmq()` 建立持久連線並宣告 queue，實作 `close_rabbitmq()` 關閉連線
- [x] 1.2 修改 `publish_job()` 使用 singleton channel 發送訊息，移除函式內部的 `connect_robust` 呼叫
- [x] 1.3 在 `backend/src/malscan/main.py` 的 startup 事件呼叫 `init_rabbitmq()`，shutdown 事件呼叫 `close_rabbitmq()`

## 2. SSE 端點 DB Session 修復

- [x] 2.1 修改 `backend/src/malscan/api/routes.py` 的 `stream_job_status` 端點：移除 `db: AsyncSession = Depends(get_db)` 參數
- [x] 2.2 在 SSE async generator 內部使用 `get_session_factory()` 每次迭代建立獨立 session，移除 `db.expire(job)` 呼叫

## 3. 上傳檔名清理

- [x] 3.1 在 `backend/src/malscan/api/routes.py` 新增 `_sanitize_filename()` 工具函式：處理路徑穿越、null bytes、反斜線、長度截斷、空白 fallback
- [x] 3.2 在 upload 端點中，取得 filename 後立即呼叫 `_sanitize_filename()` 再存入 DB

## 4. 密碼預設值移除

- [x] 4.1 修改 `backend/src/malscan/config.py`：移除 `database_url`、`minio_access_key`、`minio_secret_key`、`rabbitmq_url` 的預設值
- [x] 4.2 修改 `worker/src/malscan_worker/config.py`：同上移除密碼預設值
- [x] 4.3 建立 `.env.example` 檔案，列出所有必填環境變數及說明
- [x] 4.4 更新後端測試 fixture，透過環境變數或 monkeypatch 提供必填設定值

## 5. 驗證

- [x] 5.1 執行 `ruff check` 和 `ruff format` 確認程式碼品質
- [x] 5.2 執行後端測試 `poetry run pytest`
- [x] 5.3 執行前端建置 `npm run build`（確認無間接影響）
