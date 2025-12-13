# Change: 整合 MinIO 與 RabbitMQ 串接完整分析流程

## Why

目前 Backend 和 Worker 已完成 DB 整合，但 MinIO 檔案儲存和 RabbitMQ 任務隊列的實際串接尚未實作（代碼中標註 TODO）。這導致完整流程無法運作：

- 上傳的檔案沒有實際儲存到 MinIO
- 任務沒有發送到 RabbitMQ
- Worker 無法接收任務或下載檔案
- Job 狀態在執行期間沒有正確更新

## What Changes

### Backend

- **新增 MinIO Client**：實作 S3 相容的檔案上傳功能
- **新增 RabbitMQ Publisher**：發送任務訊息到 `malscan.jobs` queue
- **修改 `upload_file` 路由**：整合 MinIO 上傳和 RabbitMQ 發布

### Worker

- **新增 MinIO Client**：從 MinIO 下載檔案供分析使用
- **新增 DB 連線與操作**：更新 Job 狀態 (`scanning` → `completed`/`failed`)
- **修改 `pipeline.py`**：下載檔案、更新階段進度、寫入結果
- **修改 `consumer.py`**：整合狀態更新和錯誤處理

### 錯誤處理

- MinIO 下載失敗時，更新 DB 狀態為 `failed`
- 連線逾時時，正確處理並更新狀態

## Impact

- **Affected specs**: `backend-db` (修改 File Upload Persistence)
- **Affected code**:
  - `backend/src/malscan/api/routes.py`
  - `backend/src/malscan/storage.py` (新增)
  - `backend/src/malscan/queue.py` (新增)
  - `worker/src/malscan_worker/storage.py` (新增)
  - `worker/src/malscan_worker/db.py` (新增)
  - `worker/src/malscan_worker/pipeline.py`
  - `worker/src/malscan_worker/consumer.py`

## Technical Decisions

### MinIO Client 選擇
使用官方 `minio` Python SDK，因為：
- 官方支援，與 MinIO 完全相容
- 同步 API（在 async 路由中使用 `run_in_executor`）

### Storage Key 格式
使用 `{sha256}` 作為 storage key，實現內容定址儲存和自動去重。

### Worker DB 連線
Worker 需要獨立的 DB 連線來更新 Job 狀態。使用與 Backend 相同的 SQLAlchemy async 模式，但簡化為單次操作（不需要完整的 session 管理）。

### 狀態更新策略
- 收到任務：`queued` → `processing`
- 每個 Stage 完成：更新 `current_stage` 和 `stages_done`
- 全部完成：`processing` → `completed`
- 任何失敗：`failed` + `error_message`
