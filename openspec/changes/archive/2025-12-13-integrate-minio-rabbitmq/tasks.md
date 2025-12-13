# Tasks: MinIO 與 RabbitMQ 整合

## 1. Backend - MinIO 整合

- [x] 1.1 新增 `minio` 依賴到 `pyproject.toml` (已存在)
- [x] 1.2 建立 `backend/src/malscan/storage.py` MinIO client 模塊
  - 實作 `upload_file(content: bytes, key: str) -> str`
  - 實作 bucket 自動建立
  - 處理連線錯誤
- [x] 1.3 修改 `routes.py` 整合 MinIO 上傳
  - 在 DB 寫入前上傳檔案
  - 使用 SHA256 作為 storage key

## 2. Backend - RabbitMQ 整合

- [x] 2.1 新增 `aio-pika` 依賴（已存在）
- [x] 2.2 建立 `backend/src/malscan/queue.py` publisher 模塊
  - 實作 `publish_job(job_data: dict) -> None`
  - 處理連線錯誤
- [x] 2.3 修改 `routes.py` 整合 RabbitMQ 發布
  - 在 DB commit 後發布訊息
  - 發布失敗時正確處理

## 3. Worker - MinIO 整合

- [x] 3.1 新增 `minio` 依賴到 worker `pyproject.toml` (已存在)
- [x] 3.2 建立 `worker/src/malscan_worker/storage.py` MinIO client
  - 實作 `download_file(key: str, dest_path: Path) -> Path`
  - 處理下載失敗

## 4. Worker - DB 整合

- [x] 4.1 建立 `worker/src/malscan_worker/db.py` DB 操作模塊
  - 實作 `update_job_status(job_id: str, status: str, **kwargs)`
  - 實作 `update_job_stage(job_id: str, stage: str, stages_done: int)`
- [x] 4.2 新增 `sqlalchemy` 和 `asyncpg` 依賴到 worker (已存在)

## 5. Worker - Pipeline 整合

- [x] 5.1 修改 `pipeline.py` 整合 MinIO 下載
  - 下載檔案到暫存目錄
  - 下載失敗時拋出異常
- [x] 5.2 修改 `pipeline.py` 整合 DB 狀態更新
  - 每個 stage 完成後更新進度
  - Pipeline 完成後更新為 `completed`
  - Pipeline 失敗時更新為 `failed` 並記錄錯誤訊息
- [x] 5.3 實作暫存檔案清理

## 6. Worker - Consumer 整合

- [x] 6.1 修改 `consumer.py` 處理初始狀態
  - 收到訊息後立即更新為 `processing`
- [x] 6.2 加強錯誤處理
  - MinIO 下載失敗更新 DB
  - DB 連線失敗寫 log

## 7. Verification

- [ ] 7.1 本地 docker-compose 測試完整流程
- [ ] 7.2 驗證各錯誤場景正確處理

