# 工作任務清單

## 依賴套件

- [x] 在 `backend/pyproject.toml` 加入 tenacity 依賴
- [x] 在 `worker/pyproject.toml` 加入 tenacity 依賴
- [x] 執行 `poetry install` 安裝依賴

---

## Backend 實作

- [x] 重構 `queue.py` publish_job 函式
  - [x] 移除手寫 for 迴圈重試
  - [x] 加入 `@retry` 裝飾器 (stop_after_attempt=5, wait_exponential)
  - [x] 加入 before_sleep 日誌回呼
  - [x] 加入 retry_error_callback 記錄最終失敗
  - [x] 測試重試行為 ✅

---

## Worker 實作

- [x] 重構 `storage.py` download_file
  - [x] 在 `_download_file_sync` 加入 `@retry` 裝飾器 (3次, 指數退避)
  - [x] 測試 MinIO 連線重試 ✅

- [x] 重構 `consumer.py` 連線與訊息處理
  - [x] 使用 `@retry` 取代 connect_with_retry 的 for 迴圈
  - [x] 宣告 DLQ 佇列 `malscan-dlq`
  - [x] 設定主佇列的 dead-letter-exchange 參數
  - [x] 實作訊息失敗處理邏輯 (檢查 x-death header、轉信 DLQ)
  - [x] 優雅處理現有佇列參數衝突
  - [x] 測試 DLQ 機制 ✅

---

## 驗證

- [x] 執行 Backend 單元測試 (8 passed)
- [x] 執行 Worker 單元測試 (7 passed)
- [x] ruff 和 mypy 檢查通過
