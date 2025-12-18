# 新增錯誤重試與強健性機制

## 問題背景

目前 MalScanWorker 專案的重試機制存在以下問題：

1. **Backend (`queue.py`)**: 使用手寫的 `for` 迴圈進行 3 次重試，延遲固定為 1 秒，缺乏指數退避策略
2. **Worker (`consumer.py`)**: RabbitMQ 連線重試同樣使用手寫迴圈，且訊息處理失敗時不會重試
3. **Worker (`storage.py`)**: MinIO 檔案下載完全沒有重試機制
4. **無 Dead Letter Queue**: 持續失敗的訊息會被直接丟棄，無法追蹤或重新處理

## 預期成果

引入 **Tenacity** 套件，以宣告式風格統一管理重試策略：

- **指數退避 (Exponential Backoff)**: 避免在服務暫時不可用時產生大量連線請求
- **結構化日誌**: 每次重試與最終失敗都會透過 structlog 記錄
- **Dead Letter Queue (DLQ)**: 超過重試上限的訊息轉入 `malscan-dlq` 佇列供事後分析

## 實作變更

### 依賴套件

- `backend/pyproject.toml`: 新增 `tenacity = "^8.2.0"`
- `worker/pyproject.toml`: 新增 `tenacity = "^8.2.0"`

### Backend (`queue.py`)

使用 `@retry` 裝飾器取代手寫 for 迴圈，實現指數退避策略 (5次嘗試，1s → 2s → 4s → 8s → 16s)。

### Worker

- `storage.py`: MinIO 下載加入重試 (3次嘗試，指數退避)
- `consumer.py`:
  - 使用 `@retry` 取代手寫連線重試
  - 宣告 DLQ 佇列 `malscan-dlq`
  - 實作訊息重試計數與 DLQ 轉信機制

## 驗證結果

- Backend: 8 tests passed, ruff ✓
- Worker: 7 tests passed, ruff ✓, mypy ✓

## 關聯 Spec

- [error-resilience](../../specs/error-resilience/spec.md)
