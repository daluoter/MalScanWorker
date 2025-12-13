# Design: MinIO 與 RabbitMQ 整合架構

## Context

MalScanWorker 系統需要完成檔案儲存和任務隊列的整合，以實現完整的惡意軟體分析流程。目前 DB 整合已完成，但 MinIO 和 RabbitMQ 僅有配置，未實作實際操作。

**約束條件：**
- MinIO 和 RabbitMQ 已部署在 k3s 叢集中
- Worker 需要獨立的 DB 連線來更新狀態
- 必須處理網路失敗和逾時情況

## Goals / Non-Goals

**Goals:**
- 實現完整的「上傳 → 儲存 → 發送任務 → Worker 接收 → 下載 → 分析 → 更新狀態」流程
- Worker 能正確更新 Job 狀態供前端輪詢
- 失敗情況能正確處理並反映到 DB

**Non-Goals:**
- 不實作檔案分片上傳（單次上傳限制 20MB）
- 不實作 Worker 水平擴展的 lock 機制（MVP 單 Worker）
- 不實作 Report 表的寫入（後續迭代）

## Decisions

### Decision 1: MinIO SDK 選擇

**選擇**: 使用 `minio` 官方 Python SDK

**替代方案**:
- `boto3`: 更通用，但需要額外配置 endpoint
- `aiobotocore`: 原生 async，但複雜度較高

**理由**: 官方 SDK 最穩定，MinIO 特定功能支援最好。同步操作在 async 環境中使用 `run_in_executor` 即可。

### Decision 2: RabbitMQ 訊息格式

**選擇**: JSON payload 包含完整任務資訊

```json
{
  "job_id": "uuid",
  "file_id": "uuid",
  "storage_key": "sha256",
  "sha256": "hash",
  "original_filename": "name.exe"
}
```

**理由**: Worker 收到訊息後無需查詢 DB 即可開始工作，降低延遲。

### Decision 3: Worker DB 架構

**選擇**: Worker 建立獨立的 SQLAlchemy async engine

**替代方案**:
- 透過 API 回報狀態：增加網路開銷和單點故障風險
- 共用 Backend 的 DB 模塊：需要複雜的模塊共享機制

**理由**: 直接 DB 連線最簡單可靠，且 Supabase PostgreSQL 支援多連線。

### Decision 4: 檔案暫存策略

**選擇**: Worker 下載檔案到 `/tmp/{job_id}/` 目錄，分析完成後清理

**理由**: 
- 隔離不同 job 的檔案
- 容器重啟時 `/tmp` 自動清理
- 避免磁碟空間累積

## Risks / Trade-offs

| Risk | Mitigation |
|------|------------|
| MinIO 連線失敗導致上傳失敗 | 在 Backend 實作連線重試，失敗則返回 500 |
| Worker 下載失敗 | 更新 Job 狀態為 `failed`，不 requeue 訊息 |
| DB 更新失敗 | 記錄 log，不阻塞分析流程 |
| RabbitMQ 發布失敗 | 回滾 DB transaction，返回錯誤 |

## Open Questions

1. ~~是否需要在 File 表增加 `storage_key` 欄位？~~ 
   - 決定：使用 SHA256 作為 storage key，無需額外欄位

2. Worker 完成後是否需要刪除 MinIO 中的檔案？
   - 暫定：不刪除，保留供後續查詢或重新分析
