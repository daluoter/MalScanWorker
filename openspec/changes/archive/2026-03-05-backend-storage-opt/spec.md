# OpenSpec: 後端與儲存效能優化 (Backend & Storage Performance Optimization)

**狀態:** Active
**日期:** 2025-03-05
**目標:** 消除 MinIO 連線 Overhead、實作串流上傳徹底解決 OOM 隱患、放寬上傳限制至 100MB，並提升資料庫連線池穩定性。

## 1. 背景與痛點 (Context)
1. **MinIO Client 頻繁建立與重複檢查**: 在 `backend/src/malscan/storage.py` 中，每次呼叫 `upload_file` 都會重新實例化 `Minio` client，且每次都會呼叫 `_ensure_bucket_exists`。這會對每一筆上傳額外產生 2~3 個無謂的 S3 HTTP 請求，大幅拖慢單筆 API 回應速度。
2. **大檔案吃爆記憶體**: `backend/src/malscan/api/routes.py` 中的 `upload_file` 端點使用了 `content = await file.read()` 將整個檔案讀進記憶體。若上傳大檔案，API 會消耗大量 RAM 導致 OOM 崩潰。
3. **資料庫連線無限制**: `backend/src/malscan/db/engine.py` 未設定 `pool_size` 與 `max_overflow`，可能在高併發上傳時壓垮 PostgreSQL。

## 2. 變更項目 (Proposed Changes)

### A. 儲存層 Singleton 化與初始化重構
*   修改 `backend/src/malscan/storage.py` 與 `worker/src/malscan_worker/storage.py`，實作 Minio Client Singleton。
*   將 `_ensure_bucket_exists` 從上傳路徑拔除。
*   在 `backend/src/malscan/main.py` 的 FastAPI `lifespan` 加上系統啟動時的 Bucket 檢查與 lifecycle 設定。

### B. 實作 Streaming 大檔案上傳 (支援 100MB)
*   修改 `backend/src/malscan/config.py`，將 `max_file_size` 設為 100MB (`100 * 1024 * 1024`)。
*   修改 `frontend/src/pages/UploadPage.tsx`，將前端的 UI 限制與提示同步更新為 100MB。
*   改寫 `backend/src/malscan/api/routes.py` 的 `/files` 端點：
    *   移除 `await file.read()` 全讀取。
    *   實作 Streaming 上傳：分塊讀取 (chunked reading)，邊計算 SHA256 邊寫入本地暫存檔。
    *   完成後呼叫 Minio 的 `fput_object` (檔案直傳) 上傳至 Bucket，再刪除暫存檔。

### C. 資料庫連線池優化 (DB Pool Tuning)
*   修改 `backend/src/malscan/db/engine.py`，在 `create_async_engine` 中設定 `pool_size=10` 與 `max_overflow=20`。

## 3. 預期效益 (Expected Benefits)
*   **API 延遲降低**：移除每次上傳無謂的 MinIO 控制請求。
*   **記憶體穩定**：API 記憶體用量不再隨上傳檔案大小劇烈波動，徹底解決 OOM 隱患。
*   **高併發抗壓性**：資料庫連線受到池化保護，在高流量下不致崩潰。
*   **涵蓋率提升**：支援 100MB 大檔案上傳分析。
