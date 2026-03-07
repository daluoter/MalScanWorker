# OpenSpec: 前端狀態即時推播 (Real-time Status via SSE)

**狀態:** Active
**日期:** 2025-03-05
**目標:** 消除前端對後端 API 的每 2 秒輪詢（Polling），改用 Server-Sent Events (SSE) 讓後端主動推送分析狀態，減少伺服器無謂負載，並提供使用者毫秒級的即時進度體驗。

## 1. 背景與痛點 (Context)
目前的 `JobStatusPage.tsx` 使用 `setInterval` 每 2 秒向後端 `/api/v1/jobs/{job_id}` 發送一次 HTTP 請求。
這帶來了兩個問題：
1. **伺服器/DB 壓力**：如果有 N 個使用者在等待，每 2 秒就會產生 N 個 HTTP 請求和 DB 查詢。大部分的查詢都是無效的（狀態還沒變）。
2. **非即時性**：Worker 完成分析後，前端最遲可能需要等待接近 2 秒才會更新畫面，UX 不夠流暢。

## 2. 變更項目 (Proposed Changes)

### A. 依賴新增 (Backend)
*   在 `backend/pyproject.toml` 中新增 `sse-starlette` 套件，這是 FastAPI 官方推薦用來處理 SSE 串流的標準庫。

### B. 後端 API 實作 (`backend/src/malscan/api/routes.py`)
*   新增一個端點 `GET /jobs/{job_id}/stream`，回傳型別為 `EventSourceResponse`。
*   實作一個非同步產生器 (Async Generator)，邏輯如下：
    1. 接收連線，讀取目前的 Job 狀態。
    2. 進入 `while True:` 迴圈。每次迴圈暫停短暫時間（如 `asyncio.sleep(0.5)`）。
    3. 查詢資料庫的 `updated_at` 或 `stages_done`。
    4. 如果與前一次記錄不同，則 `yield` 新的狀態資料給前端。
    5. 如果狀態變為 `done` 或 `failed`，則送出最後一筆資料並結束 generator (斷開連線)。
    6. 處理客戶端斷線事件（`asyncio.CancelledError` 或檢查請求斷線）。

### C. 前端實作 (`frontend/src/pages/JobStatusPage.tsx`)
*   拔除原有的 `setInterval` 輪詢邏輯。
*   使用瀏覽器原生的 `EventSource` API 來連接 `${apiClient.baseUrl}/api/v1/jobs/${jobId}/stream`。
*   監聽 `message` 事件，每當收到資料 (JSON parse) 時，更新 React 狀態 (`setStatus`)。
*   當收到 `done` 或 `failed` 狀態，關閉 `EventSource` 連線，若成功則觸發跳轉 (Navigate) 到報告頁面。

## 3. 預期效益 (Expected Benefits)
*   完全消除因為前端 Polling 產生的海量 HTTP 請求。
*   分析進度的更新從「最大延遲 2 秒」變成了幾乎無延遲的「即時推播」。
*   FastAPI 內部非同步查詢 DB 的成本遠低於處理完整的外部 HTTP 請求。
