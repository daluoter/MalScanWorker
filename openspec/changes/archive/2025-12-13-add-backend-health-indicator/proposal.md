# Change: Add Backend Health Indicator

## Why
使用者在前端上傳檔案時，如果後端服務不可用，會直接收到網路錯誤或超時。這種體驗不佳，應該在上傳前就顯示後端連線狀態，並在後端離線時禁用上傳功能。

## What Changes
- 新增 API 客戶端健康檢查方法（呼叫後端 `/health` 端點）
- 在 UploadPage 新增連線狀態指示器（顯示後端是否存活）
- 當後端離線時禁用上傳按鈕並顯示提示訊息
- 定期輪詢後端健康狀態（每 10 秒一次）

## Impact
- Affected specs: frontend-upload (新增)
- Affected code: `frontend/src/api/client.ts`, `frontend/src/pages/UploadPage.tsx`
