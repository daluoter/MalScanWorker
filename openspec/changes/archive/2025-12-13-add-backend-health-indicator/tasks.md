# Tasks: Add Backend Health Indicator

## 1. API 客戶端擴展
- [x] 1.1 在 `client.ts` 新增 `checkHealth()` 方法，呼叫後端 `/health` 端點
- [x] 1.2 新增 `HealthResponse` 介面定義

## 2. UploadPage 健康狀態整合
- [x] 2.1 新增 `isBackendOnline` 狀態和輪詢邏輯
- [x] 2.2 新增連線狀態指示器 UI 元件
- [x] 2.3 當後端離線時禁用上傳按鈕，並顯示離線提示

## 3. 驗證
- [x] 3.1 手動測試：啟動前端，驗證連線狀態顯示
- [x] 3.2 手動測試：關閉後端，驗證狀態變更為離線，上傳被禁用
- [x] 3.3 手動測試：重新啟動後端，驗證狀態自動恢復
