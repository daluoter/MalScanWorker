# frontend-upload Specification

## Purpose
TBD - created by archiving change add-backend-health-indicator. Update Purpose after archive.
## Requirements
### Requirement: Backend Health Check
前端 API 客戶端 SHALL 提供 `checkHealth()` 方法，用於檢查後端服務是否存活。

#### Scenario: 後端存活時返回成功
- **GIVEN** 後端服務正常運行
- **WHEN** 呼叫 `checkHealth()` 方法
- **THEN** 返回 `{ status: "ok" }` 或 resolve promise

#### Scenario: 後端離線時返回失敗
- **GIVEN** 後端服務不可用
- **WHEN** 呼叫 `checkHealth()` 方法
- **THEN** 拋出錯誤或 reject promise

---

### Requirement: Backend Status Indicator
UploadPage SHALL 顯示後端連線狀態指示器，讓使用者了解服務是否可用。

#### Scenario: 後端存活時顯示在線狀態
- **GIVEN** 後端 `/health` 端點可達
- **WHEN** 使用者進入上傳頁面
- **THEN** 顯示綠色狀態指示器，標示「後端在線」或類似文字

#### Scenario: 後端離線時顯示離線狀態
- **GIVEN** 後端 `/health` 端點不可達
- **WHEN** 使用者進入上傳頁面
- **THEN** 顯示紅色狀態指示器，標示「後端離線」或類似文字

#### Scenario: 頁面載入時自動輪詢
- **GIVEN** 使用者停留在上傳頁面
- **WHEN** 經過固定時間間隔（建議 10 秒）
- **THEN** 自動重新檢查後端健康狀態並更新指示器

---

### Requirement: Upload Blocking When Offline
當後端離線時，UploadPage SHALL 禁用上傳功能以防止無謂的失敗嘗試。

#### Scenario: 後端離線時禁用上傳按鈕
- **GIVEN** 後端 `/health` 端點不可達
- **AND** 使用者已選擇檔案
- **WHEN** 使用者嘗試點擊「開始分析」按鈕
- **THEN** 按鈕應為禁用狀態，無法點擊

#### Scenario: 後端恢復後自動啟用上傳
- **GIVEN** 後端曾經離線但已恢復
- **AND** 使用者已選擇檔案
- **WHEN** 健康檢查偵測到後端恢復
- **THEN** 「開始分析」按鈕自動恢復為可點擊狀態

