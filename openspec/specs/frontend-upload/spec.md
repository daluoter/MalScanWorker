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

### Requirement: Upload Zone 視覺樣式

Upload Zone MUST 使用全息投影 (Holographic) 風格。

- 背景 MUST 使用深色半透明 + `backdrop-blur`
- 邊框 MUST 顯示霓虹 Cyan 發光效果
- 動畫 MUST 持續播放掃描光條 (scan line)
- Dragging 狀態 MUST 觸發邊框閃爍 + 背景亮度提升

#### Scenario: 使用者拖曳檔案進入 Drop Zone

**Given** 使用者開啟 UploadPage
**When** 使用者將檔案拖曳進入 Drop Zone
**Then** Drop Zone 邊框應閃爍霓虹光效
**And** 背景應顯示增強的全息動畫

---

### Requirement: 上傳按鈕樣式

上傳按鈕 MUST 使用霓虹發光樣式。

- 背景 MUST 使用漸層 (Cyan → Purple)
- 邊框 MUST 顯示霓虹 glow
- Hover 狀態 MUST 放大 1.02x + glow 增強
- Active 狀態 SHOULD 顯示 Glitch 閃爍效果

#### Scenario: 使用者 hover 上傳按鈕

**Given** 使用者選擇了一個檔案
**When** 使用者將滑鼠移至「開始分析」按鈕
**Then** 按鈕應顯示霓虹發光增強效果
**And** 按鈕應微微放大

---

### Requirement: 後端連線狀態指示

後端連線狀態 MUST 使用霓虹發光圓點顯示。

- 線上狀態 MUST 顯示綠色發光圓點 + 緩慢脈衝
- 離線狀態 MUST 顯示紅色發光圓點 + 快速脈衝
- 檢測中狀態 SHOULD 顯示灰色圓點 + 旋轉動畫

#### Scenario: 後端離線時的視覺警示

**Given** 後端服務不可用
**When** 使用者開啟 UploadPage
**Then** 應顯示紅色霓虹發光圓點
**And** 圓點應以快速頻率脈衝
