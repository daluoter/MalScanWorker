# Spec Delta: frontend-upload (UI Refactor)

此規格差異 (delta) 描述 UploadPage 的 UI 重構需求。

---

## ADDED Requirements

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
