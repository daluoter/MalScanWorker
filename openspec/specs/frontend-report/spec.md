# frontend-report Specification

## Purpose
TBD - created by archiving change refactor-frontend-cyberpunk. Update Purpose after archive.
## Requirements
### Requirement: 資訊卡片樣式

資訊卡片 MUST 使用 Glassmorphism (毛玻璃) 效果。

- 背景 MUST 使用半透明 + `backdrop-blur(12px)`
- 邊框 MUST 顯示細微白色半透明線條 (`border-white/10`)
- 陰影 SHOULD 包含微弱霓虹外發光

#### Scenario: 報告卡片的視覺呈現

**Given** 分析報告已產生
**When** 使用者查看 ReportPage
**Then** 所有資訊卡片應顯示毛玻璃效果
**And** 卡片邊框應有微弱的白色半透明線條

---

### Requirement: Verdict 判定結果呈現

Verdict 判定區塊 MUST 使用霓虹邊框樣式。

- 結構 MUST 為獨立區塊，置於頁面頂部
- 邊框 MUST 依 verdict 類型變色 (Green/Yellow/Red) + glow
- 動畫 MUST 顯示邊框緩慢脈衝呼吸效果
- Clean verdict MUST 使用 #22c55e 邊框
- Malicious verdict MUST 使用 #ef4444 邊框

#### Scenario: 惡意檔案的判定結果顯示

**Given** 分析結果 verdict 為 malicious
**When** 使用者查看報告
**Then** 判定結果區塊應顯示紅色霓虹邊框
**And** 邊框應有發光脈衝動畫

---

### Requirement: IOC 列表樣式

IOC 列表 MUST 使用 Code Snippet 風格區塊。

- 容器 MUST 類似 `<pre>` 的程式碼區塊樣式
- 字型 MUST 使用 JetBrains Mono
- 背景 MUST 使用深色 (接近黑色)
- 每個 IOC MUST 獨立一行顯示

#### Scenario: IOC URL 列表的程式碼風格呈現

**Given** 報告包含 3 個可疑 URL
**When** 使用者查看 IOC 區塊
**Then** URL 應以程式碼區塊樣式顯示
**And** 每個 URL 獨立一行

---

### Requirement: 檔案雜湊顯示

檔案雜湊 MUST 使用終端機風格可複製區塊。

- 背景 MUST 使用深色區塊
- 字型 MUST 使用 JetBrains Mono
- 功能 MUST 支援點擊複製 (click-to-copy)
- 複製後 SHOULD 顯示「已複製」提示

#### Scenario: SHA256 雜湊的複製功能

**Given** 報告顯示檔案 SHA256 雜湊
**When** 使用者點擊雜湊文字
**Then** 雜湊值應複製到剪貼簿
**And** 應顯示「已複製」的短暫提示
