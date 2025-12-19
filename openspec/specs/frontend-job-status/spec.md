# frontend-job-status Specification

## Purpose
TBD - created by archiving change refactor-frontend-cyberpunk. Update Purpose after archive.
## Requirements
### Requirement: 進度條樣式

進度條 MUST 使用 HUD 風格分段式設計。

- 結構 MUST 分為 5 段，對應 5 個分析 stage
- 已完成段 MUST 顯示 Cyan 顏色
- 進行中段 MUST 顯示脈衝閃爍效果
- 動畫 MUST 包含 overlay 掃描光條從左向右移動

#### Scenario: 分析進行中的進度顯示

**Given** 分析任務正在執行
**When** 使用者查看 JobStatusPage
**Then** 進度條應顯示分段式結構
**And** 進行中的段落應有脈衝閃爍效果
**And** 應有掃描光條動畫覆蓋於進度條上

---

### Requirement: Job ID 與狀態顯示

Job ID 和狀態文字 MUST 使用終端機 (Terminal) 風格。

- 字型 MUST 使用 JetBrains Mono
- Job ID MUST 以 Cyan 顏色顯示
- 狀態文字 MUST 依類型變色 (scanning=cyan, done=green, failed=red)

#### Scenario: Job ID 的終端機風格呈現

**Given** 使用者導航至 JobStatusPage
**When** 頁面載入完成
**Then** Job ID 應以 monospace 字型顯示
**And** 應有類似終端機的視覺樣式

---

### Requirement: Stage 資訊呈現

Stage 資訊 MUST 使用終端機命令列風格。

- 格式 MUST 為 `> [STAGE_NAME] ... [STATUS]`
- 新 stage 進入時 SHOULD 有 fade-in 效果

#### Scenario: 顯示當前執行 stage

**Given** 分析任務正在執行 clamav stage
**When** 使用者查看進度頁
**Then** 當前 stage 應以終端機命令列格式顯示
**And** 行首應有指示符號
