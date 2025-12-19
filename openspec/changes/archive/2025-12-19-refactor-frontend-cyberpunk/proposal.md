# Frontend UI Refactor: Cyberpunk 未來科技風格

## Why

MalScanWorker 前端目前使用基礎 CSS 樣式，視覺風格為傳統深色主題。為提升使用者體驗與專案辨識度，計劃將前端 UI 重構為「Cyberpunk 未來科技風格」，強制啟用 Dark Mode，並導入 Tailwind CSS 作為主要樣式框架。

**目標**：打造一個具備霓虹發光、全息投影、毛玻璃等視覺效果的沉浸式惡意軟體分析工具介面。

## What Changes

此變更導入 Tailwind CSS 設計系統，重構以下頁面的 UI：

- **UploadPage**: 全息投影風格 Drop Zone、霓虹按鈕、脈衝狀態指示
- **JobStatusPage**: HUD 風格進度條、終端機風格文字
- **ReportPage**: 毛玻璃卡片、霓虹判定框、Code Snippet IOC 列表

## User Review Required

> [!IMPORTANT]
> **技術棧變更**：此變更將導入 Tailwind CSS 作為主要樣式框架，取代現有的 Vanilla CSS 方案。這是一個不可逆的架構決策。

> [!WARNING]
> **破壞性變更**：現有 `index.css` 的所有樣式將被重寫。若有其他依賴這些 CSS class 的程式碼，需同步更新。

---

## Proposed Changes

### Design System (Tailwind Configuration)

#### [NEW] [tailwind.config.js](file:///home/daluoter/projects/MalScanWorker/frontend/tailwind.config.js)

配置 Cyberpunk 設計系統：

- **Color Palette (Dark Mode Base)**
  - Background: Deep Space `#030712`, Void `#0B1120`
  - Primary (Neon Cyan): `#06b6d4` + glow effect
  - Secondary (Neon Purple): `#8b5cf6` + glow effect
  - Danger (Alert Red): `#ef4444`
  - Success (Matrix Green): `#22c55e`

- **Typography**
  - UI Font: `Inter` (Google Fonts)
  - Code/Data Font: `JetBrains Mono` (Google Fonts)

- **Effects (Custom Utilities)**
  - Glassmorphism: `bg-opacity-10` + `backdrop-blur-md` + `border-white/10`
  - Neon Glow: `drop-shadow-[0_0_8px_rgba(6,182,212,0.5)]`
  - Grid Pattern: CSS background pattern

#### [NEW] [postcss.config.js](file:///home/daluoter/projects/MalScanWorker/frontend/postcss.config.js)

PostCSS 配置，整合 Tailwind CSS 與 Autoprefixer。

---

### Global Styles

#### [MODIFY] [index.css](file:///home/daluoter/projects/MalScanWorker/frontend/src/styles/index.css)

重寫全域樣式：

- 引入 Tailwind CSS directives (`@tailwind base/components/utilities`)
- 引入 Google Fonts (Inter, JetBrains Mono)
- 強制 Dark Mode 深色背景
- 自訂 Scrollbar 樣式 (霓虹風格)
- 定義 CSS Grid 背景圖案
- 定義 Glitch 動畫 keyframes

---

### Layout Container

#### [MODIFY] [App.tsx](file:///home/daluoter/projects/MalScanWorker/frontend/src/App.tsx)

加入 Layout Container：

- 全螢幕深色背景
- CSS Grid 背景圖案
- 四周霓虹漸層裝飾

---

### Page Components

#### [MODIFY] [UploadPage.tsx](file:///home/daluoter/projects/MalScanWorker/frontend/src/pages/UploadPage.tsx)

**全息投影風格 Drop Zone**：

| 元素 | 現況 | 改造 |
|------|------|------|
| Upload Zone | 虛線邊框卡片 | 霓虹邊框 + 背景掃描光效 + 拖曳時全息動畫 |
| Buttons | 基礎藍色按鈕 | 霓虹發光 + Hover 放大 + Glitch 微動畫 |
| 狀態指示 | 綠/紅色背景 | 霓虹發光圓點 + 脈衝動畫 |

#### [MODIFY] [JobStatusPage.tsx](file:///home/daluoter/projects/MalScanWorker/frontend/src/pages/JobStatusPage.tsx)

**HUD 風格進度顯示**：

| 元素 | 現況 | 改造 |
|------|------|------|
| Progress Bar | 單色漸層條 | 分段式 HUD 進度條 + 掃描光效 |
| Job ID / Status | 普通文字 | Monospace 終端機風格 + 打字機效果 |
| Stage Info | 列表顯示 | 終端機命令列風格輸出 |

#### [MODIFY] [ReportPage.tsx](file:///home/daluoter/projects/MalScanWorker/frontend/src/pages/ReportPage.tsx)

**毛玻璃資訊卡片 + 霓虹判定框**：

| 元素 | 現況 | 改造 |
|------|------|------|
| Cards | 實心深色卡片 | Glassmorphism 毛玻璃效果 |
| Verdict | 彩色文字 | 霓虹邊框卡片 (紅/綠/黃) + 發光動畫 |
| IOC List | Tag 樣式 | Code Snippet 風格 (類似 `<pre>` 區塊) |
| File Hash | 小字 monospace | 終端機風格滾動文字 |

---

### Dependencies

#### [MODIFY] [package.json](file:///home/daluoter/projects/MalScanWorker/frontend/package.json)

新增開發依賴：

```json
{
  "devDependencies": {
    "tailwindcss": "^3.4.x",
    "postcss": "^8.4.x",
    "autoprefixer": "^10.4.x"
  }
}
```

---

## Verification Plan

### Automated Tests

1. **Build Verification**
   ```bash
   cd frontend && npm run build
   ```
   確認 Tailwind CSS 正確編譯，無 TypeScript 錯誤。

2. **Lint Check**
   ```bash
   cd frontend && npm run lint && npm run typecheck
   ```
   確認程式碼品質無下降。

### Manual Verification

1. **Visual Inspection**
   - 啟動開發伺服器 (`npm run dev`)
   - 逐頁檢視 UploadPage、JobStatusPage、ReportPage
   - 驗證霓虹發光、毛玻璃、動畫效果正確呈現

2. **Functional Testing**
   - 拖曳上傳檔案功能正常
   - 後端連線狀態指示正確
   - 頁面間導航正常
   - API 資料正確顯示

3. **Responsive Check**
   - 桌面 (1920x1080) 與平板 (768px) 寬度下視覺正確

---

## Related Specs

此變更為前端 UI 重構，不影響 backend-db、worker-pipeline 等後端規格。
