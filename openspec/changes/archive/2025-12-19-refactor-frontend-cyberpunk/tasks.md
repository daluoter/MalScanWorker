# Tasks: Frontend UI Refactor (Cyberpunk)

## Phase 1: 基礎設施 (Prerequisites)

- [x] 1.1 安裝 Tailwind CSS 相關依賴
  - `npm install -D tailwindcss postcss autoprefixer`
- [x] 1.2 初始化 Tailwind 配置檔
  - 建立 `tailwind.config.js`
  - 建立 `postcss.config.js`
- [x] 1.3 配置 Cyberpunk 設計系統
  - 自訂色彩 (Deep Space, Neon Cyan, Neon Purple, etc.)
  - 自訂動畫 (glow, pulse, glitch, scan)
  - 自訂字型 (Inter, JetBrains Mono)

---

## Phase 2: 全域樣式 (Global Styles)

- [x] 2.1 重寫 `index.css`
  - 加入 Tailwind directives
  - 引入 Google Fonts
  - 自訂 Scrollbar
  - 定義 CSS Grid 背景圖案
  - 定義 Glitch / Scan 動畫 keyframes
- [x] 2.2 更新 `App.tsx` Layout
  - 加入背景特效容器
  - 加入霓虹邊框裝飾

---

## Phase 3: 頁面重構 (Page Refactoring)

- [x] 3.1 UploadPage 重構
  - 全息投影 Drop Zone
  - 霓虹發光按鈕 + Glitch 動畫
  - 後端狀態脈衝指示燈
- [x] 3.2 JobStatusPage 重構
  - HUD 風格進度條
  - 終端機風格文字輸出
  - 分段式 Stage 顯示
- [x] 3.3 ReportPage 重構
  - Glassmorphism 卡片
  - 霓虹邊框判定結果
  - Code Snippet 風格 IOC 列表

---

## Phase 4: 驗證 (Verification)

- [ ] 4.1 Build & Lint 驗證
  - `npm run build` 成功
  - `npm run lint` 無錯誤
  - `npm run typecheck` 無錯誤
- [ ] 4.2 視覺驗證
  - 截圖 / 錄製各頁面效果
- [ ] 4.3 功能驗證
  - 拖曳上傳正常
  - API 連動正常
  - 頁面導航正常

---

## Dependencies

```
Phase 1 → Phase 2 → Phase 3 → Phase 4
          ↘ 3.1, 3.2, 3.3 可並行 ↗
```
