# Design Document: Cyberpunk Frontend UI

## Overview

本文件描述 MalScanWorker 前端 UI 重構的技術架構與設計決策。

---

## Architecture Decision Records

### ADR-1: 選擇 Tailwind CSS 作為樣式框架

**Context**：現有前端使用 Vanilla CSS，隨著 Cyberpunk 設計需求增加（動畫、漸層、響應式），維護成本上升。

**Decision**：導入 Tailwind CSS v3.4。

**Rationale**：
- Utility-first 方法論與 React 組件模式契合
- 內建 Dark Mode、響應式支援
- JIT 編譯器僅輸出使用到的樣式，bundle size 可控
- 社群生態豐富，文件完善

**Alternatives Considered**：
| 方案 | 優點 | 缺點 |
|------|------|------|
| CSS Modules | 零學習曲線 | 動畫/漸層需大量手寫 CSS |
| Styled Components | CSS-in-JS 類型安全 | Runtime overhead |
| UnoCSS | 更快的 JIT | 生態較小 |

**Consequences**：
- 需安裝 postcss / autoprefixer
- 現有 CSS class 需遷移至 Tailwind utility classes
- 團隊需熟悉 Tailwind 語法

---

### ADR-2: 設計系統語言 (Design Tokens)

**Color System**：

```
┌─────────────────────────────────────────┐
│  Background Layers                       │
│  ┌───────────────────────────────────┐  │
│  │  Void (#0B1120) - Cards           │  │
│  │  ┌─────────────────────────────┐  │  │
│  │  │  Deep Space (#030712) - BG  │  │  │
│  │  └─────────────────────────────┘  │  │
│  └───────────────────────────────────┘  │
└─────────────────────────────────────────┘

┌───────────────────────────────────────────────┐
│  Accent Colors (Neon)                          │
│                                                │
│  Primary ━━━━━━ #06b6d4 (Cyan)   ⚡ Glow       │
│  Secondary ━━━ #8b5cf6 (Purple) ⚡ Glow       │
│  Success ━━━━━ #22c55e (Green)  Matrix        │
│  Danger ━━━━━━ #ef4444 (Red)    Alert         │
│  Warning ━━━━━ #eab308 (Yellow) Caution       │
└───────────────────────────────────────────────┘
```

**Typography**：

| 用途 | 字型 | 字重 |
|------|------|------|
| UI Text | Inter | 400, 500, 600, 700 |
| Code / Data | JetBrains Mono | 400, 500 |

---

### ADR-3: 視覺效果實作策略

**Glassmorphism (毛玻璃)**：

```css
.glass {
  background: rgba(11, 17, 32, 0.6);
  backdrop-filter: blur(12px);
  border: 1px solid rgba(255, 255, 255, 0.1);
}
```

**Neon Glow**：

```css
.neon-cyan {
  filter: drop-shadow(0 0 8px rgba(6, 182, 212, 0.5))
          drop-shadow(0 0 20px rgba(6, 182, 212, 0.3));
}
```

**Grid Pattern Background**：

```css
.cyber-grid {
  background-image:
    linear-gradient(rgba(6, 182, 212, 0.03) 1px, transparent 1px),
    linear-gradient(90deg, rgba(6, 182, 212, 0.03) 1px, transparent 1px);
  background-size: 50px 50px;
}
```

**Scan Line Animation**：

```css
@keyframes scan {
  0% { transform: translateY(-100%); }
  100% { transform: translateY(100%); }
}
```

---

## Component Hierarchy

```
App (Background Container)
├── UploadPage
│   ├── HolographicDropZone
│   │   └── ScanLineOverlay
│   ├── NeonButton
│   └── StatusIndicator (pulse)
│
├── JobStatusPage
│   ├── HUDProgressBar
│   │   └── SegmentedProgress
│   ├── TerminalOutput
│   └── StageList
│
└── ReportPage
    ├── GlassCard (multiple)
    ├── VerdictBadge (neon border)
    ├── IOCCodeBlock
    └── TimingStages
```

---

## Performance Considerations

1. **CSS Animation Performance**
   - 使用 `transform` 和 `opacity` 進行動畫，避免 layout thrash
   - 限制同時播放的動畫數量

2. **Backdrop Filter**
   - `backdrop-blur` 在低階設備可能影響效能
   - 考慮對 `prefers-reduced-motion` 提供降級體驗

3. **Font Loading**
   - Google Fonts 使用 `display=swap` 避免 FOIT
   - 可考慮 Font Subsetting 減少下載體積

---

## Migration Strategy

1. **Phase 1**：安裝 Tailwind，保留現有 CSS 運作
2. **Phase 2**：逐步將 CSS classes 轉換為 Tailwind utilities
3. **Phase 3**：移除舊 CSS 規則
4. **驗證**：每階段進行視覺 diff 確認無回歸
