# Design: 支援常用壓縮檔格式

## Context

`ArchiveExtractStage` 在先前的 `recursive-analysis` 變更中實作，但僅使用 Python 內建 `zipfile` 模組處理 ZIP 格式。`pipeline.py` 中建立 `StageContext` 的 `AsyncSession` 在 `async with` 區塊結束後即關閉，導致 stage 執行時 `ctx.db` 已失效。

## Goals / Non-Goals

**Goals:**
- 支援 7z、tar(.gz/.bz2/.xz)、gzip、bz2 等常用壓縮格式
- 修正 DB session 生命週期 bug
- 保持現有 Zip Bomb / Zip Slip 防禦不變
- 維持所有 stage 的行為一致性

**Non-Goals:**
- 不支援 RAR（需 `unrar` 系統工具）
- 不改動前端或 API

## Decisions

### D1: 多格式解壓策略

**選擇**：在 `ArchiveExtractStage` 中使用策略模式，根據檔案類型選擇不同的解壓處理器：

| 格式 | 偵測方法 | 解壓模組 |
|------|----------|----------|
| ZIP | `zipfile.is_zipfile()` | `zipfile` (Python 內建) |
| 7z | `py7zr.is_7zfile()` | `py7zr` (第三方) |
| RAR | `rarfile.is_rarfile()` | `rarfile` (第三方) + `unrar` (系統工具) |
| tar / tar.gz / tar.bz2 / tar.xz | `tarfile.is_tarfile()` | `tarfile` (Python 內建) |
| gzip (非 tar) | magic bytes `\x1f\x8b` | `gzip` (Python 內建) |
| bz2 (非 tar) | magic bytes `BZ` | `bz2` (Python 內建) |

**理由**：`zipfile`、`tarfile`、`gzip`、`bz2` 皆為 Python 標準庫，`py7zr` 和 `rarfile` 為第三方套件。偵測優先順序：ZIP → 7z → RAR → tar → gzip → bz2。

### D2: DB Session 生命週期修正

**選擇**：擴大 `pipeline.py` 中 `async with AsyncSession` 的範圍，使其涵蓋整個 pipeline 執行過程（包含所有 stage 的執行），確保 `ctx.db` 在 stage 執行期間始終有效。

**替代方案**：在 `ArchiveExtractStage` 內自行建立新的 session。
**理由**：擴大 session 範圍更簡潔，且保持 context 單一 session 的一致性。

### D3: 安全防禦沿用

沿用既有的防禦機制：
- 單檔大小上限（100MB）
- 累計大小上限（150MB）
- 膨脹率上限（100x）
- 最多解壓 10 個檔案
- Path traversal 防護
- `depth` 遞迴深度限制

所有格式均套用相同限制。

## Risks / Trade-offs

- **[py7zr 依賴]**：純 Python 套件，無需系統工具。
- **[rarfile + unrar 依賴]**：`rarfile` 需要系統安裝 `unrar` 工具。Worker Docker image 需在 Dockerfile 加入 `apt-get install -y unrar`。
- **[tar symlink 攻擊]**：tar 格式可能包含 symlink。使用 `data_filter`（Python 3.12+）或手動過濾 symlink 防禦。
- **[gzip/bz2 單檔]**：gzip/bz2 僅壓縮單一檔案，解壓後只產生一個子任務。
