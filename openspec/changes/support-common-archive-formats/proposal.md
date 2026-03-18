# Proposal: 支援常用壓縮檔格式

## Summary

目前 `ArchiveExtractStage` 僅支援 ZIP 格式的壓縮檔解壓與遞迴分析。使用者上傳 7z、tar.gz、rar 等常用壓縮格式時，stage 直接 skip，內部檔案完全不會被掃描。此外，`pipeline.py` 中的 DB session 提前關閉，導致即使修復格式支援，sub-job 的資料庫寫入也會失敗。

## Motivation

真實世界的惡意軟體常透過 7z / tar.gz / RAR 等壓縮格式傳播以規避偵測。若系統僅能解壓 ZIP，大量威脅將被遺漏。

## Scope

**In Scope:**
- 擴展 `ArchiveExtractStage` 支援 7z、RAR、tar (含 .tar.gz / .tar.bz2 / .tar.xz)、gzip、bz2 格式
- 修正 `pipeline.py` 中 DB session 過早關閉的 bug
- 沿用現有的 Zip Bomb 防禦機制（大小限制、膨脹率檢查、數量限制）
- 更新單元測試
- Docker image 加入 `unrar` 系統依賴（供 RAR 解壓使用）

**Out of Scope:**
- 巢狀壓縮檔（已由 `depth` 機制遞迴處理）
- 前端 UI 變更
