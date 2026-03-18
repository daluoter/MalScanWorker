# Tasks: 支援常用壓縮檔格式

## Task 1: 新增依賴

- [x] 1.1 在 `worker/pyproject.toml` 中新增 `py7zr` 和 `rarfile` 依賴
- [x] 1.2 在 Worker Dockerfile 中新增 `unrar` 系統套件（供 `rarfile` 使用）

## Task 2: 重構 ArchiveExtractStage 支援多格式

- [x] 2.1 重寫 `worker/src/malscan_worker/stages/archive_extract.py`：
  - 新增格式偵測函式，依序判斷 ZIP → 7z → RAR → tar → gzip → bz2
  - 為每種格式實作獨立的解壓函式，統一回傳 `list[(path, filename, size)]`
  - 所有格式共用相同的安全防禦邏輯（大小限制、膨脹率、數量限制、path traversal）
  - tar 格式需過濾 symlink / hardlink / device 等特殊 entry
  - RAR 格式需處理 `unrar` 工具不存在時的優雅降級（skip 並記錄 warning）
  - 不支援的格式回傳 `skipped`

## Task 3: 修正 Pipeline DB Session 生命週期

- [x] 3.1 修改 `worker/src/malscan_worker/pipeline.py`：
  - 擴大 `async with AsyncSession(_engine) as session` 的範圍，涵蓋所有 stage 執行
  - 確保 `ctx.db` 在 `ArchiveExtractStage` 執行期間仍然有效

## Task 4: 更新測試

- [x] 4.1 更新 `worker/tests/test_stages.py`：
  - 新增 7z 檔案解壓測試
  - 新增 tar.gz 檔案解壓測試
  - 新增非壓縮檔 skip 測試
  - 測試深度超限 skip 行為
