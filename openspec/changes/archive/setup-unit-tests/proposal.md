# setup-unit-tests: 建立單元測試基礎設施

**Status: ARCHIVED (2025-12-18)**

## Summary

為 MalScanWorker 專案建立完整的單元測試架構。目前 `backend/tests` 與 `worker/tests` 目錄均為空，需要建立測試環境設定、conftest.py fixtures，以及針對核心模組的單元測試與整合測試。

## Results

- **Backend**: 8 tests passed, 73% coverage
- **Worker**: 7 tests passed, 49% coverage

## Motivation

- 專案目前缺乏任何自動化測試，無法保證程式碼品質
- `openspec/project.md` 明確要求達成 80% 覆蓋率
- 需要隔離外部服務（MinIO, RabbitMQ, ClamAV）進行可靠測試

## Scope

### Backend 測試
1. **測試依賴更新**：新增 `httpx` 與 `pytest-mock`
2. **conftest.py**：設定 async fixtures（mock DB session, MinIO, RabbitMQ）
3. **test_api.py**：測試 `/api/v1/files`、`/jobs/{id}`、`/reports/{id}` 端點
4. **test_models.py**：測試 Job 與 File 模型建立與關聯

### Worker 測試
1. **測試依賴更新**：新增 `pytest-mock`
2. **conftest.py**：設定 Stage 測試用 fixtures
3. **test_stages.py**：針對 `FileTypeStage`、`IocExtractStage` 等純邏輯 Stage 編寫單元測試
4. **test_pipeline.py**：使用 Mock Stages 測試 `run_pipeline` 流程控制

## Technical Approach

### Mocking 策略
使用 `pytest-mock` 與 `unittest.mock` 隔離外部依賴：
- **DB Session**：使用 SQLAlchemy 的 in-memory SQLite 或 mock AsyncSession
- **MinIO Client**：Mock `upload_file` / `download_file` 函式
- **RabbitMQ**：Mock `publish_job` 函式
- **ClamAV/YARA CLI**：Mock `subprocess` 調用
