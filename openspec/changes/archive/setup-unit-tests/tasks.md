# 單元測試基礎設施任務清單

**Status: COMPLETED (2025-12-18)**

## Phase 1: 環境設定 ✅

- [x] **Task 1.1**: 更新 `backend/pyproject.toml` 新增 `httpx` 與 `pytest-mock` 依賴
- [x] **Task 1.2**: 更新 `worker/pyproject.toml` 新增 `pytest-mock` 依賴
- [x] **Task 1.3**: 建立 `backend/tests/__init__.py`
- [x] **Task 1.4**: 建立 `worker/tests/__init__.py`

## Phase 2: Backend 測試 Fixtures ✅

- [x] **Task 2.1**: 建立 `backend/tests/conftest.py`

## Phase 3: Backend 測試實作 ✅

- [x] **Task 3.1**: 建立 `backend/tests/test_models.py`
- [x] **Task 3.2**: 建立 `backend/tests/test_api.py`

## Phase 4: Worker 測試 Fixtures ✅

- [x] **Task 4.1**: 建立 `worker/tests/conftest.py`

## Phase 5: Worker 測試實作 ✅

- [x] **Task 5.1**: 建立 `worker/tests/test_stages.py`
- [x] **Task 5.2**: 建立 `worker/tests/test_pipeline.py`

## Phase 6: 驗證 ✅

- [x] **Task 6.1**: 執行 Backend 測試並確認通過 (8 passed, 73% coverage)
- [x] **Task 6.2**: 執行 Worker 測試並確認通過 (7 passed, 49% coverage)
- [x] **Task 6.3**: 產生覆蓋率報告
