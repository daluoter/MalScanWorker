## Stage 1: 資料庫模型與 API 更新

- [x] 1.1 修改 `backend/src/malscan/models/job.py`：
  - 新增 `parent_job_id` 欄位（UUID, ForeignKey("jobs.id", ondelete="CASCADE"), nullable=True），並定義 `sub_jobs` 反向關聯。
  - 新增 `depth` 欄位（Integer, default=0）用於控制遞迴層數。
  - 新增 `total_sub`, `completed_sub`, `malicious_sub` (皆為 Integer) 計算效能優化。
- [x] 1.2 建立 Alembic Migration 並執行升級。
- [x] 1.3 修改 `backend/src/malscan/schemas/requests.py`：`JobStatusResponse` 預先納入 `parent_job_id`, `depth`, 及統計欄位。
- [x] 1.4 修改 `backend/src/malscan/api/routes.py` (`upload_file`)：
  - 驗證 `parent_job_id` 是否真實存在於 DB。
  - 判斷父任務是否已超過 `MAX_DEPTH` (如 3)，若超過則拒絕建立子任務。

## Stage 2: Worker 子任務提交機制核心開發

- [x] 2.1 在 `worker/src/malscan_worker/utils/submission.py` 中建立 `InternalJobSubmitter`：
  - **循序邏輯**：1. 計算 SHA256 並搜尋 DB 檢查去重；2. 上傳至 MinIO；3. 寫入 DB 並設為 QUEUED；4. 發佈 MQ。
  - **狀態防禦**：若第 4 步發送 RabbitMQ 失敗，捕獲例外並更新 DB 該 Job 狀態為 FAILED（避免殭屍任務）。
  - **RabbitMQ 連線**：必須實作帶有 Heartbeat 與重連機制的單例長連線。

## Stage 3: 整合 ArchiveExtractStage 與 IOC

- [x] 3.1 實作 `worker/src/malscan_worker/stages/archive_extract.py`：
  - **Zip Bomb 與資源耗盡防禦**：
    - 最大單檔解壓大小及累計解壓大小（例如 100MB 單檔 / 150MB 累計上限）。
    - 壓縮膨脹率檢查（Extraction Ratio）：若單檔未壓縮大小大於整體壓縮檔大小的 100 倍，即視為惡意構造並提早引發例外，**並在 Stage Result 中直接給予 Malicious 判定（例如：設定 score=100，或添加 high_risk payload）**。
    - 最多解壓 10 個檔案，若 `ctx.depth >= MAX_DEPTH` 直接跳過。
  - **Zip Slip 防禦**：檢查 `os.path.abspath(target_path).startswith(os.path.abspath(base_dir))`，不合格即丟棄。
  - 提取符合條件的檔案，透過 `InternalJobSubmitter` 發送。
- [x] 3.2 更新 `worker/src/malscan_worker/stages/ioc_extract.py`：
  - 增加提取上限設定（例如每個實體檔案最多發送前 50 個 URL 作為子檔案）。
  - 將提取之 URL 打包為 `.url` 格式並發送子任務。
- [x] 3.3 將 `ArchiveExtractStage` 加入 `PARALLEL_STAGES`。

## Stage 4: 狀態聚合與測試驗證

- [x] 4.1 後端測試：驗證 API 端的有效性與 `MAX_DEPTH` 阻擋。
- [x] 4.2 非同步輪詢測試：使用模擬 ZIP，等待所有的 sub-jobs (整棵樹) 完成。
- [x] 4.3 去重與防止迴圈測試：上傳相同內容 ZIP / 循環引用的樣本，確保不會爆發 OOM 或無限建立 Job。
- [x] 4.4 狀態聚合整合 (基礎版)：確保 Worker 跑完子任務後，會調用 DB 原子操作更新父任務的計數欄位。
