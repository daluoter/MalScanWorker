## Why

目前 MalScanWorker 的掃描流程是單層的（線性掃描）。這意味著如果一個文件（如 ZIP 壓縮檔）內部包含了惡意執行檔，或者是 PDF 文件內部嵌入了惡意的釣魚 URL，系統只能針對外層容器文件進行掃描，而無法深入剖析內層的實際威脅載體（Payload）。
借鑑 Assemblyline 等進階惡意程式分析系統的設計，具備「遞迴式分析」（Recursive Analysis）機制是應對現代多層封裝惡意軟體（例如 Droppers, 惡意文檔等）的關鍵能力。系統必須能夠自動將掃描過程中提取出的「子樣本」重新提交至分析隊列中。

## What Changes

- **資料庫模型擴充**：在 `Job` 模型中新增 `parent_job_id` 欄位，用以追蹤子樣本與父樣本的關聯，建立分析樹（Analysis Tree）。
- **後端 API 支援**：修改 `/api/v1/files` 端點，允許在提交檔案時夾帶可選的 `parent_job_id`。
- **Worker 提交能力**：實作 `SubJobSubmitter` 或直接讓 Worker 具有透過內部共用邏輯（DB/MinIO/RabbitMQ）提交子樣本的能力。
- **提取分析階段 (Stages)**：
  - 新增 `ArchiveExtractStage`：專門針對 ZIP/TAR 等壓縮檔進行解壓縮，並將裡面的檔案作為子樣本提交。
  - 擴充 `IocExtractStage`：當提取出高風險的 URL 時，將其封裝為文字檔（或特定格式）作為子樣本提交。

## Capabilities

### New Capabilities
- `recursive-analysis`: 系統具備遞迴拆解與分析樣本的能力
- `archive-extraction`: 壓縮檔內含檔案解析與自動提交
- `job-hierarchy`: 在資料庫層級追蹤掃描任務的父子層級結構

### Modified Capabilities
- `ioc-extract`: 將單純提取 IOC 的流程擴充為具備觸發後續關聯掃描的能力

## Impact

- **Backend**：`models/job.py`（新增 `parent_job_id`）、`api/routes.py`（API 支援接受 `parent_job_id`）、`schemas/...`（回傳結構更新）。
- **Worker**：新增 `stages/archive_extract.py`，修改 `pipeline.py` 與 `stages/ioc_extract.py` 提供子樣本提交功能。
- **DB Migration**：必須進行 Alembic migration 來加入 `parent_job_id` 欄位（Foreign Key 關聯至 `jobs.id`）。
- **Tests**：需要實作測試確保父子樣本能正確建立與追蹤。
