## Context

MalScanWorker 目前的架構可以有效利用多個靜態分析 (FileType, ClamAV, YARA, IOC Extract) 與動態分析 (Sandbox) 階段來分析單一檔案。然而，許多真實世界的惡意軟體會使用防毒軟體逃避技術，最常見的做法是將惡意程式封裝在壓縮檔 (ZIP/RAR) 內，或是以連結的形式嵌入於 PDF 或 Office 文檔中。目前 Worker 雖然可以透過 `IocExtractStage` 抓出 URL，或透過 `FileTypeStage` 識別出 ZIP，但無法自動對這些被封裝的內容進行二次掃描。

為解決此問題，我們需要實作遞迴分析機制，讓 Worker 階段在獲得有意義的子結構後，能自動將其建立為新的 Job 分派至 RabbitMQ。

## Goals / Non-Goals

**Goals:**
- 在資料庫層級建立 Parent-Child 的 Job 關聯結構。
- 賦予 Worker 節點將檔案與 URL 作為子任務提交回 MalScan 分析管線的能力。
- 實作新的解壓縮層 (ArchiveExtractStage) 來處理常見壓縮格式（主要支援 ZIP）。
- 使 `IocExtractStage` 能夠自動對提取出的 URL 提交子任務（透過寫入 .url 格式文字檔掃描）。

**Non-Goals:**
- 不實作遞迴深度的強制硬性限制（但可以實作基本的深度防止無限迴圈，或者依靠暫時的層數控制）。
- 不更改現有的前端 UI 以顯示樹狀結構（UI 顯示可以留作未來擴充）。
- 不實作惡意文檔 (PDF/Office) 內嵌 OLE 物件的深度二進位提取（本次先以 ZIP 壓縮檔和字串 URL 提取為主）。

## Decisions

### D1: Job Hierarchy (父子關聯) 追蹤方式

**選擇**：在 `Job` 表中新增以下欄位：
1. `parent_job_id` (UUID, nullable)：使用 ForeignKey 關聯到自身的 `jobs.id`。設定 `ondelete="CASCADE"`，確保刪除主任務時清理關聯（未來規模擴大時可考慮轉為邏輯刪除 Soft Delete）。
2. `depth` (Integer, default=0)：紀錄當前節點深度，API 和 Worker 可依此強制拒絕超過 `MAX_DEPTH` (如 3) 的建立請求。
3. **效能優化欄位**：新增 `total_sub`、`completed_sub`、`malicious_sub` 統計欄位。當 Worker 處理完子任務，可透過原子操作 (Atomic Increment) 更新父任務的計數，避免 API 頻繁執行 `COUNT(*)` 查詢。
- **反向關聯**：新增 `sub_jobs = relationship("Job", backref=backref("parent", remote_side=[id]))` 方便查詢整個任務樹狀結構。

**替代方案**：
- 建立一個專門的 `JobRelations` 表。

**理由**：在 `Job` 模型上加入 Self-Referential ForeignKey 是最直觀且效能影響最小的方式。

### D2: Worker 如何提交子任務

**選擇**：在 Worker 中實作一個共用的 `InternalJobSubmitter` 類別 (封裝於 `worker/src/malscan_worker/utils.py`)，並嚴格遵循以下操作順序以保持狀態一致性：
1. 計算 Hash 並檢查 DB 是否已有該檔案 (去重)。
2. 若無則上傳至 MinIO。
3. 寫入 DB 並將新 Job 狀態設為 `QUEUED`。
4. **發布 MQ 訊息** (使用帶有自動重連/Heartbeat 維護機制的單例長連線)。若此步驟發送失敗，必須 Catch Exception 並將 DB 中的 Job 狀態標記為 `FAILED`，避免父任務無限期等待「殭屍子任務」。

**理由**：封裝成獨立模組可維持行為一致性，也能正確處置例外狀況。

### D3: 解壓縮處理 (Archive Extract)

**選擇**：實作 `ArchiveExtractStage`，利用 Python 內建的 `zipfile` 模組讀取。
**防禦 Zip Slip**：除使用 `os.path.abspath()` 外，還必須加上 `if not abspath.startswith(base_dir):` 判斷，確保生成的絕對路徑必定是目標暫存目錄的子路徑。

**理由**：最嚴格的 Path Traversal 阻斷檢查。

### D4: URL 提取作為子樣本

**選擇**：在 `IocExtractStage` 擷取到 URL 時，包裝為 `{domain}.url` 提交。
**限制**：當前系統僅能對此純文字內容進行靜態掃描（如 YARA 命中）。未來若需分析真實威脅，需額外實作 `WebDownloaderStage`。

## Risks / Trade-offs

- **[Infinite Recursion]** 依靠 `Job.depth` (最高 3 層) 與檔案 SHA256 去重，雙重保障停止迴圈。
- **[Performance & Resource Exhaustion (Zip Bomb 防禦)]** 解壓縮大型壓縮檔或遭受惡意構造的「減肥炸彈」。
  - **緩解措施**：實施多層次攔截：
    1. **單一檔案體積上限**：對齊系統上傳上限（100MB）。
    2. **累計解壓體積上限**：單個 ZIP 內所有檔案總解壓大小不得超過 150MB。
    3. **壓縮膨脹率 (Expansion Ratio) 檢查**：核心防禦機制。若某檔案解壓後的體積超過原始壓縮包體積的 100 倍（例如 42KB 解出 4.5PB 的情況），即便未達絕對體積上限，也直接判定為惡意構造並中斷解壓，**且立刻將此父層解壓縮 Stage 的結果判定為 Malicious（防禦反制）**。
    4. **解壓檔案數量**：單層最多提取前 10 個附檔。
- **[Aggregated Status]** 目前父任務無法即時反映子任務的威脅結果，本次 PR 著重建立基礎架構。未來可由前端透過 Polling 統計或依賴後端原子計數完成狀態聚合。

## Development Stages Overview

1. **Stage 1**: 資料庫模型更新 (`parent_job_id`, `depth`, 狀態計數器等)，建立一切基石。
2. **Stage 2**: `InternalJobSubmitter` 核心開發 (整合 MQ 長連線與 MinIO、遵守發布順序與例外還原)。
3. **Stage 3**: 實作 `ArchiveExtractStage` 並串接 Submitter。
4. **Stage 4**: 初步狀態聚合 (提供 API 摘要計量，協助前端 Polling)。
