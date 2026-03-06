# OpenSpec: Worker 核心效能優化 (Worker Core Performance Optimization)

**狀態:** Proposed
**日期:** 2025-03-05
**目標:** 大幅降低 Worker 分析單一檔案的延遲（從數秒至十幾秒降至毫秒級），並減少 CPU/Memory 資源的無謂消耗，同時確保系統能在無對外連線（Air-gapped）環境下穩定運作。

## 1. 背景與痛點 (Context)
目前 `malscan_worker` 的架構有三個主要的效能瓶頸：
1. **ClamAV 每次重新載入**: `ClamAVStage` 使用 `subprocess` 呼叫 `clamscan` CLI。這導致每次掃描都需要將龐大（數百 MB）的病毒特徵碼從硬碟載入記憶體，耗時極長且極度消耗 CPU。
2. **YARA 重複啟動 Process**: `YaraStage` 針對每一個 `.yar` 規則檔都開啟一個 `subprocess` 執行 `yara` CLI。如果有數十個規則檔，就會產生數十次的 Process 啟動成本。
3. **Pipeline 循序執行**: `pipeline.py` 透過 `for` 迴圈依序執行各個掃描階段（FileType -> ClamAV -> Yara -> IOC -> Sandbox）。這些靜態掃描階段彼此沒有依賴關係，循序執行浪費了等待時間。

## 2. 提案變更 (Proposed Changes)

### A. YARA 引擎優化 (記憶體常駐)
*   **依賴新增**: 在 `worker/pyproject.toml` 中新增 `yara-python` 套件。
*   **程式碼修改 (`worker/src/malscan_worker/stages/yara_scan.py`)**:
    *   移除 `subprocess` 呼叫。
    *   在 `YaraStage` 初始化時（或全域啟動時），一次性載入並編譯 (Compile) 所有 `/etc/yara/rules/*.yar` 規則，建立常駐記憶體的 rules 物件。
    *   掃描時直接使用 `rules.match(filepath)` 進行極速比對。

### B. ClamAV 引擎優化 (Daemon 模式 + 離線微服務)
*   **依賴新增**: 在 `worker/pyproject.toml` 中新增 `pyclamd` 套件。
*   **基礎設施修改 (重要)**:
    *   **Docker Compose (`docker-compose.yml`)**: 新增一個獨立的 `clamav` 服務，使用官方或輕量級映像檔（例如 `clamav/clamav:latest` 或 `mkodockx/docker-clamav`），設定 `CLAMAV_NO_FRESHCLAMD=true` 以適應無對外連線環境。
    *   **Kubernetes (`k8s/`)**: 新增 `clamav` 的 deployment 與 service 配置，同樣考量離線環境，並預留 Volume Mount 設定以便未來掛載本地 `.cvd` 檔案進行離線病毒庫更新。
*   **Worker 環境修改 (`worker/Dockerfile`)**:
    *   移除 `apt-get install clamav clamav-freshclam`，將 Worker 瘦身為純 Python 環境。
*   **程式碼修改 (`worker/src/malscan_worker/stages/clamav.py`)**:
    *   移除 `clamscan` CLI 呼叫。
    *   改用 `pyclamd` 或原生 socket 連線至獨立的 ClamAV 容器（例如 `tcp://clamav:3310`）。
    *   在 Worker 設定 (`worker/src/malscan_worker/config.py`) 中新增 `CLAMAV_HOST` 和 `CLAMAV_PORT` 環境變數。

### C. Pipeline 平行化 (Concurrent Execution)
*   **程式碼修改 (`worker/src/malscan_worker/pipeline.py`)**:
    *   將原本依序執行 `FileTypeStage`, `ClamAVStage`, `YaraStage`, `IocExtractStage` 的 `for` 迴圈，改為使用 `asyncio.gather(*tasks)` 讓它們平行執行。
    *   `SandboxStage` 由於目前是 Mock 狀態且可能較耗時或有特殊隔離需求，可評估是否加入平行佇列或接在靜態分析之後執行。
    *   調整 `stages_done` 狀態更新邏輯：在平行任務完成後，統一計算並更新至資料庫。

## 3. 實作步驟 (Implementation Steps)
1. **Infrastructure**: 更新 `docker-compose.yml` 和 `k8s/` 檔案，新增 ClamAV 服務。
2. **Worker Dockerfile**: 移除 ClamAV 系統依賴。
3. **Dependencies**: 在 `worker/pyproject.toml` 加入 `yara-python` 和 `pyclamd`，並更新 lock 檔。
4. **Config**: 在 Worker config 新增 ClamAV 連線設定。
5. **Stages Refactoring**:
    *   改寫 `yara_scan.py` 實作記憶體常駐編譯。
    *   改寫 `clamav.py` 實作 Socket 連線掃描。
6. **Pipeline Refactoring**: 修改 `pipeline.py` 實作 `asyncio.gather` 平行化。
7. **Testing**: 驗證修改後的 Worker 能否正確連線 ClamAV、正確載入 YARA 規則，並在離線環境下成功執行分析。

## 4. 預期效益 (Expected Benefits)
*   單一檔案掃描時間從 >5 秒 縮減至 <1 秒。
*   Worker 容器體積大幅縮小（移除 ClamAV 相關套件）。
*   系統能在無對外網路環境下穩定運作，且 ClamAV 與 Worker 資源獨立，避免 OOM 互相影響。
