# worker-yara-rules Specification

## Purpose
TBD - created by archiving change add-standard-yara-rules. Update Purpose after archive.
## Requirements
### Requirement: EICAR 測試字串偵測

系統 **SHALL** 提供 EICAR 標準測試字串規則，用於驗證惡意軟體偵測機制運作正常。

#### Scenario: 偵測標準 EICAR 字串

- **WHEN** 上傳的檔案包含 EICAR 測試字串 `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`
- **THEN** YARA 掃描 **SHALL** 觸發 `eicar` 規則
- **AND** 檔案最終判定 **SHALL** 為 `malicious`

---

### Requirement: Webshell 特徵偵測

系統 **SHALL** 提供常見 Webshell 特徵規則，能偵測 PHP、ASP、JSP 等常見 Webshell 模式。

#### Scenario: 偵測 PHP Webshell eval 注入

- **WHEN** 上傳檔案包含 `eval($_POST[` 字串
- **THEN** YARA 掃描 **SHALL** 觸發 `php_webshell` 規則

#### Scenario: 偵測 ASP Webshell cmd 執行

- **WHEN** 上傳檔案包含 `cmd.exe /c` 與 `Request("cmd")` 等特徵
- **THEN** YARA 掃描 **SHALL** 觸發 `asp_webshell` 規則

#### Scenario: 偵測 JSP Webshell Runtime.exec

- **WHEN** 上傳檔案包含 `<%@ Page Language="Jscript"` 或 `Runtime.getRuntime().exec` 等特徵
- **THEN** YARA 掃描 **SHALL** 觸發 `jsp_webshell` 規則

---

### Requirement: 挖礦程式特徵偵測

系統 **SHALL** 提供常見加密貨幣挖礦程式特徵規則。

#### Scenario: 偵測挖礦協議字串

- **WHEN** 上傳檔案包含 `stratum+tcp://` 或 `stratum+ssl://` 協議字串
- **THEN** YARA 掃描 **SHALL** 觸發 `crypto_miner` 規則

#### Scenario: 偵測挖礦池配置

- **WHEN** 上傳檔案包含 `mining_pool`、`wallet_address`、`pool_password` 等配置關鍵字
- **THEN** YARA 掃描 **SHALL** 觸發 `crypto_miner_config` 規則

---

### Requirement: 可疑 Windows API 偵測

系統 **SHALL** 提供可疑 Windows API 呼叫偵測規則。

#### Scenario: 偵測記憶體注入 API

- **WHEN** 上傳檔案包含 `VirtualAlloc`、`WriteProcessMemory`、`CreateRemoteThread` 等多個 API 字串
- **THEN** YARA 掃描 **SHALL** 觸發 `suspicious_api_calls` 規則

#### Scenario: 偵測 Registry 持久化

- **WHEN** 上傳檔案包含 `CurrentVersion\Run` 或 `Winlogon\Shell` 等 Registry 路徑
- **THEN** YARA 掃描 **SHALL** 觸發 `persistence_registry` 規則

---

### Requirement: 網路 IOC 指標偵測

系統 **SHALL** 提供網路行為指標規則，用於強化 URL/Domain 偵測（補充 IocExtractStage 功能）。

#### Scenario: 偵測 HTTP/HTTPS 連線

- **WHEN** 上傳檔案包含 `http://` 或 `https://` 協議字串
- **THEN** YARA 掃描 **SHALL** 觸發 `network_iocs` 規則
