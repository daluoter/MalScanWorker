# Change: 導入標準 YARA 規則集

## Why

目前本地 `worker/rules/placeholder.yar` 僅為佔位檔案，而 K8s ConfigMap 中已包含實際規則，導致開發與生產環境不一致。此外，專案缺乏業界標準的惡意軟體檢測規則（如 EICAR 測試字串、Webshell、挖礦程式），影響實際檢測能力。

## What Changes

- **[NEW]** `worker/rules/eicar.yar`: EICAR 標準測試字串規則（使用十六進制格式避免跳脫問題）
- **[NEW]** `worker/rules/webshells.yar`: 常見 Webshell 特徵規則
- **[NEW]** `worker/rules/crypto_miners.yar`: 挖礦協議特徵規則
- **[NEW]** `worker/rules/suspicious.yar`: 可疑 Windows API 與 Registry 規則（從 ConfigMap 同步）
- **[NEW]** `worker/rules/network.yar`: 網路 IOC 指標規則（從 ConfigMap 同步 network_indicators.yar）
- **[DELETE]** `worker/rules/placeholder.yar`: 移除無用佔位檔
- **[MODIFY]** `k8s/yara-rules/configmap.yaml`: 整合所有新規則至 ConfigMap

## Impact

- Affected specs: `worker-pipeline`（YARA 掃描階段）
- Affected code:
  - `worker/rules/*.yar`
  - `k8s/yara-rules/configmap.yaml`
  - `worker/Dockerfile`（規則複製路徑）
