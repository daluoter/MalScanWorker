# Tasks: 導入標準 YARA 規則集

## 1. 建立標準 YARA 規則檔案

- [x] 1.1 建立 `worker/rules/eicar.yar`：EICAR 測試字串規則（使用十六進制格式）
- [x] 1.2 建立 `worker/rules/webshells.yar`：Webshell 特徵規則
- [x] 1.3 建立 `worker/rules/crypto_miners.yar`：挖礦程式特徵規則
- [x] 1.4 建立 `worker/rules/suspicious.yar`：可疑 API/Registry 規則
- [x] 1.5 建立 `worker/rules/network.yar`：網路 IOC 指標規則

## 2. 清理與同步

- [x] 2.1 刪除 `worker/rules/placeholder.yar`
- [x] 2.2 更新 `k8s/yara-rules/configmap.yaml`：整合新規則

## 3. 驗證

- [x] 3.1 執行 `yara` CLI 驗證所有規則語法正確
- [x] 3.2 上傳 EICAR 測試檔確認觸發 `eicar` 規則
- [x] 3.3 上傳含有 `<% eval(request("cmd")) %>` 的文字檔確認觸發 `webshells` 規則
- [x] 3.4 執行現有 Worker 單元測試確保無迴歸
