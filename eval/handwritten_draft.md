# 手寫評估題（已 review）

> 起草：Claude · review：2026-10-05 全部通過 · 機器可讀版本：[handwritten.jsonl](handwritten.jsonl)
> 原起草日：2026-10-05 · 對應 [grill-decisions.md](../docs/grill-decisions.md) Q10、Q15
> 資料：ATT&CK v19.2。**每一個技巧 ID 都用程式確認過存在**，也確認過有沒有緩解方式。

## 怎麼 review

每一題請看三件事，在「OK」欄打 ✅ 或寫下要改的地方：

1. **問法自然嗎？** 真正的資安分析師會這樣問嗎？
2. **Gold passage 對嗎？** 這題的答案真的應該來自這份 Passage 嗎？
3. **有測到該測的東西嗎？** 看「為什麼出這題」那一欄

Gold passage 的寫法：`技巧 ID · Passage 類型`。⚠️ 標記代表那個技巧**沒有緩解方式**，Gold passage 是 No-mitigation statement。

---

## ② 換說法（15 題）

**測什麼**：問題刻意**不用技巧名稱裡的字**，看 Dense 懂不懂意思。BM25 在這類題目應該會比較吃力。

| # | 問題 | Gold passage | 為什麼出這題 | OK |
|---|---|---|---|---|
| 2-01 | How can I tell if someone is dumping credentials from the Windows process that keeps login secrets in memory? | T1003.001 LSASS Memory · Detection | 沒提到 LSASS，只描述它的功能 | ✅ |
| 2-02 | Attackers are trying one common password against many accounts to avoid lockouts — what is this? | T1110.003 Password Spraying · Overview | 描述行為，不說名稱 | ✅ |
| 2-03 | How do I stop users from getting compromised by malicious documents attached to emails? | T1566.001 Spearphishing Attachment · Mitigation | 「malicious documents attached to emails」對上 spearphishing attachment | ✅ |
| 2-04 | What can we do to limit the damage when malware scrambles our files and demands payment? | T1486 Data Encrypted for Impact · Mitigation | 口語說法的勒索軟體 | ✅ |
| 2-05 | How would I notice an attacker requesting service tickets so they can crack service account passwords offline? | T1558.003 Kerberoasting · Detection | 描述 Kerberoasting 的步驟，不說名稱 | ✅ |
| 2-06 | What is it called when malware hides its command traffic inside normal web browsing? | T1071.001 Web Protocols · Overview | 「hides in web browsing」對上 Web Protocols | ✅ |
| 2-07 | How do I spot attackers deleting backup snapshots so we can't restore our systems? | T1490 Inhibit System Recovery · Detection | 「backup snapshots」對上 shadow copies、system recovery | ✅ |
| 2-08 | What does it mean when an adversary logs in with a real employee's stolen username and password? | T1078 Valid Accounts · Overview | 「real employee's credentials」對上 Valid Accounts | ✅ |
| 2-09 | How can we protect our internet-facing web servers from being hacked through software bugs? | T1190 Exploit Public-Facing Application · Mitigation | 口語化的描述 | ✅ |
| 2-10 | How do I detect someone abusing the built-in Windows tool that loads DLLs to run malicious code? | T1218.011 Rundll32 · Detection | 沒提到 rundll32 | ✅ |
| 2-11 | An attacker pretends to be a domain controller to pull password hashes — how do I detect that? | T1003.006 DCSync · Detection | 描述 DCSync 的行為，不說名稱 | ✅ |
| 2-12 | How can I prevent attackers from forging the tokens our cloud single sign-on relies on? | T1606.002 SAML Tokens · Mitigation | 「single sign-on tokens」對上 SAML | ✅ |
| 2-13 | What is it when adversaries answer local name-lookup broadcasts to capture password hashes? | T1557.001 Name Resolution Poisoning and SMB Relay · Overview | 描述 LLMNR／NBT-NS 投毒，不說縮寫 | ✅ |
| 2-14 | Malware that checks whether it is running inside an analysis VM before doing anything — what is that? | T1497 Virtualization/Sandbox Evasion · Overview | 描述行為，不說名稱 | ✅ |
| 2-15 | Is there any way to prevent attackers from recording what users type? | T1056.001 Keylogging · Mitigation ⚠️ | **同時測 No-mitigation statement**：換了說法，還找得到「沒有緩解方式」那份嗎？ | ✅ |
---

## ③ 跨語言（15 題）

**測什麼**：用繁體中文問，資料是英文。第 4 章實驗中，只有 bge-m3 答得出這類題目。有幾題刻意**中英混用**（例如 LSASS、PowerShell），因為台灣的分析師常這樣講。

| # | 問題 | Gold passage | 為什麼出這題 | OK |
|---|---|---|---|---|
| 3-01 | 攻擊者把惡意程式寫進登錄檔的開機啟動位置，要怎麼偵測？ | T1547.001 Registry Run Keys / Startup Folder · Detection | 純中文描述 | ✅ |
| 3-02 | 密碼噴灑攻擊是什麼？ | T1110.003 Password Spraying · Overview | 技巧名稱的中文翻譯 | ✅ |
| 3-03 | 怎麼防止員工打開釣魚郵件裡的惡意附件？ | T1566.001 Spearphishing Attachment · Mitigation | 和 2-03 同一個技巧，可以比較中英文的差異 | ✅ |
| 3-04 | 勒索軟體把檔案加密了，要怎麼降低損害？ | T1486 Data Encrypted for Impact · Mitigation | 和 2-04 同一個技巧 | ✅ |
| 3-05 | 怎麼偵測有人從 LSASS 記憶體偷密碼？ | T1003.001 LSASS Memory · Detection | 中英混用 | ✅ |
| 3-06 | 攻擊者透過遠端桌面橫向移動，要怎麼防？ | T1021.001 Remote Desktop Protocol · Mitigation | 「遠端桌面」對上 RDP | ✅ |
| 3-07 | 什麼是 Kerberoasting？ | T1558.003 Kerberoasting · Overview | 中文句子裡夾一個英文專有名詞 | ✅ |
| 3-08 | 攻擊者用 PowerShell 下載並執行惡意腳本，該怎麼偵測？ | T1059.001 PowerShell · Detection | 第 5 章實驗的情境：會不會被 Mitigation 搶走？ | ✅ |
| 3-09 | 攻擊者竄改檔案的時間戳記來躲避調查，這是什麼手法？ | T1070.006 Timestomp · Overview | 「竄改時間戳記」對上 Timestomp | ✅ |
| 3-10 | 螢幕截圖這種攻擊有辦法預防嗎？ | T1113 Screen Capture · Mitigation ⚠️ | 中文 + No-mitigation statement | ✅ |
| 3-11 | 挖礦程式偷用公司電腦的資源，要怎麼偵測？ | T1496 Resource Hijacking · Detection | 「挖礦」對上 resource hijacking（cryptomining） | ✅ |
| 3-12 | 攻擊者在 Linux 上用 cron 排程來維持存取權限，要怎麼偵測？ | T1053.003 Cron · Detection | 中英混用；有相近的 T1053.005 Scheduled Task 可能搞混 | ✅ |
| 3-13 | 把惡意程式的檔名改成和系統正常檔案一樣來偽裝，是什麼技巧？ | T1036.005 Match Legitimate Resource Name or Location · Overview | 純中文描述 | ✅ |
| 3-14 | 怎麼防止攻擊者用 DNS 或其他非常規的協定把資料偷傳出去？ | T1048 Exfiltration Over Alternative Protocol · Mitigation | 「非常規的協定」對上 alternative protocol | ✅ |
| 3-15 | 瀏覽器的登入狀態被攻擊者劫持，要怎麼偵測？ | T1185 Browser Session Hijacking · Detection | 純中文描述 | ✅ |
---

## ④ 相近編號（15 題）

**測什麼**：只用技巧 ID 發問，而且**每個 ID 都有編號很接近的兄弟技巧**。第 5 章實驗中，Dense 會把 T1543.001 和 T1543.003 搞混，這類題目用來驗證 BM25 和混合檢索的價值。

| # | 問題 | Gold passage | 容易搞混的兄弟技巧 | OK |
|---|---|---|---|---|
| 4-01 | How do I detect T1543.001? | T1543.001 Launch Agent · Detection | .002 Systemd Service、.003 Windows Service | ✅ |
| 4-02 | Mitigations for T1543.002 | T1543.002 Systemd Service · Mitigation | .001、.003 | ✅ |
| 4-03 | What is T1059.003? | T1059.003 Windows Command Shell · Overview | .001 PowerShell、.004 Unix Shell | ✅ |
| 4-04 | Detection for T1059.004 | T1059.004 Unix Shell · Detection | .003、.006 Python | ✅ |
| 4-05 | T1055.001 mitigation | T1055.001 Dynamic-link Library Injection · Mitigation | .003、.012 | ✅ |
| 4-06 | What is T1055.003? | T1055.003 Thread Execution Hijacking · Overview | .001、.012 Process Hollowing | ✅ |
| 4-07 | How to detect T1218.010? | T1218.010 Regsvr32 · Detection | .005 Mshta、.011 Rundll32 | ✅ |
| 4-08 | T1218.005 mitigations | T1218.005 Mshta · Mitigation | .010、.011 | ✅ |
| 4-09 | What is T1021.006? | T1021.006 Windows Remote Management · Overview | .001 RDP、.002 SMB | ✅ |
| 4-10 | Detection for T1021.002 | T1021.002 SMB/Windows Admin Shares · Detection | .001、.006 | ✅ |
| 4-11 | How do I mitigate T1110.004? | T1110.004 Credential Stuffing · Mitigation | .001 Password Guessing、.003 Password Spraying | ✅ |
| 4-12 | What is T1110.001? | T1110.001 Password Guessing · Overview | .003、.004 | ✅ |
| 4-13 | T1053.003 detection | T1053.003 Cron · Detection | .005 Scheduled Task | ✅ |
| 4-14 | Mitigation for T1003.006 | T1003.006 DCSync · Mitigation | .001 LSASS Memory | ✅ |
| 4-15 | How to mitigate T1070.004? | T1070.004 File Deletion · Mitigation ⚠️ | .006 Timestomp（也沒有緩解方式）| ✅ |
---

## ⑥ 不支援的問題（15 題）

**測什麼**：LLM（關卡 3，[ADR 0004](../docs/adr/0004-refusal-gates.md)）發現找回來的 Passage 沒有答案時，會不會乖乖拒答，而不是憑記憶回答。原本規劃的「搜尋前比對攻擊者名單」已經拿掉（Q21）。預期行為全部都是 **Refusal（Unsupported question）**。

| # | 問題 | 類型 | 為什麼出這題 | OK |
|---|---|---|---|---|
| 6-01 | Which techniques does APT29 use? | Actor（Group） | 最典型的 Actor question | ✅ |
| 6-02 | What TTPs are associated with NobleBaron? | Actor（Group 別名） | NobleBaron 是 APT29 的別名，測規則有沒有涵蓋別名 | ✅ |
| 6-03 | Lazarus Group 用過哪些攻擊手法？ | Actor（Group，中文問句） | 測中文問法 | ✅ |
| 6-04 | Does FIN7 use spearphishing? | Actor（是非題） | ⚡ 邊界：是非題，但答案在關聯資料裡，RAG 答不完整 | ✅ |
| 6-05 | Which groups use T1059.001? | Actor（反過來問） | ⚡ 邊界：問題裡有技巧 ID，**很容易被誤判成 Technique question** | ✅ |
| 6-06 | Octo Tempest 常用哪些技巧？ | Actor（Group 別名，中文） | Octo Tempest 是 Scattered Spider 的別名 | ✅ |
| 6-07 | Which techniques does Mimikatz implement? | Actor（工具） | 軟體也屬於 Actor question | ✅ |
| 6-08 | What can Cobalt Strike do according to ATT&CK? | Actor（惡意程式） | 問法比較隱晦 | ✅ |
| 6-09 | Emotet 使用了哪些技巧？ | Actor（惡意程式，中文） | 測中文問法 | ✅ |
| 6-10 | List all techniques that affect macOS. | Aggregate | 最典型的 Aggregate question | ✅ |
| 6-11 | Which tactic has the most techniques? | Aggregate（統計） | 需要計算 | ✅ |
| 6-12 | How many sub-techniques are there in ATT&CK? | Aggregate（統計） | 需要計算 | ✅ |
| 6-13 | Which techniques have no mitigations? | Aggregate | ⚡ 邊界：和 No-mitigation statement 有關，容易被誤判 | ✅ |
| 6-14 | 列出所有跟竊取憑證有關的技巧 | Aggregate（中文） | 測中文的「列出所有」 | ✅ |
| 6-15 | What are the most commonly used techniques? | Aggregate | 「most commonly」需要統計關聯資料 | ✅ |
---

## ⑦ 沒有答案的題目（10 題）

**測什麼**：關卡 2（cosine 門檻）和關卡 3（LLM 判斷）。預期行為全部都是 **Refusal**。同時用來校正關卡 2 的門檻，以及計算**誤擋率**（拿來和其他題型比較：正常的題目有沒有被擋掉）。

| # | 問題 | 類型 | 預期由哪一關擋下 | OK |
|---|---|---|---|---|
| 7-01 | What's the weather in Taipei tomorrow? | 領域外 | 關卡 2 | ✅ |
| 7-02 | How do I bake sourdough bread? | 領域外 | 關卡 2 | ✅ |
| 7-03 | How do I configure a Kubernetes ingress controller? | 領域外（但是技術題） | 關卡 2，⚡ 但可能分數不夠低，要靠關卡 3 | ✅ |
| 7-04 | 台積電今天的股價多少？ | 領域外（中文） | 關卡 2 | ✅ |
| 7-05 | Write me a Python function that sorts a list. | 領域外（但有 Python 這個字） | ⚡ 可能對上 T1059.006 Python，要靠關卡 3 | ✅ |
| 7-06 | What is the CVSS score of T1486? | 相關但沒有答案 | 關卡 3：ATT&CK 的技巧沒有 CVSS 分數 | ✅ |
| 7-07 | Which EDR product is best at detecting T1055.012? | 相關但沒有答案 | 關卡 3：ATT&CK 不評比廠商 | ✅ |
| 7-08 | How many companies were hit by Kerberoasting in 2025? | 相關但沒有答案 | 關卡 3：ATT&CK 沒有統計數字 | ✅ |
| 7-09 | What changed for T1059 in ATT&CK v20? | 相關但沒有答案 | 關卡 3：系統固定在 v19.2 | ✅ |
| 7-10 | T1059 是哪一年被加進 ATT&CK 的？ | 相關但沒有答案 | 關卡 3。⚡ 見下方「待決定 C」 | ✅ |
---

## ⑧ 被撤銷的舊 ID（8 題）※ review 後新增

**測什麼**：問題用 v19.2 已經撤銷的舊 ID，系統要先換成新 ID 再搜尋（[ADR 0005](../docs/adr/0005-resolve-revoked-ids-before-retrieval.md)），回答時還要註明替換。Gold passage 是**新 ID** 的 Passage。

| # | 問題 | 舊 ID → 新 ID | Gold passage | OK |
|---|---|---|---|---|
| 8-01 | How do I detect T1086? | T1086 PowerShell → T1059.001 | T1059.001 PowerShell · Detection | ✅ |
| 8-02 | What is T1093? | T1093 Process Hollowing → T1055.012 | T1055.012 Process Hollowing · Overview | ✅ |
| 8-03 | How to detect T1070.001? | T1070.001 Clear Windows Event Logs → T1685.005 | T1685.005 Clear Windows Event Logs · Detection | ✅ |
| 8-04 | Mitigations for T1562.001 | T1562.001 Disable or Modify Tools → T1685 | T1685 Disable or Modify Tools · Mitigation | ✅ |
| 8-05 | What is T1574.002? | T1574.002 DLL Side-Loading → T1574.001 | T1574.001 DLL · Overview | ✅ |
| 8-06 | How can we mitigate T1193? | T1193 Spearphishing Attachment → T1566.001 | T1566.001 Spearphishing Attachment · Mitigation | ✅ |
| 8-07 | Detection for T1050 | T1050 New Service → T1543.003 | T1543.003 Windows Service · Detection | ✅ |
| 8-08 | T1077 要怎麼防？ | T1077 Windows Admin Shares → T1021.002 | T1021.002 SMB/Windows Admin Shares · Mitigation | ✅ |
8-05 特別注意：舊名稱 *DLL Side-Loading* 和新名稱 *DLL* 不一樣，只靠名稱比對會找不到。

---

## 已決定（2026-10-05，詳見 [grill-decisions.md](../docs/grill-decisions.md) Q17 到 Q20）

- **A → 保留**：2-15、3-10、4-15 測問法變難時，還找不找得到 No-mitigation statement（Q20）
- **B → 維持拒答**：6-04、6-05 都是 Actor question，因為答案只在關聯資料裡，不在 Passage 的文字裡；ADR 0001 已改寫理由（Q19）
- **C → Overview 加上戰術和平台，不加建立日期**：7-10 維持「沒有答案」，這是刻意不放的資訊（Q18）
- **D → 舊 ID 先換成新 ID 再搜尋**：新增上面的 ⑧ 8 題（Q17、ADR 0005）

---

## 原本待決定的事項（保留做紀錄）

**A. 2-15、3-10、4-15 是 No-mitigation statement 的題目**
Q10 規劃 ⑤「沒有緩解方式」的 15 題由程式自動產生。這 3 題手寫的另外測「換說法、中文、相近編號」的情況下，還找不找得到。要保留嗎？

**B. ⑥ 的三個邊界題（6-04、6-05、6-13）**
這三題最容易被誤判，是測試關卡 1 規則最好的題目。但如果你覺得 6-04（是非題）應該要回答，那 MVP 的範圍就要調整。你覺得呢？

**C. 7-10「T1059 是哪一年被加進 ATT&CK 的？」**
ATT&CK 的原始資料**其實有**這個資訊（STIX 的 `created` 欄位，T1059 是 2017-05-31），只是第 1 輪的設計沒有把它放進 Passage。要維持「沒有答案」，還是把建立日期加進 metadata 或 Overview Passage？

**D. 起草時發現的一件事**
我原本想用的三個常見 ID，在 v19.2 裡**已經被撤銷（revoked）**，並由新的 ID 取代：

| 舊 ID | 名稱 | 被取代成 |
|---|---|---|
| T1070.001 | Clear Windows Event Logs | **T1685.005** Clear Windows Event Logs |
| T1562.001 | Disable or Modify Tools | **T1685** Disable or Modify Tools |
| T1574.002 | DLL Side-Loading | **T1574.001** DLL |

網路上很多文章還在用這些舊 ID，所以**使用者很可能會問到**。ATT&CK 的資料裡有 `revoked-by` 關聯（共 157 筆），記錄每個舊 ID 被誰取代。要不要：
- 加幾題「問舊 ID」的評估題？
- 讓系統回答「T1070.001 已被 T1685.005 取代」，而不是直接拒答？這需要在第 1 輪的資料設計裡加一種新的處理方式。
