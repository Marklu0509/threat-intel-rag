# Faithfulness labelling sheet

For each claim, decide whether the cited passages support it — using only those passages, not your own knowledge. Write one of `supported / partial / unsupported` after **Your verdict**. Do not open the judge's results until you have finished.

The judge's rubric, which applies to you too (grill-decisions Q36):

```text
Verdicts:
- "supported": everything the claim asserts is in its cited passages. Allowed: rewording
  with the same meaning; summarising or generalising what the passages say (e.g. calling
  the methods they list "the main ways"); technique names and IDs from a passage heading.
- "partial": the claim's main point is in its cited passages, but it adds or changes a
  detail they don't support — a new fact, tool, step or number, or a stronger certainty
  than the passage expresses ("may indicate" stated as "indicates").
- "unsupported": the claim's main point is not in its cited passages, even if some words
  overlap, or the passages contradict it.
```

---

## C01

**Question**: 攻擊者透過遠端桌面橫向移動，要怎麼防？

**Claim**: 應考慮將本機管理員群組從允許透過 RDP 登入的群組清單中移除。

**[T1563.002:mitigation]**

T1563.002 RDP Hijacking (sub-technique of T1563 Remote Service Session Hijacking) — Mitigation
- Audit: Audit the Remote Desktop Users group membership regularly. Remove unnecessary accounts and groups from Remote Desktop Users groups.
- Disable or Remove Feature or Program: Disable the RDP service if it is unnecessary.
- Limit Access to Resource Over Network: Use remote desktop gateways.
- Network Segmentation: Enable firewall rules to block RDP traffic between network security zones within a network.
- Operating System Configuration: Change GPOs to define shorter timeouts sessions and maximum amount of time any single session can be active. Change GPOs to specify the maximum amount of time that a disconnected session stays active on the RD session host server.
- Privileged Account Management: Consider removing the local Administrators group from the list of groups allowed to log in through RDP.
- User Account Management: Limit remote user permissions if remote access is necessary.

**Your verdict**: supported

## C02

**Question**: Mitigations for T1562.001

**Claim**: Restrict File and Directory Permissions: Ensure proper process and file permissions are in place to prevent adversaries from disabling or interfering with security services.

**[T1685:mitigation]**

T1685 Disable or Modify Tools — Mitigation
- Audit: Periodically verify that tools are functioning appropriately – for example, that all expected hosts with EDRs or monitoring agents are checking in to the central console. Check EDRs to ensure that no unexpected exclusion paths have been added. In Microsoft Defender for Endpoint, exclusions can be reviewed with the `Get-MpPreference` cmdlet.
- Disable or Remove Feature or Program: Consider removing previous versions of tools that are unnecessary to the environment when possible.
- Execution Prevention: Use application control where appropriate, especially regarding the execution of tools outside of the organization's security policies (such as rootkit removal tools) that have been abused to impair system defenses. Ensure that only approved security applications are used and running on enterprise systems.
- Restrict File and Directory Permissions: Ensure proper process and file permissions are in place to prevent adversaries from disabling or interfering with security services.
- Restrict Registry Permissions: Ensure proper Registry permissions are in place to prevent adversaries from disabling or interfering with security services.
- Software Configuration: Consider automatically relaunching forwarding mechanisms at recurring intervals (ex: temporal, on-logon, etc.) as well as applying appropriate change management to firewall rules and other related system configurations.
- User Account Management: Ensure proper user permissions are in place to prevent adversaries from disabling or interfering with security services.

**Your verdict**: supported

## C03

**Question**: T1077 要怎麼防？

**Claim**: 建議停用 Windows 管理員共享（administrative shares）。

**[T1021.002:mitigation]**

T1021.002 SMB/Windows Admin Shares (sub-technique of T1021 Remote Services) — Mitigation
- Filter Network Traffic: Consider using the host firewall to restrict file sharing communications such as SMB.
- Limit Access to Resource Over Network: Consider disabling Windows administrative shares.
- Password Policies: Do not reuse local administrator account passwords across systems. Ensure password complexity and uniqueness such that the passwords cannot be cracked or guessed.
- Privileged Account Management: Deny remote use of local admin credentials to log into systems. Do not allow domain user accounts to be in the local Administrators group multiple systems.

**Your verdict**: supported

## C04

**Question**: 什麼是 Kerberoasting？

**Claim**: 攻擊者可能濫用有效的 Kerberos 票證授予票證（TGT）或嗅探網路流量，以取得可能易受暴力破解攻擊的票證授予服務（TGS）票證。

**[T1558.003:overview]**

T1558.003 Kerberoasting (sub-technique of T1558 Steal or Forge Kerberos Tickets) — Overview
Adversaries may abuse a valid Kerberos ticket-granting ticket (TGT) or sniff network traffic to obtain a ticket-granting service (TGS) ticket that may be vulnerable to Brute Force (T1110). 

Service principal names (SPNs) are used to uniquely identify each instance of a Windows service. To enable authentication, Kerberos requires that SPNs be associated with at least one service logon account (an account specifically tasked with running a service).

Adversaries possessing a valid Kerberos ticket-granting ticket (TGT) may request one or more Kerberos ticket-granting service (TGS) service tickets for any SPN from a domain controller (DC). Portions of these tickets may be encrypted with the RC4 algorithm, meaning the Kerberos 5 TGS-REP etype 23 hash of the service account associated with the SPN is used as the private key and is thus vulnerable to offline Brute Force (T1110) attacks that may expose plaintext credentials. 

This same behavior could be executed using service tickets captured from network traffic.

Cracked hashes may enable Persistence (TA0003), Privilege Escalation (TA0004), and Lateral Movement (TA0008) via access to Valid Accounts (T1078).
Tactics: Credential Access
Platforms: Windows

**Your verdict**: supported

## C05

**Question**: 攻擊者把惡意程式寫進登錄檔的開機啟動位置，要怎麼偵測？

**Claim**: 在 Windows 上，可以監控登錄檔 Run 鍵或啟動資料夾中使用者或系統登入腳本的修改與執行。

**[T1037:detection]**

T1037 Boot or Logon Initialization Scripts — Detection
- Boot or Logon Initialization Scripts Detection Strategy
  - [Windows] Monitoring modification and execution of user or system logon scripts such as in registry Run keys or startup folders.
  - [Linux] Detection of changes or execution of shell initialization scripts like .bashrc, .profile, or /etc/profile for persistence.
  - [macOS] Monitoring for modification and execution of login hook scripts or LaunchAgents/LaunchDaemons used for persistence.
  - [ESXi] Detection of modification to ESXi rc.local.d or rc scripts that are used to execute on boot.
  - [Network Devices] Detection of changes to device startup-config files that include boot scripts or scheduled execution routines.

**Your verdict**: supported

## C06

**Question**: 攻擊者把惡意程式寫進登錄檔的開機啟動位置，要怎麼偵測？

**Claim**: 在 Windows 上，可以偵測攻擊者修改登錄檔金鑰以在啟動時載入惡意腳本的行為。

**[T1137:detection]**

T1137 Office Application Startup — Detection
- Detect Office Startup-Based Persistence via Macros, Forms, and Registry Hooks
  - [Windows] Office-based persistence via Office template macros, Outlook forms/rules/homepage, or registry-persistent scripts. Adversary modifies registry keys or Office application directories to load malicious scripts at startup.
  - [Office Suite] Startup-based persistence mechanisms within Microsoft Office Suite like template macros and home page redirects being configured through internal automation or client-side settings.

**Your verdict**: supported

## C07

**Question**: 密碼噴灑攻擊是什麼？

**Claim**: 攻擊者也可能針對使用聯合驗證協定的單一登入（SSO）及雲端應用程式，以及 Office 365 等對外郵件應用程式進行密碼噴灑。

**[T1110.003:overview]**

T1110.003 Password Spraying (sub-technique of T1110 Brute Force) — Overview
Adversaries may use a single or small list of commonly used passwords against many different accounts to attempt to acquire valid account credentials. Password spraying uses one password (e.g. 'Password01'), or a small list of commonly used passwords, that may match the complexity policy of the domain. Logins are attempted with that password against many different accounts on a network to avoid account lockouts that would normally occur when brute forcing a single account with many passwords. 

Typically, management services over commonly used ports are used when password spraying. Commonly targeted services include the following:

* SSH (22/TCP)
* Telnet (23/TCP)
* FTP (21/TCP)
* NetBIOS / SMB / Samba (139/TCP & 445/TCP)
* LDAP (389/TCP)
* Kerberos (88/TCP)
* RDP / Terminal Services (3389/TCP)
* HTTP/HTTP Management Services (80/TCP & 443/TCP)
* MSSQL (1433/TCP)
* Oracle (1521/TCP)
* MySQL (3306/TCP)
* VNC (5900/TCP)

In addition to management services, adversaries may "target single sign-on (SSO) and cloud-based applications utilizing federated authentication protocols," as well as externally facing email applications, such as Office 365.

In order to avoid detection thresholds, adversaries may deliberately throttle password spraying attempts to avoid triggering security alerting. Additionally, adversaries may leverage LDAP and Kerberos authentication attempts, which are less likely to trigger high-visibility events such as Windows "logon failure" event ID 4625 that is commonly triggered by failed SMB connection attempts.
Tactics: Credential Access
Platforms: Containers, ESXi, IaaS, Identity Provider, Linux, Network Devices, Office Suite, SaaS, Windows, macOS

**Your verdict**: supported

## C08

**Question**: What is T1055.003?

**Claim**: T1055.003 是一種在另一個存活程序的位址空間中執行任意代碼的方法。

**[T1055.003:overview]**

T1055.003 Thread Execution Hijacking (sub-technique of T1055 Process Injection) — Overview
Adversaries may inject malicious code into hijacked processes in order to evade process-based defenses as well as possibly elevate privileges. Thread Execution Hijacking is a method of executing arbitrary code in the address space of a separate live process. 

Thread Execution Hijacking is commonly performed by suspending an existing process then unmapping/hollowing its memory, which can then be replaced with malicious code or the path to a DLL. A handle to an existing victim process is first created with native Windows API calls such as OpenThread. At this point the process can be suspended then written to, realigned to the injected code, and resumed via SuspendThread , VirtualAllocEx, WriteProcessMemory, SetThreadContext, then ResumeThread respectively.

This is very similar to Process Hollowing (T1055.012) but targets an existing process rather than creating a process in a suspended state. 

Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges. Execution via Thread Execution Hijacking may also evade detection from security products since the execution is masked under a legitimate process.
Tactics: Stealth, Privilege Escalation
Platforms: Windows

**Your verdict**: supported

## C09

**Question**: How would I notice an attacker requesting service tickets so they can crack service account passwords offline?

**Claim**: You can notice this activity by monitoring for anomalous Kerberos TGS requests (Event ID 4769) that use RC4 encryption (etype 0x17).

**[T1558.003:detection]**

T1558.003 Kerberoasting (sub-technique of T1558 Steal or Forge Kerberos Tickets) — Detection
- Detect Kerberoasting Attempts (T1558.003)
  - [Windows] Detects Kerberoasting attempts by monitoring for anomalous Kerberos TGS requests (Event ID 4769) with RC4 encryption (etype 0x17), accounts requesting an unusual number of service tickets in a short period, or service accounts targeted outside normal usage baselines. Also correlates suspicious process activity (e.g., Mimikatz invoking LSASS access) with Kerberos ticket anomalies.

**Your verdict**: supported

## C10

**Question**: What is it called when malware hides its command traffic inside normal web browsing?

**Claim**: Commands and results are embedded within the protocol traffic between the client and server using protocols such as HTTP/S and WebSocket.

**[T1071.001:overview]**

T1071.001 Web Protocols (sub-technique of T1071 Application Layer Protocol) — Overview
Adversaries may communicate using application layer protocols associated with web traffic to avoid detection/network filtering by blending in with existing traffic. Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic between the client and server. 

Protocols such as HTTP/S and WebSocket that carry web traffic may be very common in environments. HTTP/S packets have many fields and headers in which data can be concealed. An adversary may abuse these protocols to communicate with systems under their control within a victim network while also mimicking normal, expected traffic.
Tactics: Command and Control
Platforms: ESXi, Linux, macOS, Network Devices, Windows

**Your verdict**: supported

## C11

**Question**: How can we mitigate T1193?

**Claim**: Enable auditing and monitoring for email attachments and file transfers to detect and investigate suspicious activity.

**[T1566.001:mitigation]**

T1566.001 Spearphishing Attachment (sub-technique of T1566 Phishing) — Mitigation
- Antivirus/Antimalware: Anti-virus can also automatically quarantine suspicious files.
- Audit: Enable auditing and monitoring for email attachments and file transfers to detect and investigate suspicious activity. Regularly review logs for anomalies related to attachments containing potentially malicious content, as well as any attempts to execute or interact with these files. This practice helps identify spearphishing attempts before they can lead to further compromise.
- Network Intrusion Prevention: Network intrusion prevention systems and systems designed to scan and remove malicious email attachments can be used to block activity.
- Restrict Web-Based Content: Block unknown or unused attachments by default that should not be transmitted over email as a best practice to prevent some vectors, such as .scr, .exe, .pif, .cpl, etc. Some email scanning devices can open and analyze compressed and encrypted formats, such as zip and rar that may be used to conceal malicious attachments.
- Software Configuration: Use anti-spoofing and email authentication mechanisms to filter messages based on validity checks of the sender domain (using SPF) and integrity of messages (using DKIM). Enabling these mechanisms within an organization (through policies such as DMARC) may enable recipients (intra-org and cross domain) to perform similar message filtering and validation.
- User Account Management: Apply user account management principles to limit permissions for accounts interacting with email attachments, ensuring that only necessary accounts have the ability to open or execute files. Restricting account privileges reduces the potential impact of malicious attachments by preventing unauthorized execution or spread of malware within the environment.
- User Training: Users can be trained to identify social engineering techniques and spearphishing emails.

**Your verdict**: supported

## C12

**Question**: 怎麼防止員工打開釣魚郵件裡的惡意附件？

**Claim**: 預設封鎖不應透過電子郵件傳輸的未知或未使用附件類型，例如 .scr、.exe、.pif 和 .cpl 等。

**[T1566.001:mitigation]**

T1566.001 Spearphishing Attachment (sub-technique of T1566 Phishing) — Mitigation
- Antivirus/Antimalware: Anti-virus can also automatically quarantine suspicious files.
- Audit: Enable auditing and monitoring for email attachments and file transfers to detect and investigate suspicious activity. Regularly review logs for anomalies related to attachments containing potentially malicious content, as well as any attempts to execute or interact with these files. This practice helps identify spearphishing attempts before they can lead to further compromise.
- Network Intrusion Prevention: Network intrusion prevention systems and systems designed to scan and remove malicious email attachments can be used to block activity.
- Restrict Web-Based Content: Block unknown or unused attachments by default that should not be transmitted over email as a best practice to prevent some vectors, such as .scr, .exe, .pif, .cpl, etc. Some email scanning devices can open and analyze compressed and encrypted formats, such as zip and rar that may be used to conceal malicious attachments.
- Software Configuration: Use anti-spoofing and email authentication mechanisms to filter messages based on validity checks of the sender domain (using SPF) and integrity of messages (using DKIM). Enabling these mechanisms within an organization (through policies such as DMARC) may enable recipients (intra-org and cross domain) to perform similar message filtering and validation.
- User Account Management: Apply user account management principles to limit permissions for accounts interacting with email attachments, ensuring that only necessary accounts have the ability to open or execute files. Restricting account privileges reduces the potential impact of malicious attachments by preventing unauthorized execution or spread of malware within the environment.
- User Training: Users can be trained to identify social engineering techniques and spearphishing emails.

**Your verdict**: supported

## C13

**Question**: How do I stop users from getting compromised by malicious documents attached to emails?

**Claim**: Network intrusion prevention systems and tools that scan and remove malicious email attachments can be used to block activity.

**[T1566.001:mitigation]**

T1566.001 Spearphishing Attachment (sub-technique of T1566 Phishing) — Mitigation
- Antivirus/Antimalware: Anti-virus can also automatically quarantine suspicious files.
- Audit: Enable auditing and monitoring for email attachments and file transfers to detect and investigate suspicious activity. Regularly review logs for anomalies related to attachments containing potentially malicious content, as well as any attempts to execute or interact with these files. This practice helps identify spearphishing attempts before they can lead to further compromise.
- Network Intrusion Prevention: Network intrusion prevention systems and systems designed to scan and remove malicious email attachments can be used to block activity.
- Restrict Web-Based Content: Block unknown or unused attachments by default that should not be transmitted over email as a best practice to prevent some vectors, such as .scr, .exe, .pif, .cpl, etc. Some email scanning devices can open and analyze compressed and encrypted formats, such as zip and rar that may be used to conceal malicious attachments.
- Software Configuration: Use anti-spoofing and email authentication mechanisms to filter messages based on validity checks of the sender domain (using SPF) and integrity of messages (using DKIM). Enabling these mechanisms within an organization (through policies such as DMARC) may enable recipients (intra-org and cross domain) to perform similar message filtering and validation.
- User Account Management: Apply user account management principles to limit permissions for accounts interacting with email attachments, ensuring that only necessary accounts have the ability to open or execute files. Restricting account privileges reduces the potential impact of malicious attachments by preventing unauthorized execution or spread of malware within the environment.
- User Training: Users can be trained to identify social engineering techniques and spearphishing emails.

**Your verdict**: supported

## C14

**Question**: 攻擊者透過遠端桌面橫向移動，要怎麼防？

**Claim**: 應使用遠端桌面閘道來管理連線與安全性設定。

**[T1563.002:mitigation]**

T1563.002 RDP Hijacking (sub-technique of T1563 Remote Service Session Hijacking) — Mitigation
- Audit: Audit the Remote Desktop Users group membership regularly. Remove unnecessary accounts and groups from Remote Desktop Users groups.
- Disable or Remove Feature or Program: Disable the RDP service if it is unnecessary.
- Limit Access to Resource Over Network: Use remote desktop gateways.
- Network Segmentation: Enable firewall rules to block RDP traffic between network security zones within a network.
- Operating System Configuration: Change GPOs to define shorter timeouts sessions and maximum amount of time any single session can be active. Change GPOs to specify the maximum amount of time that a disconnected session stays active on the RD session host server.
- Privileged Account Management: Consider removing the local Administrators group from the list of groups allowed to log in through RDP.
- User Account Management: Limit remote user permissions if remote access is necessary.

**Your verdict**: partial

## C15

**Question**: 瀏覽器的登入狀態被攻擊者劫持，要怎麼偵測？

**Claim**: 偵測對瀏覽器會話 Cookie 存儲（如 Chrome 的 Cookies SQLite 數據庫）或瀏覽器進程內存的可疑訪問。

**[T1539:detection]**

T1539 Steal Web Session Cookie — Detection
- Detection of Web Session Cookie Theft via File, Memory, and Network Artifacts
  - [Windows] Detects suspicious access to browser session cookie storage (e.g., Chrome’s `Cookies` SQLite DB) or memory reads of browser processes. Anomalous injection or memory dump utilities targeting browser processes such as `chrome.exe`, `firefox.exe`, or `msedge.exe`.
  - [Linux] Detects access to known browser cookie files (e.g., `~/.mozilla/firefox/*.default/cookies.sqlite`, `~/.config/google-chrome/`) and suspicious reads of browser memory via `/proc/[pid]/mem` or ptrace.
  - [macOS] Detects unauthorized access to browser cookie paths (e.g., `~/Library/Application Support/Google/Chrome/Default/Cookies`) or `task_for_pid`/`vm_read` calls to Safari/Chrome memory space.
  - [Office Suite] Detects automation macros or VBA scripts in documents that access browser file paths, read cookie data, or attempt to exfiltrate browser session tokens over HTTP.
  - [SaaS] Detects use of session cookies or authentication tokens from unusual user agents or locations. Identifies token reuse without reauthentication or attempts to bypass MFA using previously stolen cookies.

**Your verdict**: supported

## C16

**Question**: What is T1059.003?

**Claim**: T1059.003 是 T1059 Command and Scripting Interpreter 的子技術之一。

**[T1059:overview]**

T1059 Command and Scripting Interpreter — Overview
Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries. These interfaces and languages provide ways of interacting with computer systems and are a common feature across many different platforms. Most systems come with some built-in command-line interface and scripting capabilities, for example, macOS and Linux distributions include some flavor of Unix Shell (T1059.004) while Windows installations include the Windows Command Shell (T1059.003) and PowerShell (T1059.001).

There are also cross-platform interpreters such as Python (T1059.006), as well as those commonly associated with client applications such as JavaScript (T1059.007) and Visual Basic (T1059.005).

Adversaries may abuse these technologies in various ways as a means of executing arbitrary commands. Commands and scripts can be embedded in Initial Access (TA0001) payloads delivered to victims as lure documents or as secondary payloads downloaded from an existing C2. Adversaries may also execute commands through interactive terminals/shells, as well as utilize various Remote Services (T1021) in order to achieve remote Execution.
Tactics: Execution
Platforms: Containers, ESXi, IaaS, Identity Provider, Linux, macOS, Network Devices, Office Suite, SaaS, Windows
Sub-techniques: T1059.001 PowerShell; T1059.002 AppleScript; T1059.003 Windows Command Shell; T1059.004 Unix Shell; T1059.005 Visual Basic; T1059.006 Python; T1059.007 JavaScript; T1059.008 Network Device CLI; T1059.009 Cloud API; T1059.010 AutoHotKey & AutoIT; T1059.011 Lua; T1059.012 Hypervisor CLI; T1059.013 Container CLI/API

**Your verdict**: supported

## C17

**Question**: How do I detect T1086?

**Claim**: Detect behavioral chains where PowerShell is launched with encoded commands, unusual parent processes, or suspicious modules loaded, potentially followed by network connections or child process spawning.

**[T1059.001:detection]**

T1059.001 PowerShell (sub-technique of T1059 Command and Scripting Interpreter) — Detection
- Abuse of PowerShell for Arbitrary Execution
  - [Windows] Detects behavioral chains where PowerShell is launched with encoded commands, unusual parent processes, or suspicious modules loaded, potentially followed by network connections or child process spawning. Supports detection of both direct (powershell.exe) and indirect (.NET automation) invocations.

**Your verdict**: supported

## C18

**Question**: How do I detect T1086?

**Claim**: Note that T1086 was revoked and replaced by T1059.001 in ATT&CK v19.2.

**[T1059.001:overview]**

T1059.001 PowerShell (sub-technique of T1059 Command and Scripting Interpreter) — Overview
Adversaries may abuse PowerShell commands and scripts for execution. PowerShell is a powerful interactive command-line interface and scripting environment included in the Windows operating system. Adversaries can use PowerShell to perform a number of actions, including discovery of information and execution of code. Examples include the Start-Process cmdlet which can be used to run an executable and the Invoke-Command cmdlet which runs a command locally or on a remote computer (though administrator permissions are required to use PowerShell to connect to remote systems).

PowerShell may also be used to download and run executables from the Internet, which can be executed from disk or in memory without touching disk.

A number of PowerShell-based offensive testing tools are available, including Empire (S0363), PowerSploit (S0194), PoshC2 (S0378), and PSAttack.

PowerShell commands/scripts can also be executed without directly invoking the powershell.exe binary through interfaces to PowerShell's underlying System.Management.Automation assembly DLL exposed through the .NET framework and Windows Common Language Interface (CLI).
Tactics: Execution
Platforms: Windows

**Your verdict**: unsupported

## C19

**Question**: How do I detect T1543.001?

**Claim**: Correlate file write activity with the execution of launchctl or unsigned binaries invoked at login.

**[T1543.001:detection]**

T1543.001 Launch Agent (sub-technique of T1543 Create or Modify System Process) — Detection
- Detection of Launch Agent Creation or Modification on macOS
  - [macOS] Detects creation or modification of user-level Launch Agents in monitored directories using `.plist` files with suspicious `ProgramArguments` or `RunAtLoad` keys. Correlates file write activity with execution of `launchctl` or unsigned binaries invoked at login.

**Your verdict**: supported

## C20

**Question**: 瀏覽器的登入狀態被攻擊者劫持，要怎麼偵測？

**Claim**: 偵測攻擊者創建新的登錄會話或使用明確憑據，並驅動受害者的瀏覽器訪問內網資源的行為。

**[T1185:detection]**

T1185 Browser Session Hijacking — Detection
- Detect browser session hijacking via privilege, handle access, and remote thread into browsers
  - [Windows] Adversary gains high integrity or special privileges (e.g., SeDebugPrivilege), locates a running browser process, opens it with write/inject rights, and modifies it (e.g., CreateRemoteThread / DLL load) to inherit cookies/tokens or establish a browser pivot. Optional step: create a new logon session or use explicit credentials, then drive the victim browser to intranet resources.

**Your verdict**: supported

## C21

**Question**: 攻擊者透過遠端桌面橫向移動，要怎麼防？

**Claim**: 應確保啟用網路層級驗證（Network Level Authentication），以強制遠端桌面會話在建立會話及顯示登入畫面之前進行驗證。

**[T1546.008:mitigation]**

T1546.008 Accessibility Features (sub-technique of T1546 Event Triggered Execution) — Mitigation
- Execution Prevention: Adversaries can replace accessibility features binaries with alternate binaries to execute this technique. Identify and block potentially malicious software executed through accessibility features functionality by using application control tools, like Windows Defender Application Control, AppLocker, or Software Restriction Policies where appropriate.
- Limit Access to Resource Over Network: If possible, use a Remote Desktop Gateway to manage connections and security configuration of RDP within a network.
- Operating System Configuration: To use this technique remotely, an adversary must use it in conjunction with RDP. Ensure that Network Level Authentication is enabled to force the remote desktop session to authenticate before the session is created and the login screen displayed. It is enabled by default on Windows Vista and later.

**Your verdict**: supported

## C22

**Question**: Detection for T1050

**Claim**: Detection correlates parent-child lineage, startup behavior, and rare service names.

**[T1543.003:detection]**

T1543.003 Windows Service (sub-technique of T1543 Create or Modify System Process) — Detection
- Detection of Windows Service Creation or Modification
  - [Windows] Detects creation or modification of Windows Services through command-line tools (e.g., `sc.exe`, `powershell.exe`), Registry key changes under `HKLM\System\CurrentControlSet\Services`, and service execution under SYSTEM with unsigned or anomalous binary paths. Detects privilege escalation via driver installation or `CreateServiceW` usage. Correlates parent-child lineage, startup behavior, and rare service names.

**Your verdict**: supported

## C23

**Question**: How can I tell if someone is dumping credentials from the Windows process that keeps login secrets in memory?

**Claim**: You can identify credential dumping from the Windows process that keeps login secrets in memory by detecting when a non-privileged or abnormal process attempts to open a handle with full access (0x1F0FFF) to lsass.exe.

**[T1003.001:detection]**

T1003.001 LSASS Memory (sub-technique of T1003 OS Credential Dumping) — Detection
- Detection of Credential Dumping from LSASS Memory via Access and Dump Sequence
  - [Windows] A non-privileged or abnormal process attempts to open a handle with full access (0x1F0FFF) to lsass.exe and subsequently invokes memory dump, file creation, or registry modification indicative of credential scraping. This behavior chain reflects staged credential theft activity.

**Your verdict**: partial

## C24

**Question**: T1077 要怎麼防？

**Claim**: 建議使用主機防火牆來限制如 SMB 等檔案共享通訊。

**[T1021.002:mitigation]**

T1021.002 SMB/Windows Admin Shares (sub-technique of T1021 Remote Services) — Mitigation
- Filter Network Traffic: Consider using the host firewall to restrict file sharing communications such as SMB.
- Limit Access to Resource Over Network: Consider disabling Windows administrative shares.
- Password Policies: Do not reuse local administrator account passwords across systems. Ensure password complexity and uniqueness such that the passwords cannot be cracked or guessed.
- Privileged Account Management: Deny remote use of local admin credentials to log into systems. Do not allow domain user accounts to be in the local Administrators group multiple systems.

**Your verdict**: supported

## C25

**Question**: 怎麼防止攻擊者用 DNS 或其他非常規的協定把資料偷傳出去？

**Claim**: 使用內部或代理伺服器解析 DNS 請求，可能中斷攻擊者嘗試將資料隱藏在 DNS 封包中的行為。

**[T1071.004:mitigation]**

T1071.004 DNS (sub-technique of T1071 Application Layer Protocol) — Mitigation
- Filter Network Traffic: Consider filtering DNS requests to unknown, untrusted, or known bad domains and resources. Resolving DNS requests with on-premise/proxy servers may also disrupt adversary attempts to conceal data within DNS packets.
- Network Intrusion Prevention: Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary malware can be used to mitigate activity at the network level.

**Your verdict**: supported

## C26

**Question**: How do I stop users from getting compromised by malicious documents attached to emails?

**Claim**: Users can be trained to identify social engineering techniques and spearphishing emails used to deliver malicious documents.

**[T1221:mitigation]**

T1221 Template Injection — Mitigation
- Antivirus/Antimalware: Network/Host intrusion prevention systems, antivirus, and detonation chambers can be employed to prevent documents from fetching and/or executing malicious payloads.
- Disable or Remove Feature or Program: Consider disabling Microsoft Office macros/active content to prevent the execution of malicious payloads in documents , though this setting may not mitigate the Forced Authentication (T1187) use for this technique.
- Network Intrusion Prevention: Network/Host intrusion prevention systems, antivirus, and detonation chambers can be employed to prevent documents from fetching and/or executing malicious payloads.
- User Training: Train users to identify social engineering techniques and spearphishing emails that could be used to deliver malicious documents.

**Your verdict**: supported

## C27

**Question**: What is T1574.002?

**Claim**: T1574.002 was revoked and replaced by T1574.001 in ATT&CK v19.2.

**[T1574.001:overview]**

T1574.001 DLL (sub-technique of T1574 Hijack Execution Flow) — Overview
Adversaries may abuse dynamic-link library files (DLLs) in order to achieve persistence, escalate privileges, and evade defenses. DLLs are libraries that contain code and data that can be simultaneously utilized by multiple programs. While DLLs are not malicious by nature, they can be abused through mechanisms such as side-loading, hijacking search order, and phantom DLL hijacking.

Specific ways DLLs are abused by adversaries include:

### DLL Sideloading
Adversaries may execute their own malicious payloads by side-loading DLLs. Side-loading involves hijacking which DLL a program loads by planting and then invoking a legitimate application that executes their payload(s).

Side-loading positions both the victim application and malicious payload(s) alongside each other. Adversaries likely use side-loading as a means of masking actions they perform under a legitimate, trusted, and potentially elevated system or software process. Benign executables used to side-load payloads may not be flagged during delivery and/or execution. Adversary payloads may also be encrypted/packed or otherwise obfuscated until loaded into the memory of the trusted process.

Adversaries may also side-load other packages, such as BPLs (Borland Package Library).

Adversaries may chain DLL sideloading multiple times to fragment functionality hindering analysis. Adversaries using multiple DLL files can split the loader functions across different DLLs, with a main DLL loading the separated export functions. Spreading loader functions across multiple DLLs makes analysis harder, since all files must be collected to fully understand the malware’s behavior. Another method implements a “loader-for-a-loader”, where a malicious DLL’s sole role is to load a second DLL (or a chain of DLLs) that contain the real payload. 

### DLL Search Order Hijacking
Adversaries may execute their own malicious payloads by hijacking the search order that Windows uses to load DLLs. This search order is a sequence of special and standard search locations that a program checks when loading a DLL. An adversary can plant a trojan DLL in a directory that will be prioritized by the DLL search order over the location of a legitimate library. This will cause Windows to load the malicious DLL when it is called for by the victim program.

### DLL Redirection
Adversaries may directly modify the search order via DLL redirection, which after being enabled (in the Registry or via the creation of a redirection file) may cause a program to load a DLL from a different location.

### Phantom DLL Hijacking
Adversaries may leverage phantom DLL hijacking by targeting references to non-existent DLL files. They may be able to load their own malicious DLL by planting it with the correct name in the location of the missing module.

### DLL Substitution
Adversaries may target existing, valid DLL files and substitute them with their own malicious DLLs, planting them with the same name and in the same location as the valid DLL file.

Programs that fall victim to DLL hijacking may appear to behave normally because malicious DLLs may be configured to also load the legitimate DLLs they were meant to replace, evading defenses.

Remote DLL hijacking can occur when a program sets its current directory to a remote location, such as a Web share, before loading a DLL.

If a valid DLL is configured to run at a higher privilege level, then the adversary-controlled DLL that is loaded will also be executed at the higher level. In this case, the technique could be used for privilege escalation.
Tactics: Stealth, Execution
Platforms: Windows

**Your verdict**: unsupported

## C28

**Question**: 什麼是 Kerberoasting？

**Claim**: 攻擊者持有有效的 TGT 時，可向網域控制器請求任何服務主體名稱（SPN）的 TGS 服務票證。

**[T1558.003:overview]**

T1558.003 Kerberoasting (sub-technique of T1558 Steal or Forge Kerberos Tickets) — Overview
Adversaries may abuse a valid Kerberos ticket-granting ticket (TGT) or sniff network traffic to obtain a ticket-granting service (TGS) ticket that may be vulnerable to Brute Force (T1110). 

Service principal names (SPNs) are used to uniquely identify each instance of a Windows service. To enable authentication, Kerberos requires that SPNs be associated with at least one service logon account (an account specifically tasked with running a service).

Adversaries possessing a valid Kerberos ticket-granting ticket (TGT) may request one or more Kerberos ticket-granting service (TGS) service tickets for any SPN from a domain controller (DC). Portions of these tickets may be encrypted with the RC4 algorithm, meaning the Kerberos 5 TGS-REP etype 23 hash of the service account associated with the SPN is used as the private key and is thus vulnerable to offline Brute Force (T1110) attacks that may expose plaintext credentials. 

This same behavior could be executed using service tickets captured from network traffic.

Cracked hashes may enable Persistence (TA0003), Privilege Escalation (TA0004), and Lateral Movement (TA0008) via access to Valid Accounts (T1078).
Tactics: Credential Access
Platforms: Windows

**Your verdict**: supported

## C29

**Question**: Detection for T1050

**Claim**: T1543.003 is the current sub-technique that replaced the revoked T1050 technique in ATT&CK v19.2.

**[T1543.003:overview]**

T1543.003 Windows Service (sub-technique of T1543 Create or Modify System Process) — Overview
Adversaries may create or modify Windows services to repeatedly execute malicious payloads as part of persistence. When Windows boots up, it starts programs or applications called services that perform background system functions. Windows service configuration information, including the file path to the service's executable or recovery programs/commands, is stored in the Windows Registry.

Adversaries may install a new service or modify an existing service to execute at startup in order to persist on a system. Service configurations can be set or modified using system utilities (such as sc.exe), by directly modifying the Registry, or by interacting directly with the Windows API. 

Adversaries may also use services to install and execute malicious drivers. For example, after dropping a driver file (ex: `.sys`) to disk, the payload can be loaded and registered via Native API (T1106) functions such as `CreateServiceW()` (or manually via functions such as `ZwLoadDriver()` and `ZwSetValueKey()`), by creating the required service Registry values (i.e. Modify Registry (T1112)), or by using command-line utilities such as `PnPUtil.exe`. Adversaries may leverage these drivers as Rootkit (T1014)s to hide the presence of malicious activity on a system. Adversaries may also load a signed yet vulnerable driver onto a compromised machine (known as "Bring Your Own Vulnerable Driver" (BYOVD)) as part of Exploitation for Privilege Escalation (T1068).

Services may be created with administrator privileges but are executed under SYSTEM privileges, so an adversary may also use a service to escalate privileges. Adversaries may also directly start services through Service Execution (T1569.002).

To make detection analysis more challenging, malicious services may also incorporate Masquerade Task or Service (T1036.004) (ex: using a service and/or payload name related to a legitimate OS or benign software component). Adversaries may also create ‘hidden’ services (i.e., Hide Artifacts (T1564)), for example by using the `sc sdset` command to set service permissions via the Service Descriptor Definition Language (SDDL). This may hide a Windows service from the view of standard service enumeration methods such as `Get-Service`, `sc query`, and `services.exe`.
Tactics: Persistence, Privilege Escalation
Platforms: Windows

**Your verdict**: unsupported

## C30

**Question**: 攻擊者竄改檔案的時間戳記來躲避調查，這是什麼手法？

**Claim**: 攻擊者修改檔案時間戳記的目的是使其在法證調查人員或檔案分析工具中不顯得突兀。

**[T1070.006:overview]**

T1070.006 Timestomp (sub-technique of T1070 Indicator Removal) — Overview
Adversaries may modify file time attributes to hide new files or changes to existing files. Timestomping is a technique that modifies the timestamps of a file (the modify, access, create, and change times), often to mimic files that are in the same folder and blend malicious files with legitimate files.

In Windows systems, both the `$STANDARD_INFORMATION` (`$SI`) and `$FILE_NAME` (`$FN`) attributes record times in a Master File Table (MFT) file. `$SI` (dates/time stamps) is displayed to the end user, including in the File System view, while `$FN` is dealt with by the kernel.

Modifying the `$SI` attribute is the most common method of timestomping because it can be modified at the user level using API calls. `$FN` timestomping, however, typically requires interacting with the system kernel or moving or renaming a file.

Adversaries modify timestamps on files so that they do not appear conspicuous to forensic investigators or file analysis tools. In order to evade detections that rely on identifying discrepancies between the `$SI` and `$FN` attributes, adversaries may also engage in “double timestomping” by modifying times on both attributes simultaneously.

In Linux systems and on ESXi servers, threat actors may attempt to perform timestomping using commands such as `touch -a -m -t <timestamp> <filename>` (which sets access and modification times to a specific value) or `touch -r <filename> <filename>` (which sets access and modification times to match those of another file).

Timestomping may be used along with file name Masquerading (T1036) to hide malware and tools.
Tactics: Stealth
Platforms: ESXi, Linux, macOS, Windows

**Your verdict**: supported

## C31

**Question**: 攻擊者用 PowerShell 下載並執行惡意腳本，該怎麼偵測？

**Claim**: 偵測直接透過 powershell.exe 或間接透過 .NET 自動化調用的 PowerShell 執行。

**[T1059.001:detection]**

T1059.001 PowerShell (sub-technique of T1059 Command and Scripting Interpreter) — Detection
- Abuse of PowerShell for Arbitrary Execution
  - [Windows] Detects behavioral chains where PowerShell is launched with encoded commands, unusual parent processes, or suspicious modules loaded, potentially followed by network connections or child process spawning. Supports detection of both direct (powershell.exe) and indirect (.NET automation) invocations.

**Your verdict**: supported

## C32

**Question**: How to mitigate T1070.004?

**Claim**: Security teams should rely on the Detection guidance for T1070.004 instead of preventive mitigations.

**[T1070.004:mitigation]**

T1070.004 File Deletion (sub-technique of T1070 Indicator Removal) — Mitigation
ATT&CK v19.2 lists no preventive mitigations for T1070.004 File Deletion. This technique cannot be easily prevented with preventive controls; rely on its Detection guidance instead.

**Your verdict**: supported

## C33

**Question**: Detection for T1050

**Claim**: Detection of T1543.003 Windows Service involves monitoring for the creation or modification of Windows Services through command-line tools such as sc.exe and powershell.exe.

**[T1543.003:detection]**

T1543.003 Windows Service (sub-technique of T1543 Create or Modify System Process) — Detection
- Detection of Windows Service Creation or Modification
  - [Windows] Detects creation or modification of Windows Services through command-line tools (e.g., `sc.exe`, `powershell.exe`), Registry key changes under `HKLM\System\CurrentControlSet\Services`, and service execution under SYSTEM with unsigned or anomalous binary paths. Detects privilege escalation via driver installation or `CreateServiceW` usage. Correlates parent-child lineage, startup behavior, and rare service names.

**Your verdict**: supported

## C34

**Question**: How do I spot attackers deleting backup snapshots so we can't restore our systems?

**Claim**: On Linux, monitor for shell utilities or scripts deleting /etc/systemd/system/rescue.target, /etc/fstab backups, or /boot/efi partitions, as well as chattr usage to block snapshot auto-recovery.

**[T1490:detection]**

T1490 Inhibit System Recovery — Detection
- Behavioral Detection for T1490 - Inhibit System Recovery
  - [Windows] Process chains that use native utilities (vssadmin, wbadmin, diskshadow, bcdedit, REAgentC, wmic) with arguments to delete shadow copies, disable recovery, or remove backup catalogs
  - [Linux] Shell utilities or scripts deleting `/etc/systemd/system/rescue.target`, `/etc/fstab` backups, or `/boot/efi` partitions; chattr used to block snapshot auto-recovery
  - [ESXi] ESXi shell or vim-cmd execution that deletes all VM snapshots using vmsvc/snapshot.removeall or rm on snapshot paths
  - [Network Devices] Execution of `erase`, `format`, and `reload` in immediate sequence from a privileged AAA session
  - [IaaS] Cloud API calls disabling snapshot scheduling, backup policies, versioning, followed by DeleteSnapshot/DeleteVolume operations

**Your verdict**: supported

## C35

**Question**: Mitigation for T1003.006

**Claim**: 除非受到嚴格控制，否則不要將使用者或管理員網域帳戶加入各系統的本機管理員群組，並遵循企業網路設計與管理最佳實務以限制特權帳戶在管理層級中的使用。

**[T1003.006:mitigation]**

T1003.006 DCSync (sub-technique of T1003 OS Credential Dumping) — Mitigation
- Active Directory Configuration: Manage the access control list for "Replicating Directory Changes" and other permissions associated with domain controller replication.
- Password Policies: Ensure that local administrator accounts have complex, unique passwords across all systems on the network.
- Privileged Account Management: Do not put user or admin domain accounts in the local administrator groups across systems unless they are tightly controlled, as this is often equivalent to having a local administrator account with the same password on all systems. Follow best practices for design and administration of an enterprise network to limit privileged account use across administrative tiers.

**Your verdict**: supported

## C36

**Question**: 勒索軟體把檔案加密了，要怎麼降低損害？

**Claim**: 在AWS環境中應建立IAM策略，以限制或阻擋在S3儲存桶上使用SSE-C。

**[T1486:mitigation]**

T1486 Data Encrypted for Impact — Mitigation
- Behavior Prevention on Endpoint: On Windows 10, enable cloud-delivered protection and Attack Surface Reduction (ASR) rules to block the execution of files that resemble ransomware. In AWS environments, create an IAM policy to restrict or block the use of SSE-C on S3 buckets.
- Data Backup: Consider implementing IT disaster recovery plans that contain procedures for regularly taking and testing data backups that can be used to restore organizational data. Ensure backups are stored off system and is protected from common methods adversaries may use to gain access and destroy the backups to prevent recovery. Consider enabling versioning in cloud environments to maintain backup copies of storage objects.

**Your verdict**: supported

## C37

**Question**: 攻擊者透過遠端桌面橫向移動，要怎麼防？

**Claim**: 應變更群組原則（GPO）以縮短會話逾時時間、限制單一會話的最大活躍時間，並指定已斷開連線的會話在 RD 會話主機伺服器上保持活躍的最大時間。

**[T1563.002:mitigation]**

T1563.002 RDP Hijacking (sub-technique of T1563 Remote Service Session Hijacking) — Mitigation
- Audit: Audit the Remote Desktop Users group membership regularly. Remove unnecessary accounts and groups from Remote Desktop Users groups.
- Disable or Remove Feature or Program: Disable the RDP service if it is unnecessary.
- Limit Access to Resource Over Network: Use remote desktop gateways.
- Network Segmentation: Enable firewall rules to block RDP traffic between network security zones within a network.
- Operating System Configuration: Change GPOs to define shorter timeouts sessions and maximum amount of time any single session can be active. Change GPOs to specify the maximum amount of time that a disconnected session stays active on the RD session host server.
- Privileged Account Management: Consider removing the local Administrators group from the list of groups allowed to log in through RDP.
- User Account Management: Limit remote user permissions if remote access is necessary.

**Your verdict**: supported

## C38

**Question**: What is T1574.002?

**Claim**: Adversaries abuse dynamic-link library (DLL) files to achieve persistence, escalate privileges, and evade defenses.

**[T1574.001:overview]**

T1574.001 DLL (sub-technique of T1574 Hijack Execution Flow) — Overview
Adversaries may abuse dynamic-link library files (DLLs) in order to achieve persistence, escalate privileges, and evade defenses. DLLs are libraries that contain code and data that can be simultaneously utilized by multiple programs. While DLLs are not malicious by nature, they can be abused through mechanisms such as side-loading, hijacking search order, and phantom DLL hijacking.

Specific ways DLLs are abused by adversaries include:

### DLL Sideloading
Adversaries may execute their own malicious payloads by side-loading DLLs. Side-loading involves hijacking which DLL a program loads by planting and then invoking a legitimate application that executes their payload(s).

Side-loading positions both the victim application and malicious payload(s) alongside each other. Adversaries likely use side-loading as a means of masking actions they perform under a legitimate, trusted, and potentially elevated system or software process. Benign executables used to side-load payloads may not be flagged during delivery and/or execution. Adversary payloads may also be encrypted/packed or otherwise obfuscated until loaded into the memory of the trusted process.

Adversaries may also side-load other packages, such as BPLs (Borland Package Library).

Adversaries may chain DLL sideloading multiple times to fragment functionality hindering analysis. Adversaries using multiple DLL files can split the loader functions across different DLLs, with a main DLL loading the separated export functions. Spreading loader functions across multiple DLLs makes analysis harder, since all files must be collected to fully understand the malware’s behavior. Another method implements a “loader-for-a-loader”, where a malicious DLL’s sole role is to load a second DLL (or a chain of DLLs) that contain the real payload. 

### DLL Search Order Hijacking
Adversaries may execute their own malicious payloads by hijacking the search order that Windows uses to load DLLs. This search order is a sequence of special and standard search locations that a program checks when loading a DLL. An adversary can plant a trojan DLL in a directory that will be prioritized by the DLL search order over the location of a legitimate library. This will cause Windows to load the malicious DLL when it is called for by the victim program.

### DLL Redirection
Adversaries may directly modify the search order via DLL redirection, which after being enabled (in the Registry or via the creation of a redirection file) may cause a program to load a DLL from a different location.

### Phantom DLL Hijacking
Adversaries may leverage phantom DLL hijacking by targeting references to non-existent DLL files. They may be able to load their own malicious DLL by planting it with the correct name in the location of the missing module.

### DLL Substitution
Adversaries may target existing, valid DLL files and substitute them with their own malicious DLLs, planting them with the same name and in the same location as the valid DLL file.

Programs that fall victim to DLL hijacking may appear to behave normally because malicious DLLs may be configured to also load the legitimate DLLs they were meant to replace, evading defenses.

Remote DLL hijacking can occur when a program sets its current directory to a remote location, such as a Web share, before loading a DLL.

If a valid DLL is configured to run at a higher privilege level, then the adversary-controlled DLL that is loaded will also be executed at the higher level. In this case, the technique could be used for privilege escalation.
Tactics: Stealth, Execution
Platforms: Windows

**Your verdict**: supported

## C39

**Question**: An attacker pretends to be a domain controller to pull password hashes — how do I detect that?

**Claim**: Monitor for unexpected usage of Directory Replication Service SPNs, specifically GC/ or E3514235-4B06-11D1-AB04-00C04FC2DCD2.

**[T1207:detection]**

T1207 Rogue Domain Controller — Detection
- Detection Strategy for Rogue Domain Controller (DCShadow) Registration and Replication Abuse
  - [Windows] Detection of rogue Domain Controller registration and Active Directory replication abuse by correlating: (1) creation/modification of nTDSDSA and server objects in the Configuration partition, (2) unexpected usage of Directory Replication Service SPNs (GC/ or E3514235-4B06-11D1-AB04-00C04FC2DCD2), (3) replication RPC calls (DrsAddEntry, DrsReplicaAdd, GetNCChanges) originating from non-DC hosts, and (4) Kerberos authentication by non-DC machines using DRS-related SPNs. These events in combination, especially from hosts outside the Domain Controllers OU, may indicate DCShadow or rogue DC activity.

**Your verdict**: supported

## C40

**Question**: What is T1093?

**Claim**: T1055.012 主要用於規避基於程序的防禦機制，並可能用於特權提升。

**[T1055.012:overview]**

T1055.012 Process Hollowing (sub-technique of T1055 Process Injection) — Overview
Adversaries may inject malicious code into suspended and hollowed processes in order to evade process-based defenses. Process hollowing is a method of executing arbitrary code in the address space of a separate live process. 

Process hollowing is commonly performed by creating a process in a suspended state then unmapping/hollowing its memory, which can then be replaced with malicious code. A victim process can be created with native Windows API calls such as CreateProcess, which includes a flag to suspend the processes primary thread. At this point the process can be unmapped using APIs calls such as ZwUnmapViewOfSection or NtUnmapViewOfSection before being written to, realigned to the injected code, and resumed via VirtualAllocEx, WriteProcessMemory, SetThreadContext, then ResumeThread respectively.

This is very similar to Thread Local Storage (T1055.005) but creates a new process rather than targeting an existing process. This behavior will likely not result in elevated privileges since the injected process was spawned from (and thus inherits the security context) of the injecting process. However, execution via process hollowing may also evade detection from security products since the execution is masked under a legitimate process.
Tactics: Stealth, Privilege Escalation
Platforms: Windows

**Your verdict**: partial
