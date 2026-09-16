# Incident 006: Lsass process was accessed by powershell with read permissions, possible credential dump

## Summary
- **Date/time:** 2026-09-14 19:45 (UTC+2)
- **Triggered rule(s):** Lsass process was accessed by powershell with read permissions, possible credential dump (92900) and Powershell script may be executing suspicious code with CreateThread API (91810)
- **MITRE ATT&CK technique:** T1003.001 - LSASS Memory, T1106 - Native API
- **Affected endpoint:** WIN10-LAB
- **Severity:** Critical
- **Verdict:** True positive

## 1. Attack execution
A Mimikatz execution attack was performed to dump LSASS and obtain credentials.
```
Invoke-AtomicTest T1003.001 -TestNumber 10
```

## 2. Evidence collected
- Screenshot of the event in Wazuh
![Wazuh](../images/006-lsass-dump-mimikatz-wazuh.png)
- User/Process: vboxuser -> powershell.exe
- Full command line:
```
"Process accessed:
RuleName: technique_id=T1003,technique_name=Credential Dumping
UtcTime: 2026-09-14 17:45:32.096
SourceProcessGUID: {e65a69a6-32b6-6aa8-1103-000000000900}
SourceProcessId: 7140
SourceThreadId: 4532
SourceImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
TargetProcessGUID: {e65a69a6-2986-6aa8-0c00-000000000900}
TargetProcessId: 700
TargetImage: C:\Windows\system32\lsass.exe
GrantedAccess: 0x1010
CallTrace: C:\Windows\SYSTEM32\ntdll.dll+9d234|C:\Windows\System32\KERNELBASE.dll+2c0fe|UNKNOWN(0000010A737F4503)
SourceUser: WIN10-LAB\vboxuser
TargetUser: NT AUTHORITY\SYSTEM"
```
- Correlated events: a PowerShell script executing suspicious code with `data.win.system.eventID:4104` and `rule.id:91810`

## 3. Investigation (step by step)
1. I observed that a PowerShell script could be executing malicious code with `data.win.system.eventID:4104` and `rule.id:91810`
2. Afterwards, numerous script blocks with base64 code, for example: ScriptBlock ID: 607c9878-bf40-49dd-8c2d-0716d3b025cd
3. And finally an alert was triggered warning that a process, specifically PowerShell, had accessed LSASS `data.win.system.eventID:10`, indicating a credential dump with a very high probability.
4. There is no evidence of subsequent logins (which could indicate the use of the stolen credentials)
5. There were no network connections, Sysmon event 3 was absent `data.win.system.eventID:3`, with no persistence (no 4720/7045) and no 4624 indicating prior remote access, so this is an attack contained to a single host.

## 4. Analysis
The attacker very likely performed a credential dump by accessing the memory of the lsass.exe process, using scripts obfuscated in base64.

## 5. Response actions
- Escalation to L2
- Isolation of the host from the network
- Forensic analysis of the device
- vboxuser account disabled

## 6. Improvement recommendations (detection engineering)
- Enable LSA Protection to prevent processes from opening LSASS
- Enable Credential Guard to virtualize LSASS
- Implementation of _Least Privilege_

## 7. Lessons learned
I learned what LSA Protection and Credential Guard are, two essential features when it comes to preventing credential dumping through the LSASS process.
