# Incident 002: User account enabled or created + Administrators Group Changed

## Summary
- **Date/time:** 2026-09-13 14:47 (UTC+2)
- **Triggered rule(s):** User account enabled or created (60109)
- **MITRE ATT&CK technique:** T1098 - Account Manipulation, T1484 - Domain Policy Modification
- **Affected endpoint:** WIN10-LAB
- **Severity:** Critical
- **Verdict:** True positive

## 1. Attack execution
A user account was created and later escalated so that it became an administrator.
```powershell
net user hacker P@ssw0rd123! /add
net localgroup Administrators hacker /add 
```

## 2. Evidence collected
- Screenshot of the event in Wazuh
![Wazuh dashboard](../images/003-account-creation-wazuh.png)
- User creation log:
```
A user account was created.

Subject:
	Security ID:		S-1-5-21-4160399544-949776153-194562142-1000
	Account Name:		vboxuser
	Account Domain:		WIN10-LAB
	Logon ID:		0x37607

New Account:
	Security ID:		S-1-5-21-4160399544-949776153-194562142-1001
	Account Name:		hacker
	Account Domain:		WIN10-LAB

Attributes:
	SAM Account Name:	hacker
	Display Name:		<value not set>
	User Principal Name:	-
	Home Directory:		<value not set>
	Home Drive:		<value not set>
	Script Path:		<value not set>
	Profile Path:		<value not set>
	User Workstations:	<value not set>
	Password Last Set:	<never>
	Account Expires:		<never>
	Primary Group ID:	513
	Allowed To Delegate To:	-
	Old UAC Value:		0x0
	New UAC Value:		0x15
	User Account Control:	
		Account Disabled
		'Password Not Required' - Enabled
		'Normal Account' - Enabled
	User Parameters:	<value not set>
	SID History:		-
	Logon Hours:		All

Additional Information:
	Privileges		-

```
- Privilege escalation log:
```
"A member was added to a security-enabled local group.

Subject:
	Security ID:		S-1-5-21-4160399544-949776153-194562142-1000
	Account Name:		vboxuser
	Account Domain:		WIN10-LAB
	Logon ID:		0x37607

Member:
	Security ID:		S-1-5-21-4160399544-949776153-194562142-1001
	Account Name:		-

Group:
	Security ID:		S-1-5-32-544
	Group Name:		Administrators
	Group Domain:		Builtin

Additional Information:
	Privileges:		-"
```

- Correlated events: `data.win.system.eventID:4720`, `data.win.system.eventID:4732`, `rule.id:60109`, `rule.id:60154`

## 3. Investigation (step by step)
1. I observed that a new user called `hacker` was created and added to the users group.
2. After a few minutes, a new log appeared in which the user had escalated privileges and now had administrator permissions.
3. No other newly created users were observed.
4. No remote login is observed, possible malware?
5. It was observed that the privilege escalation occurred through PowerShell at 14:50 (UTC+2) (`data.win.system.eventID:1`):
```
Process Create:
RuleName: technique_id=T1018,technique_name=Remote System Discovery
UtcTime: 2026-09-13 13:25:00.902
ProcessGuid: {e65a69a6-a42c-6aa6-c301-000000000600}
ProcessId: 2492
Image: C:\Windows\System32\net.exe
FileVersion: 10.0.19041.1 (WinBuild.160101.0800)
Description: Net Command
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: net.exe
CommandLine: "C:\Windows\system32\net.exe" localgroup Administrators hacker /add
CurrentDirectory: C:\Windows\system32\
User: WIN10-LAB\vboxuser
LogonGuid: {e65a69a6-9a98-6aa6-0776-030000000000}
LogonId: 0x37607
TerminalSessionId: 1
IntegrityLevel: High
Hashes: SHA1=88B101598CC6726B7A57D02B1FA95BE1B272A821,MD5=0BD94A338EEA5A4E1F2830AE326E6D19,SHA256=9F376759BCBCD705F726460FC4A7E2B07F310F52BAA73CAAAAA124FDDBDF993E,IMPHASH=57F0C47AE2A1A2C06C8B987372AB0B07
ParentProcessGuid: {e65a69a6-a40b-6aa6-c101-000000000600}
ParentProcessId: 6208
ParentImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
ParentCommandLine: "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" 
ParentUser: WIN10-LAB\vboxuser"
```

5. No new services were created `data.win.system.eventID:7045`.
6. It is confirmed that this does not coincide with any maintenance window or any new software deployment.

## 4. Analysis
Due to the potential danger posed by these actions, since an attacker has been able to escalate privileges, I classify the situation as critical, escalate it and take action immediately.

## 5. Response actions
- Urgent escalation to L2.
- Created account disabled
- Host isolation
- Forensic investigation and a search for persistence are required

## 6. Improvement recommendations (detection engineering)
Since the escalation occurred through PowerShell because the vboxuser account has administrator permissions, I recommend that the account used on a daily basis does not have administrator permissions (_Principle of least privilege_)

## 7. Lessons learned
I learned about the risk posed by a privilege escalation, how important it is to act in time before the attacker performs lateral movement and thus be able to contain the threat. I have learned that it is important not to shut down the host when this happens since irrecoverable forensic information would be destroyed. It is also important to analyze how the attacker got in and how they performed the escalation in order to establish the appropriate security measures so that it does not happen again. And that it is important to apply the principle of least privilege in order to reduce the attack surfaces.
