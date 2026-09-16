# Incident 002: Multiple Windows Logon Failures

## Summary
- **Date/time:** 2026-09-13 12:40 (UTC+2)
- **Triggered rule(s):** Multiple Windows Logon Failures (60204)
- **MITRE ATT&CK technique:** T1110 - Brute Force
- **Affected endpoint:** WIN10-LAB
- **Severity:** Medium
- **Verdict:** True positive

## 1. Attack execution
The Windows 10 endpoint was attacked from the VM host (port forwarding was used, which is why it shows 127.0.0.1) through a dictionary-based brute-force attack:
```bash
hydra -l vboxuser -P rockyou.txt rdp://127.0.0.1 -s 13389 -t 4 -V
```


## 2. Evidence collected
- Screenshot of the event in Wazuh
![alt text](../images/002-rdp-bruteforce-wazuh.png)
- Source IP: [10.0.2.2]
- User/Process: vboxuser -> RDP
- Full command line:
```
An account failed to log on.

Subject:
	Security ID:		S-1-0-0
	Account Name:		-
	Account Domain:		-
	Logon ID:		0x0

Logon Type:			3

Account For Which Logon Failed:
	Security ID:		S-1-0-0
	Account Name:		vboxuser
	Account Domain:		

Failure Information:
	Failure Reason:		Unknown user name or bad password.
	Status:			0xC000006D
	Sub Status:		0xC000006A


Process Information:
	Caller Process ID:	0x0
	Caller Process Name:	-

Network Information:
	Workstation Name:	arch
	Source Network Address:	10.0.2.2
	Source Port:		0

Detailed Authentication Information:
	Logon Process:		NtLmSsp 
	Authentication Package:	NTLM
	Transited Services:	-
	Package Name (NTLM only):	-
	Key Length:		0
```
- Correlated events: `rule.id:60122` and `rule.id:60204`

## 3. Investigation (step by step)
1. A brute-force attack against the virtual machine's main user through the RDP service was detected.
2. I verified that the attacker had not tried to attack any other service by looking at `data.win.eventdata.ipAddress:10.0.2.2`
3. The value `data.win.eventdata.subStatus:0xc000006a` means that the username was correct but the password was not.
4. No successful access occurred `data.win.system.eventID:4624`

## 4. Analysis
Since this is a specific attack against our system using a valid username, I assign it a medium severity, making it necessary to respond in order to mitigate possible future access.

After applying the response actions, I would continue monitoring in case further attacks occurred.

## 5. Response actions
- Escalate to L2 since this is a targeted attack.
- Establish robust password policies.
- Remove RDP access through the Internet and require the use of a VPN.
- It is recommended to establish a _lockout_ policy after a series of failed attempts. However, the attacker could carry out a denial-of-service attack, preventing the legitimate user from accessing the system.
- Change the username.
- Require the use of MFA for RDP access.

## 6. Improvement recommendations (detection engineering)
I would create an Active Response to automatically block IPs that attempt brute-force attacks, despite removing RDP access through the Internet.

## 7. Lessons learned
I learned that it is important to establish Zero Trust policies where the user must authenticate beforehand using a secure connection such as a VPN in order to subsequently access a service such as RDP. The use of MFA also drastically reduces the probability of success of a brute-force attack.
