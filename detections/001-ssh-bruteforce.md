# Incident 001 sshd brute force

## Summary
- **Date/time:** 2026-09-13 08:54 (UTC+2)
- **Triggered rule(s):** sshd: brute force trying to get access to the system. Non existent user. (5712)
- **MITRE ATT&CK technique:** T1110 - Brute Force
- **Affected endpoint:** Wazuh Manager
- **Severity:** Low
- **Verdict:** Benign

## 1. Attack execution
This attack was carried out by a series of bots that perform brute-force attacks against open ports. Specifically against the SSH port of the Wazuh Manager (since it is connected to the internet)

## 2. Evidence collected
- Screenshot of the event in Wazuh ![Wazuh log](../images/001-ssh-bruteforce-wazuh.png)
- Source IP: 35.187.231.181
- User/Process: guest -> sshd
- Full command line: `Sep 13 06:54:52 wazuh sshd[75565]: Invalid user guest from 35.187.231.181 port 57492`
- Correlated events: rule.id:5710 and rule.id:5712 and data.srcip:35.187.231.181

## 3. Investigation (step by step)
1. While reviewing the logs I found that the Wazuh server had been the victim of an external brute-force attack, common in services with ports open to the internet.
2. Afterwards I started investigating what else the attacker had done with `data.srcip:35.187.231.181`
3. I verified that it had only performed brute-force attacks against the sshd service, and furthermore none of them targeted the main user `data.srcuser:ubuntu`. Therefore, no successful login occurred.
4. I also observed the use of high and random ports, so I deduced that it was probably an automated scanner.

![Port statistics](../images/001-ssh-bruteforce-port.png)

## 4. Analysis
Since this is noise caused by having a port exposed to the Internet, SSH access with the main user is only allowed through a public-private key pair and no attempt has been made to access the main user, I set the severity to low.

## 5. Response actions
I would recommend continuing to monitor and, if it happens again, I would block the IP or close port 22 to the Internet and allow access only through the internal VPN.

## 6. Improvement recommendations (detection engineering)
I would recommend creating an Active Response rule to automatically block IPs that carry out a brute-force attack at the firewall level.

## 7. Lessons learned
I have learned that nowadays having a port open to the Internet represents a large attack surface since there are automated bots that will try to perform brute-force attacks against you at all hours.
