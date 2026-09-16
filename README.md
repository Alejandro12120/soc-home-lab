# SOC Home Lab — Wazuh + Sysmon + Atomic Red Team

This repository documents a personal security operations center (SOC) lab for collecting, investigating, and tuning Windows telemetry. Wazuh 4.14 runs as an all-in-one deployment in Oracle Cloud Infrastructure (OCI); the monitored endpoint is a Windows 10 VirtualBox VM named `WIN10-LAB`.

```text
Arch Linux bare-metal host
  ├─ attacker in some scenarios by using hydra for rdp bruteforce 
  └─ VirtualBox host: Windows 10 (WIN10-LAB)                                       
  │                    ├─ Wazuh agent + Sysmon                                  
  │                    └─ Atomic Red Team (local tests)
Tailscale
  │
OCI Madrid: Wazuh 4.14
  manager + indexer + dashboard
```

## Stack

- OCI Madrid: Ampere A1 ARM instance (2 OCPU, 12 GB RAM) running Ubuntu.
- Wazuh 4.14 all-in-one: manager, indexer, and Wazuh Dashboard
- Tailscale for private administrative access
- `WIN10-LAB`: Windows 10, Wazuh agent, Sysmon configured from sysmon-modular, and Atomic Red Team
- Arch Linux bare-metal host for VirtualBox and authorized external network-attack simulations against WIN10-LAB.

## Skills demonstrated

- Alert triage and incident documentation
- Log correlation and MITRE ATT&CK mapping
- Detection engineering
- Sysmon and Windows Event ID analysis
- Wazuh and Wazuh Dashboard investigation
- PowerShell and Linux administration

## Documentation and sanitized configuration evidence

- [Architecture](docs/architecture.md) · [Deployment record](docs/setup.md) · [Tuning](docs/tuning.md) · [Lab security](docs/lab-security.md)
- [Server configuration evidence](configs/ossec-server.conf) · [Windows agent configuration evidence](configs/ossec-agent-windows.conf) · [Sysmon configuration notes](configs/sysmon-config.md) · [Custom rules evidence](configs/local_rules.xml)

All attack activity described here was performed only against owned, isolated, and authorized lab systems. No testing was directed at external systems.
