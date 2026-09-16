# Deployment record

This is a concise record of the intended final lab, not an installation runbook. It distinguishes confirmed information from details that still require evidence.

## Confirmed completed baseline

- An OCI account was upgraded to PAYG; the instance remains within the applicable zero-cost resource limits.
- The OCI home region is Madrid.
- The Wazuh server is an all-in-one Wazuh 4.14 deployment: Wazuh manager, Wazuh indexer, and Wazuh Dashboard.
- The server runs Ubuntu on an Ampere A1 ARM shape with 2 OCPU and 12 GB RAM.
- Wazuh indexer heap is configured for 4 GB and a 4 GB swap file was configured.
- Tailscale is used for private access to the server and Wazuh services.
- `WIN10-LAB` is a Windows 10 VirtualBox VM using NAT. It has the Wazuh agent, Sysmon with sysmon-modular, and Atomic Red Team.
- The Arch Linux bare-metal host runs VirtualBox and is the source for applicable authorized network-attack simulations.

## Deployment sequence summary

1. OCI resources were provisioned in Madrid and an Ubuntu server was prepared.
2. Wazuh 4.14 was installed as an all-in-one deployment on that server.
3. Tailscale was installed to support private administrative access and allowing Wazuh agent communicating with the manager.
4. The `WIN10-LAB` Windows 10 guest was created in VirtualBox with NAT networking.
5. The Wazuh agent, Sysmon using a sysmon-modular-based configuration, and Atomic Red Team were deployed in the guest.
6. Telemetry and detection investigations were recorded under [detections/](../detections/).

## Intentionally outside the final architecture

Older planning notes that described an Ubuntu endpoint or a Kali VM do not represent the final lab. No Ubuntu endpoint was deployed. No Kali VM is part of the final architecture: the Arch Linux bare-metal VirtualBox host performs applicable network simulations, and Atomic Red Team runs locally in `WIN10-LAB`.

No credentials or routable addresses are stored in this repository.
