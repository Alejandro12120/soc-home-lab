# Architecture

## Final lab topology

```text
                         OCI — Madrid region
┌───────────────────────────────────┐
│ Ubuntu server 24.04                                                  │
│ Wazuh 4.14 all-in-one                                                │
│   ┌─────────────────────────┐             │
│   │Wazuh manager & Wazuh indexer & Wazuh Dashboard   │             │
│   └─────────────────────────┘             │
└───────────────────────────────────┘
                                │ Tailscale overlay
                                │ 
                                │ 
┌───────────────┴────────────────────┐
│ Arch Linux bare-metal host                                             │
│   ├─ VirtualBox host                                                 │
│   │   └─ NAT network ──> WIN10-LAB (Windows 10)                   │
│   │                      ├─ Wazuh agent                             │
│   │                      ├─ Sysmon                                  │
│   │                      └─ Atomic Red Team (local execution)       │
│   └─ authorized network-attack simulations ──────────> VM  │
└────────────────────────────────────┘
```

`WIN10-LAB` uses VirtualBox NAT. Therefore it is able to access the Wazuh instance by using the arch linux's tailscale instance. In order to make attacks to the VM from the host I've used port forwarding in VirtualBox settings.

## Telemetry and alert flow

1. Events originate on `WIN10-LAB`. Sysmon adds detailed telemetry, such as process creation and process access, to its Operational event channel. Windows Security and other enabled Windows Event Channels provide operating-system telemetry.
2. The Wazuh agent reads only the event channels configured in its local `ossec.conf`. The current channel list must be verified from the endpoint configuration; it is not inferred from the lab design.
3. The agent sends collected events to the Wazuh manager over the verified agent-to-manager path. Tailscale provides the private-access overlay for the server, but the guest's exact path to the manager remains unverified.
4. The manager decodes events and evaluates them against Wazuh rules, including any deployed local rules.
5. Generated alerts are indexed by the Wazuh indexer and investigated in Wazuh Dashboard.

## Simulation boundaries

Atomic Red Team tests execute locally inside `WIN10-LAB`; their process activity and resulting Windows/Sysmon events originate in the guest. By contrast, external network-attack simulations originate from the Arch Linux bare-metal host and target owned lab services exposed to that host. They are separate sources of activity and must not be conflated.
