# Lab security and trust boundaries

## Controls and boundaries

- **VirtualBox NAT:** `WIN10-LAB` is behind VirtualBox NAT, which limits direct network reachability from external networks. NAT alone is not complete isolation: host access, port forwarding, guest configuration, and outbound connectivity remain relevant.
- **Tailscale administrative access:** Tailscale provides private access to the OCI server and Wazuh services. 
- **OCI Security Lists / NSGs:** Cloud-network rules are a separate boundary from the host firewall and must be reviewed in OCI Console → Networking → Virtual Cloud Networks → Security Lists / Network Security Groups.
- **UFW host firewall:** UFW should restrict the server to necessary traffic. The following configuration is being used:
```
To                         Action      From
--                         ------      ----
OpenSSH                    ALLOW       Anywhere                  
1514/tcp                   ALLOW       100.64.0.0/10             
1515/tcp                   ALLOW       100.64.0.0/10             
443/tcp                    ALLOW       100.64.0.0/10             
OpenSSH (v6)               ALLOW       Anywhere (v6) 
```
- **Wazuh agent to manager:** Agent communications are established through a Tailscale tunnel from the host of the VM to the Wazuh instance.
- **Authorized simulations:** Atomic Red Team and network-attack tools are used only against owned lab systems. External systems are out of scope.
- **SSH:** is exposed to the internet in order make some detections.

## Known limitations

- NAT does not remove risk from host-to-guest paths, configured port forwarding, or guest outbound access.
- This repository does not contain backup schedules, restore-test evidence, or a formal privilege model.
