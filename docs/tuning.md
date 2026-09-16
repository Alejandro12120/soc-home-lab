# Tuning and operational trade-offs

## Wazuh indexer memory

The Wazuh indexer JVM heap is configured as:

```text
-Xms4g
-Xmx4g
```

Keeping the initial heap (`-Xms`) and maximum heap (`-Xmx`) equal avoids heap-resizing work and gives the indexer a predictable memory reservation. On a 12 GB server, this leaves memory for the operating system and the Wazuh manager, dashboard, and supporting processes. The 2 OCPU ARM instance has limited CPU headroom, so indexing, dashboard queries, and rule evaluation can contend during bursts of telemetry.

## Swap

A 4 GB swap file was configured. Swap is a safety mechanism for transient memory pressure; it is not a substitute for RAM. Sustained swapping can increase latency and degrade indexing responsiveness, so memory and swap usage should be monitored before raising telemetry volume or retention.

## Network-access strategy

Tailscale is the private-access mechanism for the Wazuh server and services. This reduces reliance on a public management path, but it does not by itself prove that public listeners or cloud firewall rules are absent.

The desired UFW strategy is to permit only necessary administrative and Wazuh service traffic from approved private paths, this is the current configuration:
```
To                         Action      From
--                         ------      ----
OpenSSH                    ALLOW       Anywhere                  
1514/tcp                   ALLOW       100.64.0.0/10             
1515/tcp                   ALLOW       100.64.0.0/10             
443/tcp                    ALLOW       100.64.0.0/10             
OpenSSH (v6)               ALLOW       Anywhere (v6) 
```

## Operating within the instance limits

The 2 OCPU and 12 GB RAM allocation is suitable for a small lab but requires deliberate limits on retention, concurrent dashboard use, and ingestion volume. Practical trade-offs include:

- Higher telemetry detail improves investigations but increases indexer CPU, memory, and storage pressure.
- Longer retention improves historical analysis but consumes disk capacity and can affect query performance.
- Aggressive rules and correlation improve visibility but can increase alert volume and triage effort.
- Tuning should be based on observed telemetry and alerts; no false-positive reduction or performance metric is claimed here without measured evidence.
