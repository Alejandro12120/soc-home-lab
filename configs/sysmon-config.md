# Sysmon configuration notes

Sysmon provides detailed Windows telemetry that complements standard Windows Event Channels. `WIN10-LAB` uses a configuration based on [olafhartong/sysmon-modular](https://github.com/olafhartong/sysmon-modular).

## Why?

sysmon-modular is a modular, community-maintained Sysmon configuration project. It provides a maintainable starting point for selecting useful event coverage and filtering rules, while allowing the lab to tune visibility against noise.