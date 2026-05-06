# Azure SOC Honeypot Detection Lab

## Project Goal

The goal of this project is to build a cloud-based cybersecurity lab using Microsoft Azure and Microsoft Sentinel. I will deploy a Windows virtual machine, collect security logs, detect failed login attempts, and create SOC-style alerts and dashboards.

## Tools Used

- Microsoft Azure
- Windows Server VM
- Microsoft Sentinel
- Log Analytics Workspace
- KQL
- Windows Security Event Logs

## Main Detection Goal

Detect repeated failed login attempts against a Windows server.

Important Windows Event ID:

- 4625 = Failed login attempt

## Skills Demonstrated

- Cloud security basics
- SIEM log collection
- Windows event log analysis
- KQL querying
- Brute-force detection
- Alert creation
- Incident investigation
- Cybersecurity documentation