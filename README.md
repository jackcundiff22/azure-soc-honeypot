# Azure SOC Honeypot Project

##  Overview

This project demonstrates the creation of a cloud-based Windows honeypot using Microsoft Azure to detect and analyze real-world brute-force login attempts.

A virtual machine was intentionally exposed to the internet, allowing attackers to attempt unauthorized access. Windows Security logs were collected and analyzed using Azure Monitor and Log Analytics.

---

##  Technologies Used

* Microsoft Azure
* Windows Server Virtual Machine
* Azure Monitor Agent (AMA)
* Log Analytics Workspace
* Kusto Query Language (KQL)

---

##  Project Architecture

1. Created a Windows Server VM in Azure
2. Opened RDP (port 3389) to the internet
3. Installed Azure Monitor Agent
4. Configured Data Collection Rules (DCR)
5. Sent logs to Log Analytics Workspace
6. Queried and analyzed logs using KQL

---

##  Key Findings

###  Failed vs Successful Logins

* Over **68,000 failed login attempts (Event ID 4625)**
* Minimal successful logins (Event ID 4624)

This indicates continuous brute-force attack attempts on the exposed system.

---

###  Attack Patterns Over Time

Identified spikes in login attempts using time-based queries, showing automated attack behavior.

---

###  Attacker IP Identification

Extracted attacker IP addresses from raw log data using regex:

```kql
Event
| where EventLog == "Security"
| where EventID == 4625
| extend SourceIP = extract(@"Source Network Address:\s+([0-9\.]+)", 1, RenderedDescription)
| where isnotempty(SourceIP)
| summarize Attempts = count() by SourceIP
| sort by Attempts desc
```

---

###  Brute Force Detection Logic

```kql
Event
| where EventLog == "Security"
| where EventID == 4625
| summarize Attempts = count() by bin(TimeGenerated, 5m)
| where Attempts > 50
```

This query can be used to detect abnormal login activity and trigger alerts.

---

##  Screenshots

Screenshots of the following are included in the repository:

* Azure VM setup
* Data Collection Rule configuration
* Log ingestion verification
* Failed vs successful login comparison
* Attack timeline analysis
* Attacker IP extraction

---

##  Skills Demonstrated

* Cloud security fundamentals
* Log ingestion and monitoring
* Security event analysis
* KQL querying and data parsing
* Basic threat detection (brute force attacks)

---

##  Conclusion

This project simulates a real-world SOC scenario where a system is exposed to the internet and monitored for malicious activity. It demonstrates the ability to collect, analyze, and interpret security logs to identify potential threats.

---

##  Author

Jack Cundiff
Computer Science Student | Aspiring SOC Analyst | IT Support/Help Desk
