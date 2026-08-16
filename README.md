# SOC Detection & Threat Hunting Lab — Wazuh + Sysmon

## Project Overview

This project is a hands-on SOC detection and threat hunting lab built to simulate security events, collect endpoint and network telemetry, create detection rules, and investigate alerts.

The lab uses Wazuh as the SIEM platform, Sysmon for detailed Windows endpoint telemetry, Windows 11 as the monitored endpoint, and Kali Linux to generate controlled security events.

The goal of this project is to practice the workflow of a SOC analyst:

**Generate Activity → Collect Logs → Detect → Correlate → Investigate → Determine Response**

---

## Lab Environment

| System | Purpose |
|---|---|
| Wazuh Server | SIEM, log analysis, alerting, and threat hunting |
| Windows 11 | Monitored endpoint |
| Wazuh Agent | Sends Windows security telemetry to the Wazuh server |
| Sysmon | Provides detailed process, file, network, and system telemetry |
| Windows Firewall | Generates network connection and DROP logs |
| Kali Linux | Generates controlled security activity for detection testing |
| VirtualBox | Hosts the virtual lab environment |

---

## Lab Architecture

Kali Linux  
↓  
Controlled security activity  
↓  
Windows 11 Endpoint  
↓  
Windows Firewall + Sysmon + Wazuh Agent  
↓  
Wazuh Server  
↓  
Detection Rules → Alerts → Threat Hunting → Investigation

---

## Detection Scenarios

### 1. Network Reconnaissance Detection

A controlled network scan was generated from the Kali Linux system against the Windows 11 endpoint.

Windows Firewall recorded blocked TCP connection attempts, which were collected by the Wazuh agent and analyzed by the Wazuh server.

A custom Wazuh correlation rule was created to identify multiple firewall drops occurring within a short period.

**Detection workflow:**

Kali Linux → Network Scan → Windows Firewall DROP → Wazuh → Correlation Rule → Alert

**MITRE ATT&CK:** T1046 — Network Service Discovery

---

## Sysmon Endpoint Monitoring

Sysmon was installed on the Windows 11 endpoint to provide additional endpoint telemetry.

Sysmon telemetry allows the lab to investigate information including:

- Process creation
- Parent and child process relationships
- Command-line activity
- File creation
- File hashes
- DNS activity
- Network activity

Sysmon events are forwarded through the Wazuh agent for analysis and threat hunting.

---

## Investigation Example

During testing, Wazuh generated a high-severity alert after PowerShell created a `.ps1` file within the user's temporary directory.

The alert was investigated using Sysmon telemetry rather than being classified based only on severity.

The investigation included reviewing:

- Process image
- Target file
- User
- Event ID
- Process ID
- Process GUID
- File hashes
- Surrounding events

The activity was determined to be consistent with expected PowerShell behavior in the lab environment.

This demonstrates the importance of validating alerts and considering context before classifying activity as malicious.

---

## Skills Demonstrated

- SIEM monitoring
- Wazuh administration
- Windows event analysis
- Sysmon configuration
- Custom detection rules
- Alert correlation
- Threat hunting
- Log analysis
- Network traffic analysis
- Process analysis
- File/hash analysis
- False-positive investigation
- MITRE ATT&CK mapping

---

## Project Status

🚧 **In Progress**

Additional detection scenarios and investigations will be added as the lab develops.
