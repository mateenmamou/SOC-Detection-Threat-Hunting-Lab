# SOC Detection & Threat Hunting Lab — Wazuh + Sysmon + Auditd

## Project Overview

This project is a hands-on SOC detection and threat hunting lab built to simulate security events, collect endpoint and network telemetry, create detection rules, and investigate alerts.

The lab uses Wazuh as the SIEM platform, Sysmon for detailed Windows endpoint telemetry, Auditd for Linux process execution monitoring, Windows 11 and Ubuntu as monitored endpoints, and Kali Linux to generate controlled security activity.

The goal of this project is to practice the workflow of a SOC analyst:

**Generate Activity → Collect Logs → Detect → Correlate → Investigate → Determine Response**

The project focuses not only on generating alerts, but also on examining the underlying telemetry to determine whether activity is legitimate, suspicious, or potentially malicious.

---

## Lab Environment

| System / Tool | Purpose |
|---|---|
| Wazuh Server | SIEM, log analysis, alerting, correlation, and threat hunting |
| Wazuh Indexer | Stores and indexes security alerts and events |
| Wazuh Dashboard | Provides the interface used for threat hunting and investigation |
| Windows 11 | Monitored Windows endpoint |
| Ubuntu Linux | Monitored Linux endpoint used for SSH and authentication analysis |
| Wazuh Agent | Sends endpoint security telemetry to the Wazuh server |
| Sysmon | Provides detailed Windows process, file, network, and system telemetry |
| Auditd | Provides Linux system call and process execution telemetry |
| Windows Firewall | Generates network connection and DROP logs |
| Kali Linux | Generates controlled security activity for detection testing |
| VirtualBox | Hosts the virtual lab environment |

---

## Lab Architecture

```text
                         Kali Linux
                       192.168.1.139
                         /       \
                        /         \
                       ↓           ↓
                Windows 11       Ubuntu Linux
               192.168.1.147    192.168.1.142
                     │                │
              Windows Firewall      SSH / PAM
                   Sysmon            Auditd
                     │                │
                Wazuh Agent      Wazuh Agent
                      \              /
                       \            /
                        ↓          ↓
                        Wazuh Server
                       192.168.1.146
                              │
                              ↓
                       Detection Rules
                              │
                              ↓
                            Alerts
                              │
                              ↓
                       Threat Hunting
                              │
                              ↓
                        Investigation
                              │
                              ↓
                      Analyst Response
```

---

# Detection Scenarios

## 1. Network Reconnaissance Detection

A controlled network scan was generated from the Kali Linux system against the Windows 11 endpoint.

Windows Firewall recorded blocked TCP connection attempts, which were collected by the Wazuh agent and analyzed by the Wazuh server.

A custom Wazuh correlation rule was created to identify multiple firewall drops occurring within a short period.

### Detection Workflow

```text
Kali Linux
    ↓
Network Scan
    ↓
Windows Firewall DROP
    ↓
Wazuh Agent
    ↓
Wazuh
    ↓
Correlation Rule
    ↓
Alert
```

**MITRE ATT&CK:** T1046 — Network Service Discovery

This scenario demonstrates how multiple low-level network events can be correlated into a higher-confidence security alert.

---

## 2. SSH Authentication Detection

A controlled SSH authentication scenario was generated from Kali Linux against the Ubuntu endpoint.

Multiple incorrect passwords were intentionally submitted against the `labuser` account, followed by a successful authentication.

Wazuh collected the Ubuntu SSH and PAM authentication logs and generated several related alerts, including:

- SSH authentication failures
- PAM login failures
- Multiple failed password attempts
- Successful SSH authentication
- PAM session creation

Repeated password failures triggered a **Wazuh Level 10 alert**, increasing the priority of the activity for investigation.

### Detection Workflow

```text
Kali Linux
    ↓
SSH Authentication Attempts
    ↓
Ubuntu Linux
    ↓
SSH / PAM Logs
    ↓
Wazuh Agent
    ↓
Wazuh
    ↓
Authentication Alerts
    ↓
SOC Investigation
```

### Investigation Findings

The authentication events were correlated to reconstruct the sequence of activity.

**Source:** `192.168.1.139`

**Target:** `192.168.1.142`

**Target Account:** `labuser`

**Service:** SSH / TCP 22

The observed sequence was:

```text
Failed Authentication
        ↓
Failed Authentication
        ↓
Failed Authentication
        ↓
Successful Authentication
        ↓
PAM Session Opened
```

Multiple failed authentication attempts alone do not prove malicious activity because legitimate users can mistype credentials.

However, repeated authentication failures followed by a successful login create a suspicious pattern that requires additional investigation.

If the source system were determined to be unauthorized, the successful authentication could indicate account compromise.

Possible response actions would include:

- Identifying the device associated with the source IP
- Determining whether the source was authorized to access the server
- Reviewing activity performed after authentication
- Resetting or disabling the affected account if compromise is confirmed
- Terminating unauthorized sessions
- Isolating or blocking the source system when appropriate

---

# Windows Endpoint Monitoring with Sysmon

Sysmon was installed on the Windows 11 endpoint to provide additional endpoint telemetry.

Sysmon provides visibility into activity including:

- Process creation
- Parent and child process relationships
- Command-line activity
- File creation
- File hashes
- DNS activity
- Network activity
- Process IDs
- Process GUIDs
- User context

Sysmon telemetry is forwarded through the Wazuh agent for analysis and threat hunting.

---

## Windows Process Investigation

During testing, process creation telemetry was investigated using Sysmon.

Fields examined included:

- `Image`
- `CommandLine`
- `ParentImage`
- `ParentCommandLine`
- `ProcessId`
- `ParentProcessId`
- `ProcessGuid`
- `User`
- `IntegrityLevel`
- File hashes

This allowed process relationships to be reconstructed rather than evaluating individual processes in isolation.

For example, account discovery activity involving Windows utilities such as:

```text
net user
net localgroup administrators
```

was investigated by reviewing the executable, command line, parent process, user context, and surrounding events.

These commands can be used legitimately by administrators but can also be used by attackers to discover accounts and privileged users.

**MITRE ATT&CK:** T1087 — Account Discovery

This demonstrated the importance of distinguishing between a legitimate administrative tool and potentially suspicious use of that tool.

---

# PowerShell / File Creation Investigation

During testing, Wazuh generated a high-severity alert after PowerShell created a `.ps1` file within a user's temporary directory.

Rather than classifying the activity as malicious based only on the alert severity, the underlying Sysmon telemetry was investigated.

The investigation included reviewing:

- Process image
- Parent process
- Target file
- User
- Event ID
- Process ID
- Process GUID
- File hashes
- Surrounding events

The observed activity was determined to be consistent with expected PowerShell behavior within the lab environment.

This demonstrated an important SOC principle:

> **An alert indicates that detection logic matched an event. It does not automatically prove that a security incident occurred.**

Analysts must validate alerts using the underlying telemetry and surrounding context.

---

# Linux Command Monitoring with Auditd

During post-authentication testing on Ubuntu, a visibility gap was identified.

Wazuh successfully detected:

- SSH authentication failures
- Successful SSH authentication
- PAM activity
- Sudo activity

However, detailed visibility into commands executed during the Linux session was initially limited.

Auditd was installed and configured to provide additional Linux process execution telemetry.

---

## Auditd Process Execution Rules

Audit rules were created to monitor the Linux `execve` system call.

```text
-a always,exit -F arch=b64 -S execve -k command_exec
-a always,exit -F arch=b32 -S execve -k command_exec
```

These rules monitor both 64-bit and 32-bit program execution.

Matching events are tagged with:

```text
command_exec
```

The rules were verified using:

```bash
sudo auditctl -l
```

Auditd telemetry was then validated locally using `ausearch` before attempting to analyze it through Wazuh.

This helped verify each stage of the telemetry pipeline independently.

---

## Wazuh Auditd Collection

The Auditd log was added to the Wazuh agent configuration:

```xml
<localfile>
  <log_format>audit</log_format>
  <location>/var/log/audit/audit.log</location>
</localfile>
```

This created the following telemetry pipeline:

```text
Linux Command
      ↓
execve System Call
      ↓
Auditd
      ↓
/var/log/audit/audit.log
      ↓
Wazuh Agent
      ↓
Wazuh Manager
      ↓
Decoder / Detection Rules
      ↓
Wazuh Indexer
      ↓
Threat Hunting
      ↓
SOC Investigation
```

Auditd events were successfully received and decoded by Wazuh.

The resulting events provided fields including:

- `data.audit.command`
- `data.audit.exe`
- `data.audit.execve.a0`
- `data.audit.execve.a1`
- `data.audit.key`
- `data.audit.uid`
- `data.audit.auid`
- `data.audit.cwd`
- `data.audit.success`

This improved visibility into activity occurring after a successful Linux authentication.

---

# Detection Validation and False Positives

One of the major lessons from the lab was the importance of validating detection rules against raw telemetry.

During Auditd testing, Wazuh generated an alert associated with SSH/lateral-movement behavior after detecting execution of:

```text
lscpu -J
```

The underlying Auditd telemetry showed:

```text
Command: lscpu
Executable: /usr/bin/lscpu
Argument: -J
Audit Key: command_exec
Execution: Successful
```

Because the underlying command was consistent with system-information gathering, the alert required additional investigation rather than automatically being treated as confirmed lateral movement.

This reinforced the difference between:

```text
Detection Rule Match
        ≠
Confirmed Security Incident
```

Detection severity and MITRE ATT&CK mappings provide valuable context, but analysts must still examine the underlying evidence.

---

# Troubleshooting and Lab Development

Building the lab also required troubleshooting the monitoring infrastructure.

During deployment of the Ubuntu Wazuh agent, the endpoint could reach the Wazuh server but could not successfully enroll.

Reviewing:

```text
/var/ossec/logs/ossec.log
```

revealed:

```text
Agent version must be lower or equal to manager version
```

The Ubuntu agent was running a newer version of Wazuh than the central Wazuh manager.

A VirtualBox snapshot was created before upgrading the central Wazuh components.

The following components were upgraded to matching versions:

- Wazuh Manager
- Wazuh Indexer
- Wazuh Dashboard

After the upgrade, the Ubuntu endpoint successfully enrolled and appeared as an active Wazuh agent.

This troubleshooting demonstrated the importance of distinguishing between:

```text
Service Running
        ↓
and
        ↓
Application Successfully Connected
```

A running endpoint service does not necessarily mean that the endpoint is successfully communicating with the SIEM.

---

# SOC Investigation Methodology

Throughout the project, alerts were investigated using the following workflow:

```text
Alert Generated
      ↓
Identify Affected Host
      ↓
Identify User
      ↓
Review Source / Destination
      ↓
Examine Command or Process
      ↓
Examine Parent Process
      ↓
Review Authentication Activity
      ↓
Review Surrounding Events
      ↓
Correlate Related Telemetry
      ↓
Compare with Expected Behavior
      ↓
Determine Severity
      ↓
Determine Response
```

The project emphasizes separating what the evidence **proves** from what the evidence only **suggests**.

---

# Key SOC Concepts Practiced

### Event vs Alert vs Incident

**Event**

Something occurred on a system.

Example:

```text
SSH authentication failed.
```

**Alert**

A detection rule identified activity that requires attention.

Example:

```text
Multiple SSH password failures detected.
```

**Incident**

Investigation determines that unauthorized or malicious security activity occurred and requires response.

---

### IOC vs TTP

Indicators of Compromise can include:

- Malicious IP addresses
- Malicious domains
- Known malware hashes
- Suspicious files
- Known command-and-control infrastructure

Tactics, Techniques, and Procedures describe attacker behavior, such as:

- Account Discovery
- Network Service Discovery
- Credential attacks
- Privilege discovery
- Lateral movement

This lab focused heavily on behavioral analysis and event correlation rather than relying exclusively on known malicious indicators.

---

# MITRE ATT&CK Techniques Observed / Investigated

| Technique | Description |
|---|---|
| T1046 | Network Service Discovery |
| T1087 | Account Discovery |
| T1021.004 | SSH |

MITRE ATT&CK mappings were used as investigative context rather than automatic proof that malicious activity occurred.

---

# Skills Demonstrated

- SIEM monitoring
- Wazuh administration
- Multi-endpoint monitoring
- Windows event analysis
- Linux security monitoring
- Sysmon configuration and analysis
- Linux Auditd configuration
- SSH authentication analysis
- PAM log analysis
- Custom detection rules
- Alert correlation
- Threat hunting
- Log analysis
- Network traffic analysis
- Process analysis
- Parent/child process analysis
- File/hash analysis
- Linux process execution monitoring
- False-positive investigation
- MITRE ATT&CK mapping
- Incident triage
- SOC investigation methodology
- Security monitoring troubleshooting

---

# Key Lessons Learned

This project demonstrated that effective security monitoring requires more than generating alerts.

Important lessons included:

1. **High-severity alerts are not automatically confirmed incidents.**
2. **Multiple related events provide more context than a single alert.**
3. **Failed authentication followed by successful authentication deserves additional investigation.**
4. **Parent/child process relationships can provide critical context during endpoint investigations.**
5. **Legitimate administrative tools can also be used for malicious purposes.**
6. **Additional telemetry may be required when the existing logging does not provide enough visibility.**
7. **Detection rules and MITRE ATT&CK mappings must be validated against the underlying telemetry.**
8. **A running security agent does not necessarily mean that it is successfully communicating with the SIEM.**
9. **Troubleshooting the telemetry pipeline is an important part of detection engineering and SOC operations.**
10. **Analysts should distinguish between what the evidence proves and what it only suggests.**

---

# Project Status

🚧 **In Progress**

Core Windows and Linux monitoring, network reconnaissance detection, SSH authentication analysis, Sysmon investigation, and Auditd command execution monitoring have been implemented.

Additional documentation, screenshots, and final project organization will be completed before the project is marked finished.
