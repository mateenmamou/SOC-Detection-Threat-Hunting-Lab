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
| Wazuh Dashboard | Interface used for threat hunting and investigation |
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
                       v           v
                Windows 11       Ubuntu Linux
               192.168.1.147    192.168.1.142
                     |                |
              Windows Firewall      SSH / PAM
                   Sysmon            Auditd
                     |                |
                Wazuh Agent      Wazuh Agent
                      \              /
                       \            /
                        v          v
                        Wazuh Server
                       192.168.1.146
                              |
                              v
                       Detection Rules
                              |
                              v
                            Alerts
                              |
                              v
                       Threat Hunting
                              |
                              v
                        Investigation
                              |
                              v
                      Analyst Response
```

---

# Detection Scenarios

## 1. Network Reconnaissance Detection

A controlled network scan was generated from the Kali Linux system against the Windows 11 endpoint.

Windows Firewall recorded blocked TCP connection attempts, which were collected by the Wazuh agent and analyzed by the Wazuh server.

A custom Wazuh correlation rule was created to identify multiple firewall drops occurring within a short period.

**Detection workflow:**

```text
Kali Linux → Network Scan → Windows Firewall DROP → Wazuh Agent → Wazuh → Correlation Rule → Alert
```

**MITRE ATT&CK:** T1046 — Network Service Discovery

This scenario demonstrates how multiple low-level network events can be correlated into a higher-confidence security alert.

---

## 2. SSH Authentication Detection

A controlled SSH authentication scenario was generated from Kali Linux against the Ubuntu endpoint.

Multiple incorrect passwords were intentionally submitted against the `labuser` account, followed by a successful authentication.

Wazuh collected the Ubuntu SSH and PAM authentication logs and generated related alerts for authentication failures, repeated password failures, successful authentication, and PAM session creation.

Repeated password failures triggered a **Wazuh Level 10 alert**, increasing the priority of the activity for investigation.

### Investigation Findings

- **Source:** `192.168.1.139`
- **Target:** `192.168.1.142`
- **Target account:** `labuser`
- **Service:** SSH / TCP 22

The observed pattern was:

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

Multiple failed authentication attempts alone do not prove malicious activity because legitimate users can mistype credentials. However, repeated failures followed by a successful login create a suspicious pattern that requires additional investigation.

See [SSH Authentication Analysis](docs/ssh-authentication-analysis.md) for the focused investigation write-up.

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
- Process IDs and GUIDs
- User context

Sysmon telemetry is forwarded through the Wazuh agent for analysis and threat hunting.

## Windows Process Investigation

Process creation telemetry was investigated using fields such as `Image`, `CommandLine`, `ParentImage`, `ParentCommandLine`, `ProcessId`, `ParentProcessId`, `ProcessGuid`, `User`, and `IntegrityLevel`.

Account discovery activity involving Windows utilities such as:

```text
net user
net localgroup administrators
```

was investigated by reviewing the executable, command line, parent process, user context, and surrounding events.

These commands can be used legitimately by administrators but can also be used by attackers to discover accounts and privileged users.

**MITRE ATT&CK:** T1087 — Account Discovery

See [Windows Sysmon Investigation](docs/windows-sysmon-investigation.md) for the focused investigation write-up.

---

# PowerShell / File Creation Investigation

During testing, Wazuh generated a high-severity alert after PowerShell created a `.ps1` file within a user's temporary directory.

Rather than classifying the activity as malicious based only on alert severity, the underlying Sysmon telemetry was investigated.

The investigation included reviewing the process image, parent process, target file, user, event ID, process ID, process GUID, file hashes, and surrounding events.

The observed activity was determined to be consistent with expected PowerShell behavior within the lab environment.

> **An alert indicates that detection logic matched an event. It does not automatically prove that a security incident occurred.**

---

# Linux Command Monitoring with Auditd

During post-authentication testing on Ubuntu, a visibility gap was identified. Wazuh successfully detected SSH authentication, PAM activity, and sudo activity, but detailed visibility into commands executed during the Linux session was initially limited.

Auditd was installed and configured to provide Linux process execution telemetry.

## Auditd Process Execution Rules

```text
-a always,exit -F arch=b64 -S execve -k command_exec
-a always,exit -F arch=b32 -S execve -k command_exec
```

These rules monitor both 64-bit and 32-bit `execve` program execution and tag matching events with the key `command_exec`.

The rules were verified using:

```bash
sudo auditctl -l
```

Auditd telemetry was validated locally with `ausearch` before confirming ingestion through Wazuh.

The exact rule file used for this documentation is available at [`configs/auditd-command-exec.rules`](configs/auditd-command-exec.rules).

## Wazuh Auditd Collection

The Auditd log was added to the Wazuh agent configuration:

```xml
<localfile>
  <log_format>audit</log_format>
  <location>/var/log/audit/audit.log</location>
</localfile>
```

The configuration snippet is also available at [`configs/ossec-auditd-localfile.xml`](configs/ossec-auditd-localfile.xml).

Telemetry pipeline:

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

Wazuh successfully exposed detailed Auditd fields including:

- `data.audit.command`
- `data.audit.exe`
- `data.audit.execve.a0`
- `data.audit.execve.a1`
- `data.audit.key`
- `data.audit.uid`
- `data.audit.auid`
- `data.audit.cwd`
- `data.audit.success`

See [Linux Auditd Command Monitoring](docs/linux-auditd-command-monitoring.md) for the focused investigation write-up.

---

# Detection Validation and False Positives

One of the major lessons from the lab was the importance of validating detection rules against raw telemetry.

During Auditd testing, Wazuh generated an alert associated with SSH/lateral-movement behavior after detecting execution of:

```text
lscpu -J
```

The underlying Auditd telemetry showed the command, executable, argument, `command_exec` audit key, and successful execution status. Because the underlying activity was consistent with system-information gathering in the lab, the detection required investigation rather than automatically being treated as confirmed lateral movement.

```text
Detection Rule Match ≠ Confirmed Security Incident
```

MITRE ATT&CK mappings and alert severity provide investigative context, but the underlying evidence still has to be validated.

---

# Troubleshooting and Lab Development

During deployment of the Ubuntu Wazuh agent, the endpoint could reach the Wazuh server but could not successfully enroll.

Reviewing `/var/ossec/logs/ossec.log` revealed:

```text
Agent version must be lower or equal to manager version
```

The Ubuntu agent was running a newer Wazuh version than the central manager. A VirtualBox snapshot was created before the Wazuh Manager, Indexer, and Dashboard were upgraded. After the upgrade, the Ubuntu endpoint successfully enrolled and appeared as an active Wazuh agent.

This demonstrated the difference between a service simply running and an application successfully communicating with the SIEM.

---

# SOC Investigation Methodology

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

# MITRE ATT&CK Techniques Observed / Investigated

| Technique | Description |
|---|---|
| T1046 | Network Service Discovery |
| T1087 | Account Discovery |
| T1021.004 | SSH |

MITRE ATT&CK mappings were used as investigative context rather than automatic proof that malicious activity occurred.

---

# Skills Demonstrated

- SIEM monitoring and Wazuh administration
- Multi-endpoint monitoring
- Windows event and Sysmon analysis
- Linux security monitoring and Auditd configuration
- SSH authentication and PAM log analysis
- Custom detection rules and alert correlation
- Threat hunting and log analysis
- Network traffic analysis
- Parent/child process analysis
- File/hash analysis
- Linux process execution monitoring
- False-positive investigation
- MITRE ATT&CK mapping
- Incident triage and SOC investigation methodology
- Security monitoring troubleshooting

---

# Key Lessons Learned

1. High-severity alerts are not automatically confirmed incidents.
2. Multiple related events provide more context than a single alert.
3. Failed authentication followed by successful authentication deserves additional investigation.
4. Parent/child process relationships can provide critical context during endpoint investigations.
5. Legitimate administrative tools can also be used for malicious purposes.
6. Additional telemetry may be required when existing logging does not provide enough visibility.
7. Detection rules and MITRE ATT&CK mappings must be validated against underlying telemetry.
8. A running security agent does not necessarily mean it is successfully communicating with the SIEM.
9. Troubleshooting the telemetry pipeline is an important part of detection engineering and SOC operations.
10. Analysts should distinguish between what the evidence proves and what it only suggests.

---

# Evidence Organization

The selected screenshot evidence is being organized into concise investigation folders rather than uploading every troubleshooting screenshot. The selection plan is documented in [`docs/screenshot-evidence-map.md`](docs/screenshot-evidence-map.md).

---

# Project Status

🚧 **In Progress**

Core Windows and Linux monitoring, network reconnaissance detection, SSH authentication analysis, Sysmon investigation, and Auditd command execution monitoring have been implemented.

Final screenshot organization and documentation polish are being completed before the project is marked finished.
