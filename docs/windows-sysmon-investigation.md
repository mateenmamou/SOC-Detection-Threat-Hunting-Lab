# Windows Sysmon Investigation

This investigation documents Windows endpoint activity collected from the Windows 11 Wazuh agent with Sysmon enabled.

## Telemetry reviewed

The investigation used Sysmon process and file telemetry to examine:

- Process image and command line
- Parent image and parent command line
- Process ID and parent process ID
- Process GUID
- User context and integrity level
- File creation activity
- File hashes
- Surrounding events in Wazuh Threat Hunting

## Account discovery

During testing, Windows utilities including `net.exe` and `net1.exe` were observed performing account and administrator-group discovery. Commands such as `net user` and `net localgroup administrators` are legitimate administration commands, but they also overlap with attacker discovery behavior.

The investigation therefore focused on context: who executed the command, which process launched it, when it ran, what happened before and after it, and whether other indicators supported malicious activity.

**MITRE ATT&CK:** T1087 — Account Discovery

## PowerShell and file creation

Wazuh also generated an alert when PowerShell created a `.ps1` file in a temporary directory. The alert was investigated with Sysmon fields rather than classified from severity alone. In the controlled lab context, the observed behavior was consistent with expected test activity.

This investigation reinforced the principle that a rule match is an investigative lead, not automatic proof of compromise.

Planned evidence images:

- `screenshots/03-windows-sysmon/sysmon-process-events.jpg`
- `screenshots/03-windows-sysmon/sysmon-event-details.jpg`
