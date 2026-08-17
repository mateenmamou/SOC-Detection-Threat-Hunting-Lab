# Screenshot Evidence Map

This file tracks the selected screenshots from the lab evidence set and the final repository location for each image.

| Original screenshot | Repository filename | Purpose |
|---|---|---|
| Screenshot (2386).png | `screenshots/01-lab-environment/agents-active.jpg` | Shows the Windows and Ubuntu Wazuh agents active in the same environment |
| Screenshot 2026-08-16 205415.png | `screenshots/02-network-recon/network-recon-correlation.jpg` | Shows Windows Firewall telemetry and the correlated possible TCP port-scan detection |
| Screenshot (2236).png | `screenshots/03-windows-sysmon/sysmon-process-events.jpg` | Shows Windows/Sysmon process-oriented events in Wazuh Threat Hunting |
| Screenshot (2279).png | `screenshots/03-windows-sysmon/sysmon-event-details.jpg` | Shows detailed Windows process/event fields used during investigation |
| Screenshot (2395).png | `screenshots/04-ssh-authentication/ssh-authentication-timeline.jpg` | Shows failed and successful SSH/PAM events in sequence |
| Screenshot (2391).png | `screenshots/04-ssh-authentication/ssh-authentication-details.jpg` | Shows the Level 10 repeated-password-failure alert and MITRE brute-force mapping |
| Screenshot (2403).png | `screenshots/05-linux-auditd/auditd-events.jpg` | Shows Auditd-related events arriving in Wazuh |
| Screenshot (2407).png | `screenshots/05-linux-auditd/auditd-command-details.jpg` | Shows decoded `lscpu`, executable, argument, cwd, user IDs, and `command_exec` key |
| Screenshot (2408).png | `screenshots/05-linux-auditd/auditd-lscpu-detection.jpg` | Shows Auditd syscall/raw event details used to validate the Wazuh detection |

## Selection approach

The final evidence set intentionally excludes duplicate screenshots, intermediate troubleshooting screenshots, and unrelated images. The goal is to make the repository easy to review while preserving enough evidence to support the written findings.

## Evidence quality notes

Each image supports a different part of the investigation rather than repeating the same dashboard view. The intended review sequence is: environment → network detection → Windows endpoint analysis → SSH authentication → Linux Auditd command visibility.
