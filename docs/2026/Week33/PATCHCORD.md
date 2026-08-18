# New PATCHCORD Backdoor Targets Afghan Telecom and Indian Critical Infrastructure
![alt text](images/PATCHCORD.png)

**PATCHCORD Backdoor**{.cve-chip} **SHEETCORD Implant**{.cve-chip} **APT36 / Transparent Tribe**{.cve-chip} **Telecom Targeting**{.cve-chip} **Google Sheets C2**{.cve-chip}

## Overview

Acronis identified an ongoing cyber-espionage campaign targeting Afghan telecom providers and South Asian critical infrastructure.

Attackers distribute PATCHCORD, a C/C++ Windows backdoor, through highly targeted fake VPN installers and telecom management tools impersonating legitimate organizations such as Afghan Telecom. Researchers also uncovered SHEETCORD, a Go-based implant that uses Google Sheets as command-and-control (C2), allowing malicious communications to blend with legitimate cloud traffic.

The activity was assessed with moderate confidence as being associated with APT36 (Transparent Tribe).

## Technical Details

PATCHCORD is a compiled C/C++ backdoor capable of host fingerprinting, process enumeration, remote shell execution, C2 communication, and in-memory shellcode execution.

It establishes persistence by modifying browser shortcuts and Registry startup mechanisms. SHEETCORD is written in Go and abuses the Google Sheets API for two-way C2 communication.

The campaign also used malicious domains impersonating Afghan telecom providers and Indian government organizations.

## Technical Specifications

| **Attribute** | **Details** |
|---|---|
| **Campaign Type** | Targeted cyber-espionage against telecom and critical infrastructure |
| **Primary Malware** | PATCHCORD (compiled C/C++ Windows backdoor) |
| **Secondary Malware** | SHEETCORD (Go implant using Google Sheets as C2) |
| **Initial Delivery** | Fake VPN installers and fake telecom management tools |
| **Core Capabilities** | Host fingerprinting, process enumeration, remote shell, in-memory shellcode execution |
| **Persistence Mechanisms** | Browser shortcut modification and Registry startup entries |
| **C2 Evasion Theme** | Blending malicious traffic into legitimate cloud services (Google Sheets API) |
| **Attribution (Reported)** | Moderate-confidence association with APT36 / Transparent Tribe |

## Affected Products

- Windows endpoints where fake VPN or telecom tools are installed
- Telecom-sector operational and administrative workstations
- Government, defense, and energy organizations in the observed targeting scope
- Enterprise environments where Google Sheets API traffic is not tightly monitored

## Attack Scenario

1. Attackers create convincing telecom- and government-themed lures.
2. Victim downloads and executes a fake VPN or telecom-management installer.
3. Malicious installer deploys PATCHCORD on the Windows host.
4. Malware establishes persistence through browser shortcuts and Registry startup entries.
5. PATCHCORD fingerprints the host and initiates communication with attacker infrastructure.
6. Operators issue commands and execute additional shellcode in memory.
7. In related activity, SHEETCORD uses Google Sheets for C2, making traffic harder to distinguish from legitimate cloud activity.

## Impact Assessment

=== "Integrity"

    - Persistent remote access can enable attacker-driven system and configuration changes
    - In-memory shellcode execution supports follow-on payload deployment and stealthy tampering
    - Telecom and critical-infrastructure targeting increases potential for strategic manipulation of core systems

=== "Confidentiality"

    - Host reconnaissance and command execution can expose sensitive operational and administrative data
    - Credential theft and privileged access pathways may enable broader data collection and lateral movement
    - Target profile suggests elevated risk of strategic intelligence theft across government and infrastructure sectors

=== "Availability"

    - No confirmed destructive effects or operational disruption were reported in cited sources
    - Persistent footholds can still degrade operational resilience by increasing remediation complexity
    - Undetected cloud-like C2 traffic can extend attacker dwell time and incident containment windows

## Mitigation Strategies

### Preventive Controls

- Block and investigate unauthorized software installers, especially fake VPN and telecom tools.
- Implement application allowlisting to restrict unapproved executable deployment.
- Apply least privilege and restrict users from installing software without approval.

### Persistence and Endpoint Detection

- Monitor modifications to browser `.lnk` shortcuts.
- Monitor suspicious Registry Run keys and Startup-folder persistence activity.
- Enable EDR behavioral detection for memory-based shellcode execution and unusual child processes.
- Monitor PowerShell and `cmd.exe` activity spawned by newly installed applications.

### Network and C2 Monitoring

- Inspect unusual Google Sheets API activity from endpoints that do not normally use it.
- Block known malicious domains/IPs and continuously monitor DNS requests for look-alike telecom and government domains.
- Correlate endpoint and DNS telemetry for staged loader-to-backdoor execution patterns.

### Threat Hunting and Response

- Conduct threat hunting for PATCHCORD and SHEETCORD indicators across Windows endpoints.
- Prioritize triage for telecom and critical-infrastructure user groups and administrative hosts.
- Rapidly isolate suspected infected hosts and validate persistence eradication before rejoining production networks.

## Resources and References

!!! info "Public Reporting"
    - [New PATCHCORD Backdoor Targets Afghan Telecom and Indian Critical Infrastructure](https://thehackernews.com/2026/08/new-patchcord-backdoor-targets-afghan.html)

---

*Last Updated: August 18, 2026*
