# Fortinet Vulnerability Exploitation and PeerStitch FortiGate Implant
![alt text](images/Fortinet.png)

**Fortinet**{.cve-chip} **FortiManager**{.cve-chip} **FortiGate**{.cve-chip} **PeerStitch**{.cve-chip} **UNC5820**{.cve-chip}

## Overview

A suspected state-sponsored threat actor tracked as UNC5820 compromised a telecommunications organization by exploiting vulnerabilities in Fortinet infrastructure.

The attackers reportedly compromised FortiManager, obtained configuration data associated with more than 500 managed FortiGate firewalls, and deployed a previously unknown implant called PeerStitch. The implant was designed to maintain covert access to FortiGate devices while evading conventional detection and forensic investigation.

## Technical Details

- CVE-2024-47575 (FortiJump): Critical remote code execution vulnerability in FortiManager used for initial access.
- CVE-2025-61624: Path traversal vulnerability used to write or delete arbitrary files and reportedly obtain root access on the firewall.
- CVE-2024-26008: Reportedly exploited to terminate legitimate management sessions and impersonate FortiManager.
- PeerStitch implant: ARM64 malware written in C that operates in memory and patches running FortiOS processes.
- Stealth techniques: Avoids listening ports, direct outbound connections, and persistent on-disk artifacts.
- Management abuse: Exploits FortiGate-to-FortiManager (FGFM) communications to issue commands from external infrastructure.

## Technical Specifications

| **Attribute** | **Details** |
|---|---|
| **Threat Actor** | UNC5820 (suspected state-sponsored) |
| **Primary Target Sector** | Telecommunications |
| **Initial Access** | CVE-2024-47575 (FortiManager RCE / FortiJump) |
| **Privilege/Control Expansion** | CVE-2025-61624 path traversal with reported root-level impact |
| **Session/Management Abuse** | CVE-2024-26008 reportedly used to disrupt legitimate sessions and impersonate FortiManager |
| **Implant** | PeerStitch (ARM64, in-memory FortiOS process patching) |
| **Operational Objective** | Stealthy, long-term access to FortiGate management plane |

## Affected Products

- Fortinet FortiManager systems exposed to relevant vulnerable conditions.
- Managed FortiGate firewall estate connected through FGFM relationships.
- Telecom network environments where management-plane trust and credentials are exposed.

## Attack Scenario

1. Exploit CVE-2024-47575 to compromise FortiManager.
2. Register a rogue Virtual FortiGate appliance and extract configuration data covering more than 500 managed firewalls.
3. Exploit CVE-2025-61624 to obtain root access on a FortiGate operating system.
4. Deploy PeerStitch to patch running processes and establish covert inter-process communication.
5. Impersonate FortiManager to issue commands and maintain long-term access.
6. Remove forensic artifacts to complicate detection and incident investigation.

## Impact Assessment

=== "Infrastructure and Access Impact"

    - Unauthorized access to critical telecommunications network infrastructure
    - Compromise of management-plane integrity across firewall environments

=== "Data and Operational Impact"

    - Exposure of firewall configurations and sensitive network topology information
    - Potential disruption of VPN-related and perimeter security services

=== "Defensive Impact"

    - Long-term stealth persistence on compromised FortiGate devices
    - Reduced effectiveness of conventional malware detection and forensic analysis

## Mitigation Strategies

1. Apply Fortinet security updates addressing all relevant vulnerabilities.
2. Review FortiManager for unauthorized devices, suspicious configuration exports, and unexpected management sessions.
3. Audit FortiGate-to-FortiManager trust relationships and administrative accounts.
4. Rotate potentially exposed credentials, secrets, and certificates.
5. Investigate suspicious process behavior and memory-resident modifications using appropriate forensic procedures.
6. Preserve logs and evidence before remediation when compromise is suspected.
7. Engage Fortinet or a qualified incident-response team, and consider rebuilding affected appliances from trusted firmware if an implant is confirmed.
8. Prioritize CVE-2025-61624 remediation in accordance with applicable CISA KEV requirements.

## Resources and References

!!! info "Public Reporting"
    1. [Exploited Fortinet Bug Linked to Stealthy FortiGate Implant in Telecom Hack - SecurityWeek](https://www.securityweek.com/exploited-fortinet-bug-linked-to-stealthy-fortigate-implant-in-telecom-hack/)

---

*Last Updated: October 20, 2026*
