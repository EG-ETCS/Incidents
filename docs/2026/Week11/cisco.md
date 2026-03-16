# Cisco Confirms Active Exploitation of Two Catalyst SD-WAN Manager Vulnerabilities
![alt text](images/cisco.png)

**Cisco SD-WAN**{.cve-chip} **Active Exploitation**{.cve-chip} **Critical Infrastructure**{.cve-chip}

## Overview

Cisco confirmed active exploitation of two recently patched Catalyst SD-WAN Manager vulnerabilities, CVE-2026-20122 and CVE-2026-20128, following earlier exploitation of the critical CVE-2026-20127 authentication-bypass flaw.

Public reporting indicates attackers are leveraging these weaknesses to gain high-privileged access to SD-WAN management planes, deploy implants, and maintain long-term persistence in enterprise and critical-infrastructure environments.

## Technical Specifications

| Field | Details |
|-------|---------|
| **Affected Products** | Cisco Catalyst SD-WAN Manager (vManage), Catalyst SD-WAN Controller environments |
| **Primary CVEs** | CVE-2026-20122, CVE-2026-20128 |
| **CVSS Score** | 5.4 (Medium), 7.5 (High) |
| **Related Critical CVE** | CVE-2026-20127 (pre-auth auth bypass, CVSS 10.0) |
| **Exploitation Type** | API/web-interface abuse, file overwrite, privilege escalation, potential code execution |
| **Attacker Objective** | Control-plane compromise, implant deployment, persistent access |
| **Exposure Condition** | Reachable SD-WAN management interface |

## Affected Products

- Cisco Catalyst SD-WAN Manager (vManage) instances.
- Catalyst SD-WAN Controller deployments with exposed or reachable management interfaces.
- Distributed enterprise and critical-infrastructure networks operating affected versions.

## Technical Details

- CVE-2026-20122 is associated with arbitrary file overwrite behavior through SD-WAN Manager API abuse, enabling dropped files or implant placement.
- CVE-2026-20128 is reported as a complementary SD-WAN Manager flaw that may support privilege escalation or command execution in exploit chains.
- CVE-2026-20127 (critical pre-auth bypass) has prior real-world exploitation history and can be chained with newer flaws for deeper compromise.
- Attack paths target server-side logic in vManage APIs/web components and can result in high-privilege appliance access.
- Cisco PSIRT and external reporting indicate active exploitation and broad internet-scale scanning activity.

## Attack Scenario

1. **Discovery and Targeting**: Adversaries identify internet-exposed or reachable Catalyst SD-WAN management nodes.
2. **Initial Access**: Attackers leverage CVE-2026-20127 (or weak credentials/other access) to enter the SD-WAN management plane.
3. **Exploit Chaining**: Crafted API/HTTP requests exploit CVE-2026-20122 and CVE-2026-20128 to overwrite files, escalate privileges, or execute commands.
4. **Post-Exploitation Control**: Attackers modify policies/routes, add rogue peers, and install implants for persistence.
5. **Long-Term Operations**: Compromised SD-WAN control infrastructure is used for monitoring, lateral movement, and sustained access.

## Impact Assessment

=== "Control-Plane and Network Impact"
    Full SD-WAN management compromise can allow hijacking of routing/VPN policies, traffic rerouting or mirroring, and disruption of branch, data-center, and cloud connectivity.

=== "Enterprise and Critical-Infrastructure Impact"
    Affected organizations may include critical-infrastructure operators, and compromise can degrade confidentiality, integrity, and availability across distributed IT and OT-connected environments.

=== "Threat Persistence Impact"
    Combined exploitation paths enable stealthy, long-term presence through implant deployment and trusted-network pivoting from core WAN management assets.

## Mitigation Strategies

- Patch immediately to Cisco-recommended fixed releases for CVE-2026-20122, CVE-2026-20128, and CVE-2026-20127.
- Use Cisco Software Checker to validate version exposure and remediation status.
- Remove direct internet exposure of SD-WAN management/web interfaces; restrict access to hardened admin networks or VPN-only paths.
- Enforce strong authentication controls (unique credentials, MFA where available) and least-privilege admin role assignments.
- Segment SD-WAN control infrastructure from general IT and OT networks and restrict east-west access.
- Maintain tested backups of SD-WAN configurations and prepare rebuild/re-trust procedures for compromised controllers.

## Resources

!!! info "Open-Source Reporting"
    - [Cisco Event Response: March 2026 Cisco Secure Firewall ASA, Secure FMC, and Secure FTD Software Security Advisory Bundled Publication](https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-75736)
    - [Cisco Confirms Active Exploitation of Two Catalyst SD-WAN Manager Vulnerabilities](https://thehackernews.com/2026/03/cisco-confirms-active-exploitation-of.html)
    - [Cisco flags ongoing exploitation of two recently patched Catalyst SD-WAN flaws](https://securityaffairs.com/189056/security/cisco-flags-ongoing-exploitation-of-two-recently-patched-catalyst-sd-wan-flaws.html)

---
*Last Updated: March 16, 2026*