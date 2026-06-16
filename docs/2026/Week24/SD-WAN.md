# Cisco SD-WAN 'Make-Me-Root' Bug Under Attack in Catalyst SD-WAN Manager
![alt text](images/SD-WAN.png)

**CVE-2026-20127**{.cve-chip} **CVE-2026-20182**{.cve-chip} **CVE-2026-20245**{.cve-chip} **Authentication Bypass**{.cve-chip} **Active Exploitation**{.cve-chip} **CISA KEV**{.cve-chip}

## Overview

Cisco Catalyst SD-WAN Manager (formerly vManage) is affected by a chain of critical vulnerabilities allowing attackers to bypass authentication, obtain administrative access, and ultimately execute commands as root on the SD-WAN control plane. Several flaws have been actively exploited since at least 2023, with CISA issuing emergency directives for U.S. federal agencies. The most severe — CVE-2026-20127 — carries a CVSS score of 10.0. A command-injection "make-me-root" bug (CVE-2026-20245) was exploited as a zero-day until Cisco's June 2026 patch cycle.

## Technical Specifications

| Attribute | Details |
|---|---|
| **Primary CVEs** | CVE-2026-20127 (CVSS 10.0), CVE-2026-20182, CVE-2026-20245 |
| **Additional CVEs** | CVE-2026-20122, CVE-2026-20126, CVE-2026-20128, CVE-2026-20133 |
| **Affected Product** | Cisco Catalyst SD-WAN Manager (formerly vManage) and Controller |
| **Vulnerability Types** | Authentication bypass, command injection, privilege escalation, file overwrite, credential exposure |
| **Attack Vector** | Network (internet-facing management plane) |
| **Authentication Required** | None (for auth-bypass CVEs) |
| **Exploitation Status** | Actively exploited in the wild; multiple CVEs in CISA KEV catalog |
| **CISA Action** | Emergency directive issued for U.S. federal agencies |
| **Fixed Versions** | 20.9.8.2, 20.12.5.3, 20.18.2.1 and later; versions 20.18+ immune to key auth-bypass and DCA flaws |

## Affected Products

- Cisco Catalyst SD-WAN Manager (all versions prior to fixed releases)
- Cisco Catalyst SD-WAN Controller
- On-premises and Cisco-hosted deployments
- FedRAMP and enterprise/government environments using Catalyst SD-WAN

## Attack Scenario

1. Attacker scans for internet-exposed Cisco Catalyst SD-WAN Manager or Controller instances.
2. Using CVE-2026-20127 or CVE-2026-20182, crafted requests exploit broken peering/API authentication to gain administrative access without credentials.
3. With admin or low-privileged access, attacker exploits CVE-2026-20122 (file overwrite) to escalate to full vmanage rights.
4. CVE-2026-20128 is abused to dump plaintext passwords from the Data Collection Agent (DCA), enabling lateral movement to other systems.
5. CVE-2026-20126 or CVE-2026-20245 command injection is triggered to execute arbitrary commands as root on the SD-WAN Manager OS.
6. As root/admin on SD-WAN Manager, attacker adds rogue peers, pushes malicious configurations to branch routers, and hijacks or disrupts WAN traffic across the fabric.
7. Attacker may downgrade software, alter logging, or schedule unexpected reboots to persist and erase traces.

## Impact

=== "Integrity"

    - Full control of the SD-WAN management plane with root access on the controller host
    - Ability to push malicious or destructive configurations to all branch routers and gateways
    - Addition of rogue peers and manipulation of WAN topology

=== "Confidentiality"

    - Plaintext credential exposure via CVE-2026-20128 DCA flaw enabling lateral movement
    - Interception and rerouting of traffic across the corporate WAN
    - Exfiltration of sensitive data in transit across all connected sites

=== "Availability"

    - Mass WAN outages possible across corporate infrastructure, branches, and data centers
    - Reconfiguration or disabling of branch routers, firewalls, and service-edge nodes
    - Critical services disruption across FedRAMP, enterprise, and government SD-WAN environments

## Mitigations

### Immediate Actions

- Upgrade Cisco Catalyst SD-WAN Manager to fixed versions: **20.9.8.2**, **20.12.5.3**, **20.18.2.1** or later
- Follow Cisco PSIRT advisories for all listed CVEs: 20127, 20122, 20126, 20128, 20133, 20182, 20245
- Place SD-WAN Controller/Manager behind firewalls — do not expose management interfaces directly to the internet
- Disable unused services (HTTP/FTP) and require VPN or dedicated management networks for access

### Short-term Measures

- Isolate the SD-WAN management plane from general IT networks
- Enforce least-privileged accounts and review all admin-level users in SD-WAN Manager
- Engage Cisco TAC if compromise is suspected and collect admin-tech output (`request admin-tech`) for analysis
- Treat any suspected compromise as both a patching and IR event — assume possibility of malicious configuration changes and credential theft

### Monitoring & Detection

- Review `/var/log/auth.log` for suspicious `Accepted publickey for vmanage-admin` entries from unknown IPs
- Check `/var/log/tmplog/vdebug` and `/var/volatile/log/sw_script_synccdb.log` for unexpected downgrades, reboots, or unusual script activity
- Monitor SD-WAN Manager UI for unknown peers, unexpected configuration changes, and new admin accounts
- Forward SD-WAN logs to a separate SIEM to prevent local evidence erasure by attackers

### Long-term Solutions

- Continuously track Cisco advisories and CISA KEV additions related to SD-WAN Manager
- Implement network segmentation ensuring SD-WAN management compromise cannot cascade to broader IT/OT environments
- Enforce zero-trust access for all SD-WAN management plane interactions

## Resources

!!! info "Open-Source Reporting"
    - [Cisco SD-WAN 'make-me-root' bug under attack | The Register](https://forums.theregister.com/forum/all/2026/06/15/202625/)
    - [Cisco Security Advisory – CVE-2026-20127 (cisco-sa-sdwan-rpa-EHchtZk)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-rpa-EHchtZk)
    - [CISA flags another Cisco Catalyst SD-WAN Manager bug as exploited – CVE-2026-20133 | HelpNet Security](https://www.helpnetsecurity.com/2026/04/21/cisa-flags-another-cisco-catalyst-sd-wan-manager-bug-as-exploited-cve-2026-20133/)
    - [SD-WAN Ongoing Exploitation | Cisco Talos](https://blog.talosintelligence.com/sd-wan-ongoing-exploitation/)

---

*Last Updated: June 16, 2026*
