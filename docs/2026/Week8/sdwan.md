# Cisco SD-WAN Zero-Day CVE-2026-20127 Exploited Since 2023 for Admin Access
![alt text](images/sdwan.png)

**CVE-2026-20127**{.cve-chip}  **Authentication Bypass**{.cve-chip}  **CVSS 10.0**{.cve-chip}  **Zero-Day**{.cve-chip}  **UAT-8616**{.cve-chip}

## Overview
Cisco disclosed a critical zero-day authentication bypass vulnerability in Cisco Catalyst SD-WAN Controller (vSmart) and Cisco Catalyst SD-WAN Manager (vManage), tracked as CVE-2026-20127 (CVSS 10.0). The flaw has reportedly been actively exploited since at least 2023 by a sophisticated threat actor tracked as UAT-8616 to gain high-privileged access and establish long-term persistence in SD-WAN infrastructures.

## Technical Specifications

| **Attribute** | **Details** |
|---------------|-------------|
| **CVE ID** | CVE-2026-20127 |
| **Vulnerability Type** | Improper authentication / authentication bypass (CWE-287) |
| **CVSS Score** | 10.0 (Critical) |
| **Affected Products** | Cisco Catalyst SD-WAN Controller (vSmart), Cisco Catalyst SD-WAN Manager (vManage) |
| **Root Cause** | Peering authentication mechanism does not function correctly, allowing crafted request bypass |
| **Access Requirements** | Remote unauthenticated network access to reachable controller/manager interfaces |
| **Initial Access Outcome** | Login as internal high-privileged non-root user with NETCONF/API access |
| **Threat Actor** | UAT-8616 (per Cisco Talos), active exploitation observed since at least 2023 |

## Affected Products
- Cisco Catalyst SD-WAN Controller (formerly vSmart)
- Cisco Catalyst SD-WAN Manager (formerly vManage)
- Certain vulnerable software versions listed in Cisco’s advisory
- Enterprise and government SD-WAN deployments where controller/manager interfaces are reachable
- Status: Actively exploited; patching required

## Technical Details

### Vulnerability Mechanics
- CVE-2026-20127 is an authentication bypass in the SD-WAN peering authentication mechanism.
- A remote unauthenticated attacker can send specially crafted requests to bypass normal authentication checks.
- Successful exploitation grants access as an internal high-privileged non-root account.

### Post-Authentication Abuse Path
- With high-privileged access, attackers can use NETCONF and management APIs.
- They can alter SD-WAN fabric configuration, modify peers, and change route/policy behavior.
- This enables potential interception, redirection, or disruption of branch-to-data-center traffic.

### Observed Escalation Chain (Cisco/ACSC Reporting)
- Actor adds rogue peers and manipulates control-plane state.
- Device/software is downgraded to a release vulnerable to CVE-2022-20775 (path traversal).
- CVE-2022-20775 is exploited to obtain root access.
- System is upgraded back while preserving persistence and privileged foothold.

## Attack Scenario
1. **Target Discovery**:
    - Attacker identifies internet-exposed or otherwise reachable Cisco SD-WAN Controllers/Managers.

2. **Zero-Day Exploitation**:
    - Crafted requests exploit CVE-2026-20127 to bypass authentication.
    - Attacker logs in as an internal high-privileged non-root user.

3. **Control-Plane Manipulation**:
    - Attacker accesses NETCONF and management APIs.
    - Rogue SD-WAN peers are added and configuration/policies are modified.

4. **Root Escalation & Persistence**:
    - Attacker downgrades software to a version vulnerable to CVE-2022-20775.
    - Path traversal exploit is used to gain root, followed by re-upgrade to conceal activity.

5. **Long-Term Operations**:
    - Persistent access supports traffic interception, policy tampering, stealth monitoring, and potential pivoting into connected branch/data-center networks.

## Impact Assessment

=== "Integrity"
    * Unauthorized changes to routing, VPN, and SD-WAN policy across the fabric
    * Injection of rogue peers and manipulation of control-plane relationships
    * Potential tampering with enterprise-wide traffic handling behavior

=== "Confidentiality"
    * Traffic interception and monitoring opportunities between sites
    * Exposure of sensitive operational and network management data
    * Elevated espionage risk in enterprise/government environments

=== "Availability"
    * Disruption of inter-site connectivity and branch operations
    * Potential outage conditions from malicious configuration changes
    * Increased recovery complexity when persistence/root access is established

## Mitigation Strategies

### Immediate Actions
- Patch immediately to fixed Cisco software versions listed in the official advisory
- Treat patching as mandatory; there are no configuration-only workarounds that remove the vulnerability
- Follow Cisco temporary hardening guidance only as interim risk reduction

### Network Hardening
- Restrict management and peering interface access to trusted management networks and approved peers only
- Avoid direct internet exposure of SD-WAN controllers/managers
- Enforce strict ACLs and segmentation around SD-WAN control-plane systems

### Threat Hunting & Detection
- Hunt for unexplained configuration changes (new peers, altered NETCONF settings)
- Investigate unusual downgrade/upgrade sequences around vulnerable releases
- Review for unauthorized root access indicators and suspicious local account activity
- Correlate alerts with national-agency and vendor IoCs related to UAT-8616 activity

## Resources and References

!!! info "Official & Security Reporting"
    - [Cisco Catalyst SD-WAN Controller Authentication Bypass Vulnerability](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-rpa-EHchtZk)
    - [Cisco SD-WAN Zero-Day CVE-2026-20127 Exploited Since 2023 for Admin Access](https://thehackernews.com/2026/02/cisco-sd-wan-zero-day-cve-2026-20127.html)
    - [Critical Cisco SD-WAN bug exploited in zero-day attacks since 2023](https://www.bleepingcomputer.com/news/security/critical-cisco-sd-wan-bug-exploited-in-zero-day-attacks-since-2023/)
    - [Governments issue warning over Cisco zero-day attacks dating back to 2023 | CyberScoop](https://cyberscoop.com/cisco-zero-days-cisa-emergency-directive-five-eyes/)
    - [Threat actor leveraged Cisco SD-WAN zero-day since 2023 (CVE-2026-20127) - Help Net Security](https://www.helpnetsecurity.com/2026/02/25/cisco-sd-wan-zero-day-cve-2026-20127/)
    - [CVE-2026-20127 Zero-Day Auth Bypass Exploited | Tenable®](https://es-la.tenable.com/blog/cve-2026-20127-cisco-catalyst-sd-wan-controllermanager-zero-day-authentication-bypass)
    - [CVE-2026-20127 - Cisco Catalyst Zero-Day Vulnerability | eSentire](https://www.esentire.com/security-advisories/cve-2026-20127-cisco-catalyst-zero-day-vulnerability)

---

*Last Updated: February 26, 2026* 
