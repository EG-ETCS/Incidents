# TP-Link Archer NX Firmware Takeover Vulnerabilities
![alt text](images/Tplink.png)

**TP-Link Archer NX**{.cve-chip} **Firmware Takeover**{.cve-chip} **Router Security**{.cve-chip}

## Overview

Multiple vulnerabilities in TP-Link Archer NX routers can allow attackers to bypass authentication and upload malicious firmware. Exploitation may result in persistent device compromise and full control over routed traffic and managed settings.

Because these flaws affect internet-connected edge infrastructure, successful compromise can expose downstream users and connected systems to interception, redirection, and botnet abuse.

## Technical Specifications

| Field | Details |
|-------|---------|
| **Primary CVE** | CVE-2025-15517 |
| **CVSS Score** | 8.6(High) |
| **Additional CVEs** | CVE-2025-15605, CVE-2025-15518, CVE-2025-15519 |
| **Primary Flaw Type** | Authentication bypass in web management interface |
| **Secondary Flaw Types** | Hardcoded crypto key; command injection |
| **Affected Models** | Archer NX200, NX210, NX500, NX600 |
| **Potential Outcome** | Unauthenticated firmware upload, command execution, persistent root control |

## Affected Products

- TP-Link Archer NX200
- TP-Link Archer NX210
- TP-Link Archer NX500
- TP-Link Archer NX600

## Technical Details

- CVE-2025-15517 enables authentication bypass through missing access controls in CGI management endpoints.
- The bypass can permit unauthenticated firmware upload in vulnerable configurations.
- CVE-2025-15605 involves a hardcoded cryptographic key that can enable config decryption and tampering.
- CVE-2025-15518 and CVE-2025-15519 are command-injection issues that may permit arbitrary OS-level command execution after access.
- Attackers can chain these weaknesses to gain persistent control of router firmware and settings.

## Attack Scenario

1. An attacker scans for exposed TP-Link Archer NX router management interfaces.
2. The attacker exploits authentication bypass to access firmware management paths without valid login.
3. A malicious firmware image is uploaded and applied.
4. The compromised router is controlled at root/firmware level for persistence.
5. Additional command injection and config tampering are used to deepen control and conceal activity.

## Impact Assessment

=== "Device and Network Control Impact"
    Full router takeover can provide persistent firmware-level control of edge network behavior and administrative functions.

=== "Traffic and Security Impact"
    Attackers can perform DNS hijacking, traffic redirection, MITM interception, and potentially inject malicious payloads into network flows.

=== "Enterprise and Ecosystem Impact"
    Compromised routers can be enrolled into botnets, support DDoS operations, and serve as pivot points for lateral movement to internal assets.

## Mitigation Strategies

- Apply the latest TP-Link firmware updates immediately for affected Archer NX models.
- Disable remote/WAN management unless strictly required.
- Restrict admin interface access to trusted internal networks only.
- Rotate default/admin credentials and enforce strong authentication hygiene.
- Monitor router configuration, DNS settings, and management logs for unauthorized changes.
- Segment IoT and less-trusted devices from critical enterprise systems.

## Resources

!!! info "Open-Source Reporting"
    - [Security Advisory on Multiple Vulnerabilities on TP-Link Archer NX200, NX210, NX500 and NX600 (CVE-2025-15517 to CVE-2025-15519 and CVE-2025-15605)](https://www.tp-link.com/us/support/faq/5027/)
    - [Patch now: TP-Link Archer NX routers vulnerable to firmware takeover](https://securityaffairs.com/189980/iot/patch-now-tp-link-archer-nx-routers-vulnerable-to-firmware-takeover.html)
    - [Patch now: TP-Link Archer NX routers vulnerable to firmware takeover | SOC Defenders](https://www.socdefenders.ai/item/edf42ba6-23ad-42e3-8726-bd84a4234f5e)
    - [TP-Link warns users to patch critical router auth bypass flaw](https://www.bleepingcomputer.com/news/security/tp-link-warns-users-to-patch-critical-router-auth-bypass-flaw/amp/)
    - [TP-Link Patches Multiple Flaws Including Authentication Bypass in Archer NX Routers](https://beyondmachines.net/event_details/tp-link-patches-multiple-flaws-including-authentication-bypass-in-archer-nx-routers-7-i-6-1-m)
    - [NVD - CVE-2025-15517](https://nvd.nist.gov/vuln/detail/CVE-2025-15517)

---
*Last Updated: March 26, 2026*