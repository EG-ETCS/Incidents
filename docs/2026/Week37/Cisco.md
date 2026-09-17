# Actively Exploited Cisco ISE / ISE-PIC Authentication Bypass Zero-Day
![alt text](images/Cisco.png)

**Cisco ISE**{.cve-chip} **ISE-PIC**{.cve-chip} **CVE-2026-76460**{.cve-chip} **Authentication Bypass**{.cve-chip} **Active Exploitation**{.cve-chip}

## Overview

Cisco released emergency updates for **CVE-2026-76460**, a maximum-severity vulnerability affecting Cisco Identity Services Engine (ISE) and Cisco ISE Passive Identity Connector (ISE-PIC). Cisco PSIRT confirmed active exploitation in the wild.

The flaw allows remote authentication bypass on a vulnerable API endpoint and can provide unauthorized access to affected systems regardless of configuration. Because ISE/ISE-PIC are central components for enterprise identity, NAC, and policy enforcement, compromise can create significant downstream risk across network access-control environments.

## Technical Details

### Vulnerability

- **CVE-2026-76460**
- Class: authentication bypass on affected API functionality.
- Reported severity: maximum/critical.

### Affected Products

- Cisco Identity Services Engine (ISE)
- Cisco ISE Passive Identity Connector (ISE-PIC)

### Exploitation Status

- Cisco PSIRT confirmed active exploitation in real-world attacks.
- No published workaround; patching is required.

### Attribution

- Public reporting does not provide definitive threat-group attribution for all observed exploitation.

### Cisco Guidance and Investigation Context

- Cisco advises immediate upgrade to fixed releases.
- Cisco compromise-assessment guidance includes IOC review on each node, access-log analysis, and checks for administrative/policy tampering.
- Cisco also warns attackers may achieve root-level command execution and remove traces in some cases; full attack-chain specifics are not publicly disclosed.

### Other Cisco ISE Fixes in Same Release Cycle

- Additional vulnerabilities were fixed in the same update cycle, including **CVE-2026-76423** and other critical issues.
- At publication, those additional issues were not publicly reported as actively exploited in the same manner as CVE-2026-76460.

## Technical Specifications

| **Attribute** | **Details** |
|---|---|
| **Primary CVE** | CVE-2026-76460 |
| **Affected Platforms** | Cisco ISE and Cisco ISE-PIC |
| **Core Impact** | Remote authentication bypass on vulnerable API endpoint |
| **Exploitation Status** | Confirmed active exploitation by Cisco PSIRT |
| **Workaround Availability** | No workaround reported; update required |
| **Control-Plane Risk** | Centralized identity/NAC/policy infrastructure exposure |
| **Related Fixed Issue** | CVE-2026-76423 (same release cycle) |

## Affected Products

- Cisco ISE and ISE-PIC deployments running vulnerable software.
- Organizations relying on centralized NAC and identity-based policy enforcement.
- Environments where management/API interfaces are reachable from untrusted networks.

## Attack Scenario

1. Attacker identifies exposed or reachable Cisco ISE/ISE-PIC management/API surface.
2. Crafted request targets an affected API endpoint with insufficient authentication checks.
3. Authentication bypass grants unauthorized access to the platform.
4. Attacker may attempt administrative manipulation of policies, identities, endpoint posture, or integration settings.
5. In some cases, escalation to deeper command execution and log/trace removal may occur.
6. Compromised ISE control plane can be leveraged for follow-on network access abuse and lateral movement.

## Impact Assessment

=== "Confirmed Impact"

    - Active exploitation of CVE-2026-76460 is confirmed by Cisco PSIRT
    - Successful exploitation allows unauthorized access to vulnerable ISE/ISE-PIC devices

=== "Potential Impact"

    - Unauthorized policy manipulation and weakened Zero Trust/NAC posture
    - Identity-store and integration tampering
    - Exposure of enterprise access-control metadata and trust relationships
    - Follow-on access into connected enterprise systems

=== "Criticality"

    - **Critical** due to active exploitation, centralized identity-control role of ISE, and lack of workaround

## Mitigation Strategies

### Patch Immediately

- Upgrade all affected ISE/ISE-PIC nodes to the first fixed release or later for your deployment track.
- Prioritize internet-reachable and high-trust control-plane nodes.

### Perform Compromise Assessment

- Review `access.log` and node telemetry for suspicious access patterns and Cisco-provided IOCs.
- Investigate unexpected admin accounts, policy changes, configuration drift, and anomalous API activity.
- Compare current policy/integration/certificate/posture settings against known-good baselines.

### Review Network and Security Telemetry

- Hunt firewall, DNS, proxy, and network logs for suspicious outbound data movement and unrecognized external connections.
- Assume local evidence may be incomplete if attacker trace-removal behavior occurred.

### Re-image if Compromise Is Found

- If IOCs or malicious actions are confirmed, re-image/redeploy affected nodes from trusted sources.
- Do not rely on patch-only remediation for confirmed compromise.

### Rotate Secrets and Revalidate Trust

- Rotate ISE admin credentials, API credentials, SSH keys, certificates, RADIUS/TACACS+ secrets, and AD/service-account passwords where compromise is suspected.
- Revalidate trust relationships and identity-system integrations after recovery.

### Reduce Exposure and Improve Resilience

- Restrict management/API interfaces to trusted networks, VPNs, or hardened jump hosts.
- Enforce MFA and least privilege for administrative access.
- Segment ISE administration traffic and continuously monitor policy/configuration changes.
- Patch all additional ISE/ISE-PIC vulnerabilities fixed in the same cycle, including CVE-2026-76423.

## Resources and References

!!! info "Public Reporting"
    - [Cisco warns of Identity Services Engine zero-day exploited in attacks](https://www.bleepingcomputer.com/news/security/cisco-warns-of-identity-service-engine-zero-day-exploited-in-attacks/)

---

*Last Updated: September 17, 2026*