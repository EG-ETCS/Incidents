# SonicWall SMA 1000 SSRF + Post-Auth Code-Injection Zero-Days
![alt text](images/SonicWall.png)

**CVE-2026-15409**{.cve-chip} **CVE-2026-15410**{.cve-chip} **SMA 1000**{.cve-chip} **Zero-Day Chain**{.cve-chip} **Root RCE**{.cve-chip}

## Overview

This incident covers two SonicWall SMA 1000 zero-day vulnerabilities disclosed and patched in mid-July 2026 that are being actively exploited in the wild.

The flaws, CVE-2026-15409 (SSRF, CVSS 10.0) and CVE-2026-15410 (post-authentication code injection, CVSS 7.2), can be chained to provide effective unauthenticated remote code execution with root privileges on affected SMA 1000 appliances.

## Technical Specifications

| **Attribute** | **Details** |
|---|---|
| **Affected Product Family** | SonicWall Secure Mobile Access (SMA) 1000 Series |
| **Impacted Components** | WorkPlace web interface and Appliance Management Console (AMC) |
| **CVE-2026-15409** | SSRF in WorkPlace (CVSS 10.0) |
| **CVE-2026-15410** | Post-auth code injection in AMC (CVSS 7.2) |
| **Combined Outcome** | Effective unauthenticated remote code execution as root via chaining |
| **Exploitation Status** | Confirmed active exploitation in the wild |
| **Advisory Timeline** | SonicWall PSIRT advisory released July 14, 2026 |
| **CISA KEV Status** | Both CVEs added to KEV same day as advisory |
| **Threat Context** | Public reporting links activity to actor associated with Inc RaaS ecosystem |

## Affected Products

- SonicWall SMA 1000 appliances used for enterprise remote access/VPN services
- Deployments exposing WorkPlace or AMC interfaces to untrusted networks
- Organizations relying on SMA 1000 as a central remote-access trust boundary

## Attack Scenario

1. Attacker targets exposed SMA 1000 WorkPlace interface and exploits SSRF (CVE-2026-15409).
2. SSRF access is leveraged to reach internal AMC functionality or privileged paths.
3. Attacker exploits post-auth code injection flaw (CVE-2026-15410) to execute arbitrary system commands.
4. Chained exploitation yields root-level control of the SMA appliance.
5. Adversary harvests credentials, modifies appliance behavior, establishes persistence, and pivots into internal enterprise networks.

## Impact Assessment

=== "Integrity"

    - Root compromise enables attacker control of gateway configuration and policy behavior
    - Persistent backdoors may be implanted on a high-trust remote-access appliance
    - Administrative controls and logs can be manipulated to hinder detection

=== "Confidentiality"

    - Exposure of credentials, session context, and internal access pathways
    - Potential theft of VPN and administrative secrets from compromised appliance state
    - Increased risk of enterprise data access through trusted remote-access channels

=== "Availability"

    - Gateway compromise can disrupt remote-access services for large user populations
    - Incident containment and emergency patching may require temporary service interruption
    - Follow-on ransomware staging and lateral movement can impact broader business operations

## Mitigation Strategies

### Immediate Actions

- Apply SonicWall-released hotfixes for CVE-2026-15409 and CVE-2026-15410 immediately
- Verify all SMA 1000 appliances run latest PSIRT-recommended builds
- Treat exposed SMA devices as potentially compromised until validated clean

### Short-term Measures

- Restrict or eliminate direct internet exposure of WorkPlace and AMC interfaces
- Allow management access only from trusted admin networks or tightly scoped VPN sources
- Segment SMA appliances as high-value assets with strict east-west controls

### Monitoring & Detection

- Monitor for unusual AMC/WorkPlace requests, suspicious admin actions, and configuration drift
- Hunt for indicators of credential theft, unauthorized account creation, and persistence artifacts
- Correlate appliance telemetry with SIEM detections for lateral movement and ransomware staging

### Incident Response and Recovery

- If exploitation is suspected: rotate all relevant credentials, invalidate sessions/tokens, and collect forensic artifacts
- Rebuild from trusted images where integrity cannot be assured
- Follow CISA KEV remediation timelines as mandatory high-priority actions

## Resources and References

!!! info "Public Reporting"
    - [SonicWall warns of active exploitation of two SMA 1000 zero-days](https://securityaffairs.com/195364/hacking/sonicwall-warns-of-active-exploitation-of-two-sma-1000-zero-days.html)
    - [Inc Ransomware Exploits SonicWall SMA Zero-Days](https://www.darkreading.com/vulnerabilities-threats/inc-ransomware-exploits-sonicwall-sma-zero-days)

---

*Last Updated: July 20, 2026*
