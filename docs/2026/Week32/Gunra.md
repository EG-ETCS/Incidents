# Gunra Ransomware Exploits Fortinet to Breach Networks
![alt text](images/Gunra.png)

**Gunra RaaS**{.cve-chip} **Double Extortion**{.cve-chip} **CVE-2024-55591**{.cve-chip} **CVE-2025-24472**{.cve-chip} **Fortinet Edge Exploitation**{.cve-chip}

## Overview

Gunra is a Ransomware-as-a-Service (RaaS) operation that emerged in April 2025 and evolved from leaked Conti ransomware source code. By early 2026, it had established an affiliate program.

Gunra uses a double-extortion model: operators steal sensitive information before encrypting systems, then threaten to publish stolen data if ransom demands are not met.

## Technical Details

Initial access has included exploitation of vulnerabilities in internet-facing Fortinet FortiOS and FortiProxy devices, including CVE-2024-55591 and CVE-2025-24472. Attackers have also abused exposed remote-access infrastructure.

After foothold, operators have stolen credentials and session cookies, compromised VDI and authentication infrastructure, modified authentication-processing files to bypass MFA, moved laterally, exfiltrated data, compromised or deleted backups, and deployed ransomware across enterprise systems.

## Technical Specifications

| **Attribute** | **Details** |
|---|---|
| **Threat Type** | Ransomware-as-a-Service (RaaS) with affiliate operations |
| **Campaign Lineage** | Evolved from leaked Conti ransomware source code |
| **Primary Initial Access** | Exploitation of internet-facing Fortinet and remote-access infrastructure |
| **Referenced CVEs** | CVE-2024-55591, CVE-2025-24472 |
| **Credential Abuse** | Theft of credentials and session cookies |
| **Identity Evasion** | Authentication-file modification and MFA bypass techniques |
| **Post-Compromise Actions** | Lateral movement, data exfiltration, backup compromise, encryption |
| **Extortion Model** | Double extortion (encryption plus data-leak threat) |

## Affected Products

- Internet-facing Fortinet FortiOS and FortiProxy deployments with unpatched exposure
- Remote-access and VPN infrastructure with weak hardening or exposed management surfaces
- VDI and authentication systems handling privileged enterprise sessions
- Backup and recovery environments lacking immutability or network isolation

## Attack Scenario

1. Initial access is gained by exploiting vulnerable internet-facing VPN or firewall infrastructure.
2. Attackers steal credentials and session cookies from exposed or compromised systems.
3. Authentication mechanisms are bypassed by modifying auth-processing components or abusing active sessions.
4. Lateral movement occurs across internal systems and privileged accounts.
5. Sensitive data is identified, staged, and exfiltrated.
6. Backups and recovery infrastructure are compromised or deleted.
7. Gunra ransomware is deployed across critical systems for broad encryption impact.
8. Victims receive extortion demands with threats to publish stolen data.

## Impact Assessment

=== "Integrity"

    - Compromise of authentication systems and privileged accounts can allow widespread policy and configuration tampering
    - Ransomware deployment can alter or destroy enterprise data and system-state integrity
    - Backup manipulation undermines recovery trust and incident response confidence

=== "Confidentiality"

    - Sensitive government, customer, and internal enterprise data may be exfiltrated prior to encryption
    - Credential and session-theft activity can expose additional systems beyond initially compromised edge devices
    - Data-leak extortion materially increases confidentiality and legal risk even if restoration succeeds

=== "Availability"

    - Encryption and backup destruction can cause severe service outages and prolonged operational downtime
    - Critical business functions may be interrupted across endpoints, servers, and identity platforms
    - Recovery timelines can extend significantly when immutable or offline backup controls are absent

## Mitigation Strategies

### Immediate Containment and Patching

- Patch internet-facing Fortinet devices immediately, prioritizing exposures tied to CVE-2024-55591 and CVE-2025-24472.
- Remove unnecessary public exposure of management interfaces and remote-access services.
- Investigate compromised edge devices for persistence before restoring normal operations.

### Identity and Access Hardening

- Enforce strong authentication controls and monitor authentication infrastructure for unauthorized modification.
- Protect privileged credentials, rotate high-risk secrets, and invalidate suspicious sessions and tokens.
- Restrict lateral movement through segmentation and least-privilege administration controls.

### Detection and Monitoring

- Monitor VPN and VDI activity for anomalous access patterns and suspicious session behavior.
- Deploy EDR and SIEM detections for credential theft, privilege abuse, and lateral movement.
- Monitor for unusual outbound data transfers indicative of staged or active exfiltration.

### Resilience and Recovery

- Maintain offline and immutable backups for critical systems and data.
- Regularly test restoration procedures and business continuity runbooks.
- Validate backup-environment isolation to reduce ransomware blast radius.

## Resources and References

!!! info "Public Reporting"
    - [US and South Korea warn of Gunra ransomware targeting govt agencies](https://www.bleepingcomputer.com/news/security/us-warns-of-gunra-ransomware-attacks-against-government-critical-infrastructure/)
    - [Gunra Ransomware Exploits Fortinet and Schneider Electric Flaws to Breach Networks](https://thehackernews.com/2026/08/gunra-ransomware-exploits-fortinet-and.html)
    - [#StopRansomware: Gunra Ransomware | CISA](https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-222a)
    - [#StopRansomware: Gunra Ransomware](https://media.defense.gov/2026/Aug/10/2003976697/-1/-1/0/CSA_STOPRANSOMWARE_GUNRA_RANSOMWARE.PDF)

---

*Last Updated: August 12, 2026*
