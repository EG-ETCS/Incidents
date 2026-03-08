# Hikvision & Rockwell Automation Critical Vulnerabilities Added to KEV Catalog
![alt text](images/hikvision.png)

**CVE-2017-7921**{.cve-chip}  **CVE-2021-22681**{.cve-chip}  **CISA KEV**{.cve-chip}  **Critical Infrastructure Risk**{.cve-chip}

## Overview
CISA added two high-severity vulnerabilities affecting Hikvision surveillance systems and Rockwell Automation industrial software to the Known Exploited Vulnerabilities (KEV) Catalog. KEV inclusion indicates credible exploitation risk and urgent remediation priority for exposed organizations.

The issues impact both physical-security surveillance environments and industrial control workflows, raising risk of unauthorized monitoring, credential abuse, and potential operational disruption.

## Technical Specifications

| **Attribute** | **Details** |
|---------------|-------------|
| **CVE 1** | CVE-2017-7921 |
| **Product Scope 1** | Hikvision IP cameras and surveillance systems |
| **Issue Type 1** | Authentication bypass (improper auth controls) |
| **CVSS 1** | 9.8 (Critical) |
| **CVE 2** | CVE-2021-22681 |
| **Product Scope 2** | Rockwell Automation ICS software (including Studio 5000 Logix Designer contexts) |
| **Issue Type 2** | Credential exposure / weak credential protection |
| **CVSS 2** | 9.8 (Critical) |

## Affected Products
- Multiple Hikvision surveillance devices and management deployments impacted by CVE-2017-7921
- Rockwell Automation industrial environments using affected software workflows related to controller management
- Industrial/OT networks where engineering workstation trust can be abused
- Organizations with internet-exposed surveillance or weakly segmented ICS management paths
- Status: CISA KEV-listed; accelerated patching and hardening required

## Technical Details

### CVE-2017-7921 (Hikvision Authentication Bypass)
- Improper authentication logic allows bypass of normal login controls.
- Attackers can obtain elevated/administrator-level access on vulnerable camera systems.
- Unauthorized access can expose video feeds and sensitive device/network configuration data.

### CVE-2021-22681 (Rockwell Credential Exposure)
- Weak credential protection can expose or enable misuse of authentication material.
- Attackers may impersonate trusted engineering workstations.
- Compromise of trusted ICS management context can enable unsafe interaction with controllers.

### KEV Significance
- KEV listing indicates active threat relevance and prioritized exploitation concern.
- Combined IT/OT and surveillance exposure increases organizational attack surface.

## Attack Scenario
1. **Target Discovery**:
    - Attacker scans for reachable Hikvision management interfaces or exposed industrial software paths.

2. **Initial Compromise**:
    - Authentication bypass is used to access surveillance devices, or credential exposure is leveraged in industrial software contexts.

3. **Privilege Abuse**:
    - Attacker escalates operational control over camera systems or impersonates trusted engineering workstations.

4. **Operational Manipulation**:
    - Surveillance: access to live feeds and configuration extraction.
    - Industrial: potential controller logic/configuration manipulation via trusted channels.

5. **Persistence and Expansion**:
    - Adversary establishes footholds for long-term reconnaissance, sabotage staging, or broader network pivoting.

## Impact Assessment

=== "Surveillance & Data Risk"
    * Unauthorized access to camera feeds and monitoring infrastructure
    * Exposure of network topology and security configuration data
    * Potential espionage and privacy violations through compromised surveillance systems

=== "Industrial/OT Risk"
    * Potential impersonation of trusted engineering workstations
    * Elevated risk of unsafe PLC logic/configuration changes
    * Operational disruption across manufacturing, utilities, and critical infrastructure sectors

=== "Strategic and Business Impact"
    * Increased likelihood of targeted exploitation due to KEV visibility
    * Higher incident response burden across converged IT/OT environments
    * Risk of sabotage, service downtime, and reputational damage

## Mitigation Strategies

### Patch and Firmware Management
- Apply latest Hikvision firmware updates addressing known auth bypass exposure
- Install Rockwell Automation security patches for affected software versions
- Prioritize KEV-listed remediation in vulnerability management workflows

### Exposure Reduction
- Restrict management interfaces to trusted networks only
- Enforce strong network segmentation between IT, surveillance, and OT control layers
- Disable unnecessary externally reachable services

### Authentication and Monitoring
- Enforce strong credential policies and access controls on admin/engineering accounts
- Monitor for unusual access attempts, unauthorized config changes, and anomalous engineering actions
- Integrate KEV advisories into threat-hunting and detection use cases

## Resources and References

!!! info "Open-Source Reporting"
    - [Hikvision and Rockwell Automation CVSS 9.8 Flaws Added to CISA KEV Catalog](https://thehackernews.com/2026/03/hikvision-and-rockwell-automation-cvss.html)
    - [CISA Adds Hikvision and Rockwell Automation CVSS 9.8 Flaws to KEV Catalog](https://abit.ee/en/cybersecurity/vulnerabilities/cisa-kev-hikvision-rockwell-automation-cve-2017-7921-cve-2021-22681-cybersecurity-vulnerability-en)
    - [U.S. CISA adds Apple, Rockwell, and Hikvision flaws to its Known Exploited Vulnerabilities catalog](https://securityaffairs.com/189005/security/u-s-cisa-adds-apple-rockwell-and-hikvision-flaws-to-its-known-exploited-vulnerabilities-catalog.html)
    - [CISA Flags Hikvision Camera & Rockwell Logix Vulnerabilities as Actively Exploited](https://socradar.io/blog/hikvision-camera-rockwell-logix-cisa/)

---

*Last Updated: March 8, 2026* 