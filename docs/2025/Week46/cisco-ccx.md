# Cisco Unified Contact Center Express (Unified CCX) Vulnerabilities

**CVE-2025-20354**{.cve-chip}
**CVE-2025-20358**{.cve-chip}
**Remote Code Execution**{.cve-chip}
**Authentication Bypass**{.cve-chip}

## Overview

Cisco disclosed two critical vulnerabilities in its **Unified Contact Center Express (Unified CCX)** appliance that could allow remote attackers to execute arbitrary commands or gain administrative control without authentication. The flaws reside in the **Java RMI process** and the **CCX Editor authentication flow**. Cisco released fixed versions **12.5 SU3 ES07** and **15.0 ES01**. No exploitation has been observed in the wild at publication time.

## Technical Specifications

| **Attribute**           | **Details**                                                        |
| ----------------------- | ------------------------------------------------------------------ |
| **CVE IDs**             | CVE-2025-20354, CVE-2025-20358                                     |
| **Vulnerability Type**  | Remote Code Execution (RCE), Authentication Bypass                 |
| **Attack Vector**       | Network (remote)                                                   |
| **Authentication**      | None required (for CVE-20354); Weak authentication (for CVE-20358) |
| **Complexity**          | Low                                                                |
| **Privileges Required** | None                                                               |
| **User Interaction**    | Not required                                                       |
| **CVSS Scores**         | 9.8 (CVE-2025-20354), 9.4 (CVE-2025-20358)                         |
| **Affected Versions**   | Unified CCX 12.5 SU3 and earlier (before ES07); 15.0 before ES01   |
| **Fixed Versions**      | Unified CCX 12.5 SU3 ES07, 15.0 ES01                               |

## Attack Scenario

1. Attacker identifies a vulnerable Unified CCX system exposed to the network.
2. For **CVE-2025-20354**, the attacker connects to the **Java RMI** service and uploads a malicious file to the server, achieving **root command execution**.
3. For **CVE-2025-20358**, the attacker sets up a **malicious server** that impersonates the legitimate CCX server; the CCX Editor authenticates incorrectly and grants **administrator privileges**.
4. The attacker can then run arbitrary scripts or deploy malware within the contact-center environment, gaining persistence and potential lateral movement.

## Impact Assessment

=== "Integrity"
* Full compromise of Unified CCX configuration and operating system
* Arbitrary file upload and script execution with root privileges
* Tampering with contact-center call handling logic

=== "Confidentiality"
* Access to sensitive contact-center data
* Disclosure of internal scripts and configurations
* Exposure of connected systems credentials (CUIC, CCE, CUCM)

=== "Availability"
* Service disruption due to command injection or file corruption
* Possible denial of service from malicious script execution

=== "Network Security"
* Potential lateral movement to other Cisco Unified systems
* Launchpad for wider network compromise
* Root-level persistence across the appliance

## Mitigation Strategies

### :material-update: Patching

* **Upgrade immediately** to fixed versions:

  * Unified CCX **12.5 SU3 ES07**
  * Unified CCX **15.0 ES01**
* There are **no workarounds** for these vulnerabilities.

### :material-shield-key: Network Hardening

* Restrict access to Unified CCX management interfaces and **Java RMI ports**.
* Place CCX appliances behind firewalls with strict access controls.
* Segment contact-center servers from less-trusted networks.

### :material-monitor-dashboard: Monitoring & Detection

* Enable detailed logging and alerting for RMI and Editor traffic.
* Monitor for unauthorized file uploads and script executions.
* Review network logs for traffic to unknown servers during Editor operations.

### :material-account-lock: Access Controls

* Enforce administrative access over VPN or secure bastion hosts only.
* Regularly review and rotate credentials for CCX and connected systems.
* Disable or limit Editor access where not operationally required.

## Technical Recommendations

### Immediate Actions

1. Identify all Unified CCX instances and their version/build.
2. Apply the relevant patch immediately if below ES07 (12.5) or ES01 (15.0).
3. Restrict external network access to the affected services.
4. Enable and review security logging.

### Short-term Measures

1. Perform vulnerability scanning for open RMI endpoints.
2. Audit connected systems (CUCM, CCE, CUIC) for shared credentials.
3. Review contact-center configuration for unauthorized scripts.

### Long-term Strategy

1. Integrate Unified CCX into central patch management workflows.
2. Implement continuous vulnerability assessment for Cisco appliances.
3. Conduct periodic penetration testing on voice and contact-center infrastructure.

## Resources and References

!!! info "Official Documentation"
- [Cisco Security Advisory – cisco-sa-cc-unauth-rce-QeN8h7mQ](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cc-unauth-rce-QeN8h7mQ)
- [Cisco Patches Critical Vulnerabilities in Contact Center Appliance – SecurityWeek](https://www.securityweek.com/cisco-patches-critical-vulnerabilities-in-contact-center-appliance/)
- [Cisco Warns of New Firewall Exploit Variants – The Hacker News](https://thehackernews.com/2025/11/cisco-warns-of-new-firewall-attack.html)
- [Cisco Firewalls Under Attack Surge – TechRadar](https://www.techradar.com/pro/security/cisco-firewalls-are-facing-another-huge-surge-of-attacks)

!!! warning "Risk Level: Critical"
Both vulnerabilities allow remote code execution and privilege escalation **without authentication**. Systems must be patched immediately to prevent compromise.
