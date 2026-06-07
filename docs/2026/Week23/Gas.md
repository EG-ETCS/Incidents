# Exposed U.S. Gas Station Tank Gauge Systems
![alt text](images/Gas.png)

**Operational Technology (OT)**{.cve-chip} **Critical Infrastructure**{.cve-chip} **Automatic Tank Gauge (ATG)**{.cve-chip} **Internet-Exposed Systems**{.cve-chip}

## Overview

More than 900 internet-accessible Automatic Tank Gauge (ATG) systems used at U.S. gas stations and fuel storage facilities were found exposed online and vulnerable to cyberattacks. These systems are used to monitor underground fuel tanks, detect leaks, and manage fuel inventory. U.S. government agencies warned that attackers could manipulate or disrupt these systems, potentially causing operational and environmental damage.

## Technical Specifications

| Attribute | Details |
|---|---|
| **Incident Type** | Exposure of internet-accessible OT/ICS fuel monitoring systems |
| **Systems Identified** | Over 1,000 exposed ATG systems globally |
| **U.S. Exposure** | Approximately 909 exposed ATG systems |
| **Primary Reachability** | TCP port 10001 |
| **Authentication Weaknesses** | Default credentials, weak passwords, authentication bypass vulnerabilities |
| **Application Weaknesses** | SQL injection vulnerabilities, remote command execution issues, privilege escalation flaws |
| **Network Security Gaps** | Direct internet exposure, lack of VPN protection, insufficient network segmentation |
| **Sector at Risk** | Fuel retail and storage operations (critical infrastructure / OT environments) |
| **CVE IDs** | Not specified in publicly referenced advisories for this incident summary |

## Affected Products

- Internet-exposed **Automatic Tank Gauge (ATG)** systems deployed at U.S. gas stations and fuel storage facilities
- OT fuel monitoring devices reachable over TCP port 10001
- Deployments using default credentials or weak authentication controls
- Installations lacking VPN-protected access and OT/IT network segmentation

## Attack Scenario

1. An attacker scans the internet for exposed ATG systems and identifies a vulnerable gas station fuel monitoring device.
2. Using default credentials or authentication vulnerabilities, the attacker gains administrative access to the ATG interface.
3. The attacker manipulates fuel level readings and alters tank configuration settings to disrupt normal operations.
4. Leak detection alerts are disabled or tampered with, reducing visibility into safety and environmental issues.
5. In severe cases, the attacker causes operational outages, conceals fuel leaks, or damages fuel management processes.

## Impact

=== "Integrity"

    - Unauthorized modification of tank configuration settings and system parameters
    - Manipulation of fuel level and inventory readings leading to incorrect operational decisions
    - Potential long-term degradation of OT system reliability and trustworthiness

=== "Confidentiality"

    - Exposure of operational monitoring data and system metadata to unauthorized actors
    - Increased reconnaissance value for attackers targeting broader fuel and critical infrastructure networks
    - Potential disclosure of credentials and configuration information in weakly secured interfaces

=== "Availability"

    - Operational disruption at gas stations and fuel storage sites
    - Disabled or degraded leak detection and monitoring functionality
    - Fuel supply interruptions, financial losses, environmental contamination risk, and potential fire hazards

## Mitigations

### Immediate Actions

- Remove ATG systems from direct internet exposure
- Use VPN-secured remote access only
- Change default passwords and enforce strong authentication
- Restrict access using firewalls and ACLs

### Short-term Measures

- Implement Multi-Factor Authentication (MFA)
- Apply firmware and security updates
- Segment OT networks from IT and public networks
- Validate and harden remote management interfaces and services

### Monitoring & Detection

- Continuously monitor for unauthorized configuration changes
- Alert on suspicious authentication attempts and remote access behavior
- Track abnormal fuel readings, sudden configuration changes, and leak alert suppression events

## Resources

!!! info "Open-Source Reporting"
    - [Over 900 US gas station tank gauge systems exposed to attacks](https://www.bleepingcomputer.com/news/security/over-900-us-gas-station-tank-gauge-systems-exposed-to-attacks/)
    - [Exposed Fuel Tank Gauges Under Attack in the US](https://www.darkreading.com/cyberattacks-data-breaches/exposed-fuel-tank-gauges-attack-us)
    - [US agencies warn of hackers targeting fuel tank monitoring systems | brief | SC Media](https://www.scworld.com/brief/us-agencies-warn-of-hackers-targeting-fuel-tank-monitoring-systems)

---

*Last Updated: June 7, 2026*
